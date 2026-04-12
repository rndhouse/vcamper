//! Application orchestration for the VCamper CLI.
//! Ownership: client-only

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

use crate::cli::{AnalyzeArgs, Cli, Commands, PipelineStage, ProviderKind};
use crate::git;
use crate::hotspot::{self, HotspotCluster, HotspotPlan};
use crate::prompt;
use crate::provider::{
    AnalysisPhase, ProviderRequest, build_provider, interaction_schema, reachability_schema,
    screening_schema, verification_schema,
};
use crate::report;
use crate::types::{
    CandidateOutcome, CommitCandidate, FileStat, InteractionAnalysis, InteractionKind,
    InteractionVerdict, ProgressCompleteCandidate, ProgressPendingCandidate, ProgressResult,
    ProgressState, ProgressStatus, ReachabilityAnalysis, ReachabilityAssessment,
    ReachabilitySurface, ReachabilityVerdict, RunManifest, ScreeningAnalysis, SuspiciousFinding,
    VerificationAnalysis,
};

const MAX_ADJUDICATION_INPUT_BYTES: usize = 28_000;

/// Runs the selected CLI command.
pub(crate) fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Analyze(args) => run_analyze(args),
    }
}

/// Runs one end-to-end repository analysis.
fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    validate_args(&args)?;
    let verbose = args.verbose;

    log_step(
        verbose,
        "analyze",
        format!("starting analysis for repo {}", args.repo.display()),
    );
    let repo_root = git::repo_root(&args.repo)?;
    log_step(
        verbose,
        "analyze",
        format!("resolved repo root to {}", repo_root.display()),
    );
    let from = git::resolve_revision(&repo_root, &args.from)?;
    let to = git::resolve_revision(&repo_root, &args.to)?;
    log_step(
        verbose,
        "analyze",
        format!("resolved range {}..{}", short_hash(&from), short_hash(&to)),
    );
    let commits = git::list_commits(&repo_root, &from, &to)?;
    log_step(
        verbose,
        "analyze",
        format!("loaded {} commit(s) in the selected range", commits.len()),
    );

    if let Some(max_commits) = args.max_commits
        && commits.len() > max_commits
    {
        bail!(
            "commit range contains {} commits, which exceeds --max-commits {}",
            commits.len(),
            max_commits
        );
    }

    let run_dir = create_run_dir(&args.out)?;
    log_step(
        verbose,
        "analyze",
        format!("writing artifacts to {}", run_dir.display()),
    );

    let screen_effort = args.resolved_screen_effort();
    let verify_effort = args.resolved_verify_effort();
    let manifest = RunManifest {
        provider: args.provider.as_str().to_owned(),
        model: args.model.clone(),
        screen_effort: screen_effort.map(|effort| effort.as_str().to_owned()),
        verify_effort: verify_effort.map(|effort| effort.as_str().to_owned()),
        repo_root: repo_root.display().to_string(),
        from: from.clone(),
        to: to.clone(),
        commit_count: commits.len(),
        max_patch_bytes: args.max_patch_bytes,
        dry_run: args.dry_run,
        stop_after_stage: args.stop_after_stage.map(|stage| stage.as_str().to_owned()),
    };
    ensure_manifest(&run_dir, &manifest, verbose)?;
    log_step(
        verbose,
        "analyze",
        format!(
            "provider={} model={} screen_effort={} verify_effort={}",
            manifest.provider,
            manifest
                .model
                .clone()
                .unwrap_or_else(|| "provider default".to_owned()),
            manifest
                .screen_effort
                .clone()
                .unwrap_or_else(|| "provider default".to_owned()),
            manifest
                .verify_effort
                .clone()
                .unwrap_or_else(|| "provider default".to_owned()),
        ),
    );

    let candidates = build_candidates(&repo_root, &commits, args.max_patch_bytes, verbose)?;
    log_step(
        verbose,
        "analyze",
        format!("prepared {} candidate(s)", candidates.len()),
    );
    initialize_progress_state(&run_dir, &candidates)?;

    let screen_schema = screening_schema()?;
    let interaction_review_schema = interaction_schema()?;
    let reachability_review_schema = reachability_schema()?;
    let verify_schema = verification_schema()?;
    let provider = build_provider(args.provider);
    let progress = ProgressUi::new(candidates.len(), manifest.commit_count, verbose);
    let mut outcomes: Vec<(usize, CandidateOutcome)> = Vec::new();
    let mut resume_from_candidate = None;

    for candidate in &candidates {
        let completed_dir = completed_candidate_dir(&run_dir, candidate.candidate_index);
        let wip_dir = wip_candidate_dir(&run_dir, candidate.candidate_index);
        log_step(
            verbose,
            "candidate",
            format!(
                "preparing candidate {:04}: {}",
                candidate.candidate_index,
                short_hash(&candidate.commit.id)
            ),
        );

        if resume_from_candidate.is_none() {
            if let Some(saved_outcome) = load_saved_candidate_outcome(
                &run_dir,
                &completed_dir,
                candidate.candidate_index,
                verbose,
            )? {
                update_candidate_progress(
                    &run_dir,
                    candidate.candidate_index,
                    None,
                    None,
                    Some(progress_result_from_outcome(
                        &saved_outcome,
                        completed_dir.exists(),
                    )),
                )?;
                log_step(
                    verbose,
                    "resume",
                    format!(
                        "reusing completed candidate {:04}",
                        candidate.candidate_index
                    ),
                );
                progress.reuse_candidate(candidate.candidate_index);
                outcomes.push((candidate.candidate_index, saved_outcome));
                continue;
            }

            resume_from_candidate = Some(candidate.candidate_index);
            log_step(
                verbose,
                "resume",
                format!(
                    "starting execution from candidate {:04}",
                    candidate.candidate_index
                ),
            );
        } else {
            log_step(
                verbose,
                "resume",
                format!(
                    "rerunning candidate {:04} after resume boundary",
                    candidate.candidate_index
                ),
            );
        }

        update_candidate_progress(
            &run_dir,
            candidate.candidate_index,
            Some(ProgressStatus::InProgress),
            Some("preparing candidate"),
            None,
        )?;
        prepare_wip_candidate_dir(&wip_dir, verbose)?;

        let screen_dir = pass_dir(&wip_dir, AnalysisPhase::Screen);
        fs::create_dir_all(&screen_dir)
            .with_context(|| format!("failed to create {}", screen_dir.display()))?;
        let codex_screen_artifacts = match args.provider {
            ProviderKind::Codex => Some(prepare_codex_screen_plan_artifacts(
                &repo_root,
                &screen_dir,
                candidate,
            )?),
            ProviderKind::Claude => {
                let screen_prompt = prepare_screen_pass_artifacts(
                    args.provider,
                    &repo_root,
                    &screen_dir,
                    candidate,
                )?;
                persist_pass_artifacts(
                    &screen_dir,
                    &prompt::build_prompt_input(candidate),
                    &screen_prompt,
                )?;
                None
            }
        };

        if args.dry_run {
            log_step(
                verbose,
                "candidate",
                format!(
                    "candidate {:04} dry-run enabled, provider skipped",
                    candidate.candidate_index
                ),
            );
            let outcome = CandidateOutcome {
                screening: ScreeningAnalysis {
                    candidate_summary: "dry-run: provider execution skipped".to_owned(),
                    suspicious_findings: Vec::new(),
                },
                verification: None,
            };
            persist_candidate_input(&wip_dir, candidate)?;
            persist_screening_analysis(&screen_dir, &outcome.screening)?;
            persist_candidate_outcome(&wip_dir, &outcome)?;
            promote_completed_candidate(&wip_dir, &completed_dir, verbose)?;
            update_candidate_progress(
                &run_dir,
                candidate.candidate_index,
                None,
                None,
                Some(progress_result_from_outcome(&outcome, true)),
            )?;
            progress.complete_candidate(candidate.candidate_index, 0, true);
            outcomes.push((candidate.candidate_index, outcome));
            continue;
        }

        progress.start_phase(
            candidate.candidate_index,
            AnalysisPhase::Screen,
            manifest.provider.as_str(),
            short_hash(&candidate.commit.id),
        );
        update_candidate_progress(
            &run_dir,
            candidate.candidate_index,
            Some(ProgressStatus::InProgress),
            Some("screen inventory"),
            None,
        )?;
        log_step(
            verbose,
            "candidate",
            format!(
                "invoking {} screen pass for candidate {:04}",
                manifest.provider, candidate.candidate_index
            ),
        );
        let codex_screening_output = if let Some(screen_artifacts) = &codex_screen_artifacts {
            Some(run_codex_screening_pipeline(
                provider.as_ref(),
                &repo_root,
                &screen_dir,
                candidate,
                screen_artifacts,
                &run_dir,
                &screen_schema,
                &interaction_review_schema,
                &reachability_review_schema,
                args.model.as_deref(),
                screen_effort,
                args.stop_after_stage,
                verbose,
            )?)
        } else {
            None
        };
        let screening = if let Some(output) = &codex_screening_output {
            output.screening.clone()
        } else {
            let screen_prompt = prompt::render_screen_prompt(&manifest.repo_root, candidate)?;
            provider.screen_candidate(ProviderRequest {
                working_dir: &screen_dir,
                prompt: &screen_prompt,
                schema: &screen_schema,
                pass_dir: &screen_dir,
                candidate_index: candidate.candidate_index,
                phase: AnalysisPhase::Screen,
                model: args.model.as_deref(),
                effort: screen_effort,
                verbose,
            })?
        };
        log_step(
            verbose,
            "candidate",
            format!(
                "candidate {:04} screen pass returned {} suspicious finding(s)",
                candidate.candidate_index,
                screening.suspicious_findings.len()
            ),
        );
        persist_screening_analysis(&screen_dir, &screening)?;

        let verification = if screening.suspicious_findings.is_empty()
            || matches!(
                args.stop_after_stage,
                Some(PipelineStage::Inventory)
                    | Some(PipelineStage::Interaction)
                    | Some(PipelineStage::Reachability)
            ) {
            None
        } else {
            let verify_dir = pass_dir(&wip_dir, AnalysisPhase::Verify);
            fs::create_dir_all(&verify_dir)
                .with_context(|| format!("failed to create {}", verify_dir.display()))?;
            progress.start_phase(
                candidate.candidate_index,
                AnalysisPhase::Verify,
                manifest.provider.as_str(),
                short_hash(&candidate.commit.id),
            );
            update_candidate_progress(
                &run_dir,
                candidate.candidate_index,
                Some(ProgressStatus::InProgress),
                Some("verify adjudication"),
                None,
            )?;
            log_step(
                verbose,
                "candidate",
                format!(
                    "invoking {} verify pass for candidate {:04}",
                    manifest.provider, candidate.candidate_index
                ),
            );
            let verification = if matches!(args.provider, ProviderKind::Codex) {
                let Some(output) = &codex_screening_output else {
                    bail!("missing Codex screening pipeline output for verification");
                };
                if let Some(prompt_input) = build_codex_verify_prompt_input(
                    &repo_root,
                    &verify_dir,
                    candidate,
                    &output.hotspot_plan,
                    &output.reachability_results,
                )? {
                    let prompt_input_path =
                        absolute_artifact_path(&verify_dir.join("prompt-input.json"))?;
                    let verify_prompt =
                        prompt::render_codex_verify_prompt(Path::new(&prompt_input_path));
                    persist_pass_artifacts(&verify_dir, &prompt_input, &verify_prompt)?;
                    Some(provider.verify_candidate(ProviderRequest {
                        working_dir: &repo_root,
                        prompt: &verify_prompt,
                        schema: &verify_schema,
                        pass_dir: &verify_dir,
                        candidate_index: candidate.candidate_index,
                        phase: AnalysisPhase::Verify,
                        model: args.model.as_deref(),
                        effort: verify_effort,
                        verbose,
                    })?)
                } else {
                    Some(VerificationAnalysis {
                        verification_summary:
                            "No reachability-reviewed hypotheses survived into adjudication."
                                .to_owned(),
                        verdict: crate::types::VerificationVerdict::Rejected,
                        confirmed_findings: Vec::new(),
                    })
                }
            } else {
                let verify_prompt = prepare_verify_pass_artifacts(
                    args.provider,
                    &repo_root,
                    &verify_dir,
                    candidate,
                    &screening,
                )?;
                Some(provider.verify_candidate(ProviderRequest {
                    working_dir: &verify_dir,
                    prompt: &verify_prompt,
                    schema: &verify_schema,
                    pass_dir: &verify_dir,
                    candidate_index: candidate.candidate_index,
                    phase: AnalysisPhase::Verify,
                    model: args.model.as_deref(),
                    effort: verify_effort,
                    verbose,
                })?)
            };
            log_step(
                verbose,
                "candidate",
                format!(
                    "candidate {:04} verify pass verdict={} confirmed {} finding(s)",
                    candidate.candidate_index,
                    verification
                        .as_ref()
                        .map(|analysis| analysis.verdict.as_str())
                        .unwrap_or("rejected"),
                    verification
                        .as_ref()
                        .map(|analysis| analysis.confirmed_findings.len())
                        .unwrap_or(0)
                ),
            );
            if let Some(verification) = &verification {
                persist_verification_analysis(&verify_dir, verification)?;
            }
            verification
        };

        let outcome = CandidateOutcome {
            screening,
            verification,
        };
        persist_candidate_input(&wip_dir, candidate)?;
        persist_candidate_outcome(&wip_dir, &outcome)?;
        let keep_candidate_dir = should_retain_candidate_artifacts();
        finalize_candidate_dir(&wip_dir, &completed_dir, keep_candidate_dir, verbose)?;
        update_candidate_progress(
            &run_dir,
            candidate.candidate_index,
            None,
            None,
            Some(progress_result_from_outcome(&outcome, keep_candidate_dir)),
        )?;
        progress.complete_candidate(
            candidate.candidate_index,
            outcome.final_findings().len(),
            false,
        );
        outcomes.push((candidate.candidate_index, outcome));
    }

    progress.finish();
    log_step(
        verbose,
        "report",
        "merging findings across candidates".to_owned(),
    );
    let report = report::merge_findings(manifest, &candidates, &outcomes, args.min_confidence);
    report::write_report(&run_dir, &report)?;
    log_step(
        verbose,
        "report",
        format!(
            "wrote final report with {} finding(s)",
            report.findings.len()
        ),
    );
    report::print_terminal_summary(&report, &run_dir);
    Ok(())
}

/// Validates command-line arguments for analysis.
fn validate_args(args: &AnalyzeArgs) -> Result<()> {
    if !(0.0..=1.0).contains(&args.min_confidence) {
        bail!("--min-confidence must be between 0.0 and 1.0");
    }
    if args.stop_after_stage.is_some() && !matches!(args.provider, ProviderKind::Codex) {
        bail!("--stop-after-stage is currently supported only with --provider codex");
    }
    Ok(())
}

/// Ensures the run manifest either matches the existing run directory or is written freshly.
fn ensure_manifest(run_dir: &Path, manifest: &RunManifest, verbose: bool) -> Result<()> {
    let path = run_dir.join("manifest.json");
    if path.exists() {
        let existing: RunManifest = serde_json::from_str(
            &fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", path.display()))?;

        if existing != *manifest {
            bail!(
                "existing run manifest in {} does not match the current command",
                run_dir.display()
            );
        }

        log_step(
            verbose,
            "resume",
            format!("found matching manifest in {}", run_dir.display()),
        );
        return Ok(());
    }

    fs::write(&path, serde_json::to_string_pretty(manifest)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Loads one saved candidate outcome when it is present and valid.
fn load_saved_candidate_outcome(
    run_dir: &Path,
    candidate_dir: &Path,
    candidate_index: usize,
    verbose: bool,
) -> Result<Option<CandidateOutcome>> {
    if let Some(outcome) = load_completed_clean_outcome(run_dir, candidate_index)? {
        return Ok(Some(outcome));
    }

    let outcome_path = candidate_dir.join("outcome.json");
    if outcome_path.exists() {
        return load_json_file(&outcome_path).map(Some).or_else(|error| {
            log_step(
                verbose,
                "resume",
                format!(
                    "ignoring invalid saved candidate outcome at {}: {}",
                    outcome_path.display(),
                    error
                ),
            );
            Ok(None)
        });
    }

    let screen_path = pass_dir(candidate_dir, AnalysisPhase::Screen).join("analysis.json");
    if !screen_path.exists() {
        return Ok(None);
    }

    let screening: ScreeningAnalysis = match load_json_file(&screen_path) {
        Ok(screening) => screening,
        Err(error) => {
            log_step(
                verbose,
                "resume",
                format!(
                    "ignoring invalid screening analysis at {}: {}",
                    screen_path.display(),
                    error
                ),
            );
            return Ok(None);
        }
    };
    let verification_path = pass_dir(candidate_dir, AnalysisPhase::Verify).join("analysis.json");
    let verification = if verification_path.exists() {
        match load_json_file::<VerificationAnalysis>(&verification_path) {
            Ok(verification) => Some(verification),
            Err(error) => {
                log_step(
                    verbose,
                    "resume",
                    format!(
                        "ignoring invalid verification analysis at {}: {}",
                        verification_path.display(),
                        error
                    ),
                );
                return Ok(None);
            }
        }
    } else {
        None
    };

    Ok(Some(CandidateOutcome {
        screening,
        verification,
    }))
}

/// Loads one JSON file into the requested type.
fn load_json_file<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

/// Persists one first-pass screening analysis.
fn persist_screening_analysis(pass_dir: &Path, analysis: &ScreeningAnalysis) -> Result<()> {
    let path = pass_dir.join("analysis.json");
    fs::write(&path, serde_json::to_string_pretty(analysis)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Persists one second-pass verification analysis.
fn persist_verification_analysis(pass_dir: &Path, analysis: &VerificationAnalysis) -> Result<()> {
    let path = pass_dir.join("analysis.json");
    fs::write(&path, serde_json::to_string_pretty(analysis)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Persists one reachability analysis for a screened hypothesis.
fn persist_reachability_analysis(pass_dir: &Path, analysis: &ReachabilityAnalysis) -> Result<()> {
    let path = pass_dir.join("analysis.json");
    fs::write(&path, serde_json::to_string_pretty(analysis)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Persists one interaction analysis for a screened hypothesis.
fn persist_interaction_analysis(pass_dir: &Path, analysis: &InteractionAnalysis) -> Result<()> {
    let path = pass_dir.join("analysis.json");
    fs::write(&path, serde_json::to_string_pretty(analysis)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Persists one completed candidate outcome.
fn persist_candidate_outcome(candidate_dir: &Path, outcome: &CandidateOutcome) -> Result<()> {
    let path = candidate_dir.join("outcome.json");
    fs::write(&path, serde_json::to_string_pretty(outcome)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Persists the full collected commit evidence for one candidate.
fn persist_candidate_input(candidate_dir: &Path, candidate: &CommitCandidate) -> Result<()> {
    fs::write(
        candidate_dir.join("input.json"),
        serde_json::to_string_pretty(candidate)?,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            candidate_dir.join("input.json").display()
        )
    })
}

/// Persists one pass-specific prompt input and rendered prompt.
fn persist_pass_artifacts<T>(pass_dir: &Path, prompt_input: &T, prompt: &str) -> Result<()>
where
    T: Serialize,
{
    fs::write(
        pass_dir.join("prompt-input.json"),
        serde_json::to_string_pretty(prompt_input)?,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            pass_dir.join("prompt-input.json").display()
        )
    })?;
    fs::write(pass_dir.join("prompt.txt"), prompt)
        .with_context(|| format!("failed to write {}", pass_dir.join("prompt.txt").display()))
}

#[derive(Debug, Clone, Serialize)]
struct CodexPromptCommit {
    id: String,
    short_id: String,
    parent_ids: Vec<String>,
    files_changed: Vec<String>,
    file_stats: Vec<FileStat>,
    patch_file: String,
    changed_files_file: String,
    snapshot_manifest_file: String,
    hotspot_plan_file: String,
}

#[derive(Debug, Serialize)]
struct CodexInventoryPlanPromptInput {
    candidate_index: usize,
    commit: CodexPromptCommit,
    hotspot_plan: HotspotPlan,
}

#[derive(Debug, Serialize)]
struct CodexInventoryClusterPromptInput {
    candidate_index: usize,
    commit: CodexPromptCommit,
    hotspot_plan: HotspotPlan,
    cluster: HotspotCluster,
}

#[derive(Debug, Serialize)]
struct CodexInteractionPromptInput {
    candidate_index: usize,
    commit: CodexPromptCommit,
    hotspot_plan: HotspotPlan,
    cluster: HotspotCluster,
    inventory_hypothesis: SuspiciousFinding,
}

#[derive(Debug, Serialize)]
struct CodexReachabilityPromptInput {
    candidate_index: usize,
    commit: CodexPromptCommit,
    hotspot_plan: HotspotPlan,
    cluster: HotspotCluster,
    inventory_hypothesis: SuspiciousFinding,
    interaction_review: InteractionAnalysis,
}

#[derive(Debug, Clone, Serialize)]
struct CodexAdjudicationCandidate {
    hypothesis_index: usize,
    cluster_title: String,
    cluster_category: String,
    interaction_summary: String,
    interaction_verdict: InteractionVerdict,
    interaction_kind: InteractionKind,
    reachability_summary: String,
    reachability_verdict: ReachabilityVerdict,
    reachability_assessment: ReachabilityAssessment,
    surface: ReachabilitySurface,
    preconditions: Vec<String>,
    refined_finding: SuspiciousFinding,
}

#[derive(Debug, Serialize)]
struct CodexVerifyPromptInput {
    candidate_index: usize,
    commit: CodexPromptCommit,
    commit_message: String,
    hotspot_plan: HotspotPlan,
    finalists: Vec<CodexAdjudicationCandidate>,
}

#[derive(Debug, Serialize)]
struct CodexSnapshotEntry {
    path: String,
    before_file: Option<String>,
    after_file: Option<String>,
}

#[derive(Debug, Clone)]
struct CodexEvidenceRefs {
    patch_file: String,
    changed_files_file: String,
    snapshot_manifest_file: String,
    hotspot_plan_file: String,
}

#[derive(Debug, Clone)]
struct CodexInventoryClusterArtifacts {
    cluster: HotspotCluster,
    pass_dir: PathBuf,
    prompt: String,
}

#[derive(Debug, Clone)]
struct CodexInventoryPlanArtifacts {
    full_patch: String,
    hotspot_plan: HotspotPlan,
    clusters: Vec<CodexInventoryClusterArtifacts>,
}

#[derive(Debug, Clone)]
struct CodexInventoryHypothesis {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    finding: SuspiciousFinding,
}

#[derive(Debug, Clone)]
struct CodexInteractionArtifacts {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    inventory_finding: SuspiciousFinding,
    pass_dir: PathBuf,
    prompt: String,
}

#[derive(Debug, Clone)]
struct CodexInteractionRecord {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    inventory_finding: SuspiciousFinding,
    analysis: InteractionAnalysis,
}

#[derive(Debug, Clone)]
struct CodexReachabilityArtifacts {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    interaction_review: InteractionAnalysis,
    pass_dir: PathBuf,
    prompt: String,
}

#[derive(Debug, Clone)]
struct CodexReachabilityRecord {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    interaction_analysis: InteractionAnalysis,
    analysis: ReachabilityAnalysis,
}

#[derive(Debug, Clone)]
struct CodexInventoryMergeOutput {
    analysis: ScreeningAnalysis,
    hypotheses: Vec<CodexInventoryHypothesis>,
}

#[derive(Debug, Clone)]
struct CodexScreeningPipelineOutput {
    screening: ScreeningAnalysis,
    hotspot_plan: HotspotPlan,
    reachability_results: Vec<CodexReachabilityRecord>,
}

/// Prepares one screening-pass prompt and pass artifacts for the selected provider.
fn prepare_screen_pass_artifacts(
    provider: ProviderKind,
    repo_root: &Path,
    pass_dir: &Path,
    candidate: &CommitCandidate,
) -> Result<String> {
    match provider {
        ProviderKind::Codex => {
            let artifacts = prepare_codex_screen_plan_artifacts(repo_root, pass_dir, candidate)?;
            let prompt_input_path = absolute_artifact_path(&pass_dir.join("prompt-input.json"))?;
            Ok(prompt::render_codex_screen_plan_prompt(
                artifacts.clusters.len(),
                Path::new(&prompt_input_path),
            ))
        }
        ProviderKind::Claude => {
            let repo_root = repo_root.display().to_string();
            prompt::render_screen_prompt(&repo_root, candidate)
        }
    }
}

/// Prepares one verification-pass prompt and pass artifacts for the selected provider.
fn prepare_verify_pass_artifacts(
    provider: ProviderKind,
    repo_root: &Path,
    pass_dir: &Path,
    candidate: &CommitCandidate,
    screening: &ScreeningAnalysis,
) -> Result<String> {
    match provider {
        ProviderKind::Codex => bail!("Codex verification artifacts require staged screening data"),
        ProviderKind::Claude => {
            let repo_root = repo_root.display().to_string();
            let prompt = prompt::render_verify_prompt(&repo_root, candidate, screening)?;
            persist_pass_artifacts(
                pass_dir,
                &prompt::build_verification_prompt_input(candidate, screening),
                &prompt,
            )?;
            Ok(prompt)
        }
    }
}

/// Returns the inventory-stage artifact root for one screen pass.
fn inventory_stage_dir(screen_dir: &Path) -> PathBuf {
    screen_dir.join("inventory")
}

/// Returns the reachability-stage artifact root for one screen pass.
fn reachability_stage_dir(screen_dir: &Path) -> PathBuf {
    screen_dir.join("reachability")
}

/// Returns the interaction-stage artifact root for one screen pass.
fn interaction_stage_dir(screen_dir: &Path) -> PathBuf {
    screen_dir.join("interaction")
}

/// Builds the inventory focus units used for isolated first-stage Codex runs.
fn build_inventory_focuses(hotspot_plan: &HotspotPlan) -> Vec<HotspotCluster> {
    if hotspot_plan.files.is_empty() {
        return hotspot_plan.clusters.clone();
    }

    hotspot_plan
        .files
        .iter()
        .enumerate()
        .map(|(cluster_index, file)| HotspotCluster {
            cluster_index,
            title: format!("{} [{}]", file.path, file.category),
            rationale: file.rationale.clone(),
            category: file.category.clone(),
            files: vec![file.path.clone()],
            function_hints: file.function_hints.clone(),
            signal_terms: file.signal_terms.clone(),
            score: file.score,
        })
        .collect()
}

/// Prepares one focused Codex inventory plan and its evidence bundles.
fn prepare_codex_screen_plan_artifacts(
    repo_root: &Path,
    screen_dir: &Path,
    candidate: &CommitCandidate,
) -> Result<CodexInventoryPlanArtifacts> {
    let full_patch = git::load_full_patch(repo_root, &candidate.commit.id)?;
    let hotspot_plan = hotspot::build_hotspot_plan(&full_patch);
    let inventory_focuses = build_inventory_focuses(&hotspot_plan);
    let evidence = persist_codex_evidence_bundle(
        screen_dir,
        repo_root,
        candidate,
        &candidate.commit.files_changed,
        &full_patch,
        &hotspot_plan,
    )?;
    let plan_prompt_input = CodexInventoryPlanPromptInput {
        candidate_index: candidate.candidate_index,
        commit: build_codex_prompt_commit(candidate, evidence),
        hotspot_plan: hotspot_plan.clone(),
    };
    let plan_prompt_input_path = absolute_artifact_path(&screen_dir.join("prompt-input.json"))?;
    let plan_prompt = prompt::render_codex_screen_plan_prompt(
        inventory_focuses.len(),
        Path::new(&plan_prompt_input_path),
    );
    persist_pass_artifacts(screen_dir, &plan_prompt_input, &plan_prompt)?;

    let inventory_dir = inventory_stage_dir(screen_dir);
    fs::create_dir_all(&inventory_dir)
        .with_context(|| format!("failed to create {}", inventory_dir.display()))?;
    let mut clusters = Vec::with_capacity(inventory_focuses.len());
    for cluster in &inventory_focuses {
        let cluster_dir = inventory_dir.join(format!("cluster-{:04}", cluster.cluster_index));
        fs::create_dir_all(&cluster_dir)
            .with_context(|| format!("failed to create {}", cluster_dir.display()))?;
        let filtered_patch = hotspot::filtered_patch_for_files(&full_patch, &cluster.files);
        let evidence = persist_codex_evidence_bundle(
            &cluster_dir,
            repo_root,
            candidate,
            &cluster.files,
            &filtered_patch,
            &hotspot_plan,
        )?;
        let prompt_input = CodexInventoryClusterPromptInput {
            candidate_index: candidate.candidate_index,
            commit: build_codex_prompt_commit(candidate, evidence),
            hotspot_plan: hotspot_plan.clone(),
            cluster: cluster.clone(),
        };
        let prompt_input_path = absolute_artifact_path(&cluster_dir.join("prompt-input.json"))?;
        let prompt =
            prompt::render_codex_screen_cluster_prompt(cluster, Path::new(&prompt_input_path));
        persist_pass_artifacts(&cluster_dir, &prompt_input, &prompt)?;
        clusters.push(CodexInventoryClusterArtifacts {
            cluster: cluster.clone(),
            pass_dir: cluster_dir,
            prompt,
        });
    }

    Ok(CodexInventoryPlanArtifacts {
        full_patch,
        hotspot_plan,
        clusters,
    })
}

/// Runs the staged Codex screening pipeline for one candidate.
fn run_codex_screening_pipeline(
    provider: &dyn crate::provider::AgentProvider,
    repo_root: &Path,
    screen_dir: &Path,
    candidate: &CommitCandidate,
    artifacts: &CodexInventoryPlanArtifacts,
    run_dir: &Path,
    inventory_schema: &str,
    interaction_schema: &str,
    reachability_schema: &str,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    stop_after_stage: Option<PipelineStage>,
    verbose: bool,
) -> Result<CodexScreeningPipelineOutput> {
    let inventory = run_codex_inventory(
        provider,
        artifacts,
        repo_root,
        run_dir,
        inventory_schema,
        candidate.candidate_index,
        model,
        effort,
        verbose,
    )?;
    let inventory_dir = inventory_stage_dir(screen_dir);
    persist_screening_analysis(&inventory_dir, &inventory.analysis)?;

    if matches!(stop_after_stage, Some(PipelineStage::Inventory)) {
        return Ok(CodexScreeningPipelineOutput {
            screening: inventory.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
        });
    }

    if inventory.hypotheses.is_empty() {
        return Ok(CodexScreeningPipelineOutput {
            screening: inventory.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
        });
    }

    update_candidate_progress(
        run_dir,
        candidate.candidate_index,
        Some(ProgressStatus::InProgress),
        Some("screen interaction"),
        None,
    )?;
    let interaction_artifacts = prepare_codex_interaction_artifacts(
        repo_root,
        screen_dir,
        candidate,
        artifacts,
        &inventory.hypotheses,
    )?;
    let interaction_results = run_codex_interaction(
        provider,
        repo_root,
        &interaction_artifacts,
        run_dir,
        interaction_schema,
        candidate.candidate_index,
        model,
        effort,
        verbose,
    )?;
    let interaction_dir = interaction_stage_dir(screen_dir);
    let interaction_screening =
        merge_codex_interaction_results(artifacts.clusters.len(), &interaction_results);
    persist_screening_analysis(&interaction_dir, &interaction_screening)?;

    if matches!(stop_after_stage, Some(PipelineStage::Interaction)) {
        return Ok(CodexScreeningPipelineOutput {
            screening: interaction_screening,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
        });
    }

    update_candidate_progress(
        run_dir,
        candidate.candidate_index,
        Some(ProgressStatus::InProgress),
        Some("screen reachability"),
        None,
    )?;
    let reachability_artifacts = prepare_codex_reachability_artifacts(
        repo_root,
        screen_dir,
        candidate,
        artifacts,
        &interaction_results,
    )?;
    let reachability_results = run_codex_reachability(
        provider,
        repo_root,
        &reachability_artifacts,
        run_dir,
        reachability_schema,
        candidate.candidate_index,
        model,
        effort,
        verbose,
    )?;
    let screening =
        merge_codex_reachability_results(artifacts.clusters.len(), &reachability_results);
    let reachability_dir = reachability_stage_dir(screen_dir);
    persist_screening_analysis(&reachability_dir, &screening)?;

    Ok(CodexScreeningPipelineOutput {
        screening,
        hotspot_plan: artifacts.hotspot_plan.clone(),
        reachability_results,
    })
}

/// Runs Codex inventory across hotspot clusters and merges the results into hypotheses.
fn run_codex_inventory(
    provider: &dyn crate::provider::AgentProvider,
    artifacts: &CodexInventoryPlanArtifacts,
    working_dir: &Path,
    run_dir: &Path,
    schema: &str,
    candidate_index: usize,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    verbose: bool,
) -> Result<CodexInventoryMergeOutput> {
    let mut cluster_results = Vec::with_capacity(artifacts.clusters.len());
    for cluster_artifact in &artifacts.clusters {
        update_candidate_progress(
            run_dir,
            candidate_index,
            Some(ProgressStatus::InProgress),
            Some(&format!(
                "screen inventory focus {:04}",
                cluster_artifact.cluster.cluster_index
            )),
            None,
        )?;
        log_step(
            verbose,
            "inventory-focus",
            format!(
                "inventory focus {:04} ({})",
                cluster_artifact.cluster.cluster_index, cluster_artifact.cluster.title
            ),
        );
        let analysis = provider.screen_candidate(ProviderRequest {
            working_dir,
            prompt: &cluster_artifact.prompt,
            schema,
            pass_dir: &cluster_artifact.pass_dir,
            candidate_index,
            phase: AnalysisPhase::Screen,
            model,
            effort,
            verbose,
        })?;
        persist_screening_analysis(&cluster_artifact.pass_dir, &analysis)?;
        cluster_results.push((cluster_artifact.cluster.clone(), analysis));
    }

    Ok(merge_codex_inventory_results(
        artifacts.clusters.len(),
        cluster_results,
    ))
}

/// Merges clustered Codex inventory results into a deduplicated hypothesis list.
fn merge_codex_inventory_results(
    cluster_count: usize,
    cluster_results: Vec<(HotspotCluster, ScreeningAnalysis)>,
) -> CodexInventoryMergeOutput {
    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    let mut positive_clusters = Vec::new();

    for (cluster, analysis) in cluster_results {
        let primary_finding = analysis
            .suspicious_findings
            .into_iter()
            .max_by(|left, right| {
                left.confidence
                    .partial_cmp(&right.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| left.title.cmp(&right.title))
            });

        if primary_finding.is_some() {
            positive_clusters.push(cluster.title.clone());
        }

        if let Some(finding) = primary_finding {
            let key = format!(
                "{}|{}|{}",
                finding.commit_id.to_ascii_lowercase(),
                finding.title.to_ascii_lowercase(),
                finding
                    .likely_bug_class
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            );
            if seen.insert(key) {
                deduped.push(CodexInventoryHypothesis {
                    hypothesis_index: 0,
                    cluster: cluster.clone(),
                    finding,
                });
            }
        }
    }
    deduped.sort_by(|left, right| {
        right
            .finding
            .confidence
            .partial_cmp(&left.finding.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.finding.title.cmp(&right.finding.title))
    });
    for (hypothesis_index, hypothesis) in deduped.iter_mut().enumerate() {
        hypothesis.hypothesis_index = hypothesis_index;
    }

    let candidate_summary = if positive_clusters.is_empty() {
        format!(
            "Inventoried {} hotspot focus unit(s). No focus produced a stable security hypothesis from the supplied evidence.",
            cluster_count
        )
    } else {
        format!(
            "Inventoried {} hotspot focus unit(s). Plausible security hypotheses came from: {}.",
            cluster_count,
            positive_clusters.join("; ")
        )
    };

    CodexInventoryMergeOutput {
        analysis: ScreeningAnalysis {
            candidate_summary,
            suspicious_findings: deduped
                .iter()
                .map(|hypothesis| hypothesis.finding.clone())
                .collect(),
        },
        hypotheses: deduped,
    }
}

/// Prepares one interaction-review bundle for each inventoried hypothesis.
fn prepare_codex_interaction_artifacts(
    repo_root: &Path,
    screen_dir: &Path,
    candidate: &CommitCandidate,
    artifacts: &CodexInventoryPlanArtifacts,
    hypotheses: &[CodexInventoryHypothesis],
) -> Result<Vec<CodexInteractionArtifacts>> {
    let interaction_dir = interaction_stage_dir(screen_dir);
    fs::create_dir_all(&interaction_dir)
        .with_context(|| format!("failed to create {}", interaction_dir.display()))?;

    let mut outputs = Vec::with_capacity(hypotheses.len());
    for hypothesis in hypotheses {
        let hypothesis_dir =
            interaction_dir.join(format!("hypothesis-{:04}", hypothesis.hypothesis_index));
        fs::create_dir_all(&hypothesis_dir)
            .with_context(|| format!("failed to create {}", hypothesis_dir.display()))?;
        let selected_files = selected_files_for_hypothesis(hypothesis);
        let filtered_patch = filtered_patch_for_selection(&artifacts.full_patch, &selected_files);
        let evidence = persist_codex_evidence_bundle(
            &hypothesis_dir,
            repo_root,
            candidate,
            &selected_files,
            &filtered_patch,
            &artifacts.hotspot_plan,
        )?;
        let prompt_input = CodexInteractionPromptInput {
            candidate_index: candidate.candidate_index,
            commit: build_codex_prompt_commit(candidate, evidence),
            hotspot_plan: artifacts.hotspot_plan.clone(),
            cluster: hypothesis.cluster.clone(),
            inventory_hypothesis: hypothesis.finding.clone(),
        };
        let prompt_input_path = absolute_artifact_path(&hypothesis_dir.join("prompt-input.json"))?;
        let prompt = prompt::render_codex_interaction_prompt(Path::new(&prompt_input_path));
        persist_pass_artifacts(&hypothesis_dir, &prompt_input, &prompt)?;
        outputs.push(CodexInteractionArtifacts {
            hypothesis_index: hypothesis.hypothesis_index,
            cluster: hypothesis.cluster.clone(),
            inventory_finding: hypothesis.finding.clone(),
            pass_dir: hypothesis_dir,
            prompt,
        });
    }

    Ok(outputs)
}

/// Runs one interaction review for each inventoried hypothesis.
fn run_codex_interaction(
    provider: &dyn crate::provider::AgentProvider,
    working_dir: &Path,
    artifacts: &[CodexInteractionArtifacts],
    run_dir: &Path,
    schema: &str,
    candidate_index: usize,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    verbose: bool,
) -> Result<Vec<CodexInteractionRecord>> {
    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        update_candidate_progress(
            run_dir,
            candidate_index,
            Some(ProgressStatus::InProgress),
            Some(&format!(
                "screen interaction hypothesis {:04}",
                artifact.hypothesis_index
            )),
            None,
        )?;
        log_step(
            verbose,
            "interaction",
            format!(
                "reviewing interaction for hypothesis {:04} from cluster {}",
                artifact.hypothesis_index, artifact.cluster.title
            ),
        );
        let analysis = provider.review_interaction(ProviderRequest {
            working_dir,
            prompt: &artifact.prompt,
            schema,
            pass_dir: &artifact.pass_dir,
            candidate_index,
            phase: AnalysisPhase::Screen,
            model,
            effort,
            verbose,
        })?;
        persist_interaction_analysis(&artifact.pass_dir, &analysis)?;
        results.push(CodexInteractionRecord {
            hypothesis_index: artifact.hypothesis_index,
            cluster: artifact.cluster.clone(),
            inventory_finding: artifact.inventory_finding.clone(),
            analysis,
        });
    }

    Ok(results)
}

/// Merges interaction-reviewed hypotheses into a stage summary.
fn merge_codex_interaction_results(
    cluster_count: usize,
    interaction_results: &[CodexInteractionRecord],
) -> ScreeningAnalysis {
    let mut findings = Vec::new();
    let mut kept = Vec::new();

    for result in interaction_results {
        if result.analysis.preserve_for_reachability || result.analysis.preserve_for_adjudication {
            kept.push(format!(
                "{} [{}]",
                result.cluster.title,
                interaction_kind_label(result.analysis.interaction_kind)
            ));
        }
        if let Some(finding) = &result.analysis.refined_finding {
            findings.push(finding.clone());
        }
    }

    let candidate_summary = if kept.is_empty() {
        format!(
            "Reviewed {} hotspot cluster(s) for interaction-dependent security theories. No hypothesis needed special preservation beyond ordinary reachability.",
            cluster_count
        )
    } else {
        format!(
            "Reviewed {} hotspot cluster(s) for interaction-dependent security theories. Preserved hypotheses came from: {}.",
            cluster_count,
            kept.join("; ")
        )
    };

    ScreeningAnalysis {
        candidate_summary,
        suspicious_findings: findings,
    }
}

/// Prepares one reachability bundle for each inventoried hypothesis.
fn prepare_codex_reachability_artifacts(
    repo_root: &Path,
    screen_dir: &Path,
    candidate: &CommitCandidate,
    artifacts: &CodexInventoryPlanArtifacts,
    interaction_results: &[CodexInteractionRecord],
) -> Result<Vec<CodexReachabilityArtifacts>> {
    let reachability_dir = reachability_stage_dir(screen_dir);
    fs::create_dir_all(&reachability_dir)
        .with_context(|| format!("failed to create {}", reachability_dir.display()))?;

    let mut outputs = Vec::with_capacity(interaction_results.len());
    for hypothesis in interaction_results {
        if !should_review_reachability(&hypothesis.analysis) {
            continue;
        }
        let hypothesis_dir =
            reachability_dir.join(format!("hypothesis-{:04}", hypothesis.hypothesis_index));
        fs::create_dir_all(&hypothesis_dir)
            .with_context(|| format!("failed to create {}", hypothesis_dir.display()))?;
        let selected_files = selected_files_for_interaction_record(hypothesis);
        let filtered_patch = filtered_patch_for_selection(&artifacts.full_patch, &selected_files);
        let evidence = persist_codex_evidence_bundle(
            &hypothesis_dir,
            repo_root,
            candidate,
            &selected_files,
            &filtered_patch,
            &artifacts.hotspot_plan,
        )?;
        let prompt_input = CodexReachabilityPromptInput {
            candidate_index: candidate.candidate_index,
            commit: build_codex_prompt_commit(candidate, evidence),
            hotspot_plan: artifacts.hotspot_plan.clone(),
            cluster: hypothesis.cluster.clone(),
            inventory_hypothesis: hypothesis.inventory_finding.clone(),
            interaction_review: hypothesis.analysis.clone(),
        };
        let prompt_input_path = absolute_artifact_path(&hypothesis_dir.join("prompt-input.json"))?;
        let prompt = prompt::render_codex_reachability_prompt(Path::new(&prompt_input_path));
        persist_pass_artifacts(&hypothesis_dir, &prompt_input, &prompt)?;
        outputs.push(CodexReachabilityArtifacts {
            hypothesis_index: hypothesis.hypothesis_index,
            cluster: hypothesis.cluster.clone(),
            interaction_review: hypothesis.analysis.clone(),
            pass_dir: hypothesis_dir,
            prompt,
        });
    }

    Ok(outputs)
}

/// Runs one reachability review for each inventoried hypothesis.
fn run_codex_reachability(
    provider: &dyn crate::provider::AgentProvider,
    working_dir: &Path,
    artifacts: &[CodexReachabilityArtifacts],
    run_dir: &Path,
    schema: &str,
    candidate_index: usize,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    verbose: bool,
) -> Result<Vec<CodexReachabilityRecord>> {
    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        update_candidate_progress(
            run_dir,
            candidate_index,
            Some(ProgressStatus::InProgress),
            Some(&format!(
                "screen reachability hypothesis {:04}",
                artifact.hypothesis_index
            )),
            None,
        )?;
        log_step(
            verbose,
            "reachability",
            format!(
                "reviewing hypothesis {:04} from cluster {}",
                artifact.hypothesis_index, artifact.cluster.title
            ),
        );
        let analysis = provider.review_reachability(ProviderRequest {
            working_dir,
            prompt: &artifact.prompt,
            schema,
            pass_dir: &artifact.pass_dir,
            candidate_index,
            phase: AnalysisPhase::Screen,
            model,
            effort,
            verbose,
        })?;
        persist_reachability_analysis(&artifact.pass_dir, &analysis)?;
        results.push(CodexReachabilityRecord {
            hypothesis_index: artifact.hypothesis_index,
            cluster: artifact.cluster.clone(),
            interaction_analysis: artifact.interaction_review.clone(),
            analysis,
        });
    }

    Ok(results)
}

/// Merges reachability-reviewed hypotheses into the final screening result.
fn merge_codex_reachability_results(
    cluster_count: usize,
    reachability_results: &[CodexReachabilityRecord],
) -> ScreeningAnalysis {
    let mut supported = Vec::new();
    let mut surfaces = Vec::new();

    for result in reachability_results {
        if !should_keep_reachability_result(result) {
            continue;
        }

        if let Some(finding) = &result.analysis.refined_finding {
            supported.push((
                result.cluster.category.clone(),
                result.interaction_analysis.verdict,
                result.analysis.verdict,
                result.analysis.assessment,
                result.analysis.surface,
                finding.clone(),
            ));
            surfaces.push(format!(
                "{} [{}/{}]",
                result.cluster.title,
                result.analysis.surface.as_str(),
                result.analysis.assessment.as_str()
            ));
        }
    }

    supported.sort_by(|left, right| {
        interaction_verdict_priority(right.1)
            .cmp(&interaction_verdict_priority(left.1))
            .then_with(|| {
                reachability_verdict_priority(right.2).cmp(&reachability_verdict_priority(left.2))
            })
            .then_with(|| {
                reachability_assessment_priority(right.3)
                    .cmp(&reachability_assessment_priority(left.3))
            })
            .then_with(|| {
                reachability_surface_priority(right.4).cmp(&reachability_surface_priority(left.4))
            })
            .then_with(|| {
                right
                    .5
                    .confidence
                    .partial_cmp(&left.5.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let candidate_summary = if supported.is_empty() {
        format!(
            "Reviewed {} hotspot cluster(s) through staged reachability analysis. No hypothesis kept a stable attacker-controlled path.",
            cluster_count
        )
    } else {
        format!(
            "Reviewed {} hotspot cluster(s) through staged reachability analysis. Surviving hypotheses came from: {}.",
            cluster_count,
            surfaces.join("; ")
        )
    };

    ScreeningAnalysis {
        candidate_summary,
        suspicious_findings: supported
            .into_iter()
            .map(|(_, _, _, _, _, finding)| finding)
            .collect(),
    }
}

/// Returns whether an interaction-reviewed hypothesis should continue into reachability review.
fn should_review_reachability(analysis: &InteractionAnalysis) -> bool {
    analysis.preserve_for_reachability || analysis.preserve_for_adjudication
}

/// Returns whether a reachability-reviewed hypothesis should remain visible after filtering.
fn should_keep_reachability_result(result: &CodexReachabilityRecord) -> bool {
    result.analysis.verdict != ReachabilityVerdict::Rejected
        || result.analysis.keep_for_adjudication
        || result.interaction_analysis.preserve_for_adjudication
}

/// Selects the files and snapshots needed to review one inventoried hypothesis.
fn selected_files_for_hypothesis(hypothesis: &CodexInventoryHypothesis) -> Vec<String> {
    let mut selected = BTreeSet::new();
    for path in &hypothesis.cluster.files {
        selected.insert(path.clone());
    }
    for path in &hypothesis.finding.affected_files {
        selected.insert(path.clone());
    }
    selected.into_iter().collect()
}

/// Selects the files and snapshots needed to review one interaction-reviewed hypothesis.
fn selected_files_for_interaction_record(hypothesis: &CodexInteractionRecord) -> Vec<String> {
    let mut selected = BTreeSet::new();
    for path in &hypothesis.cluster.files {
        selected.insert(path.clone());
    }
    for path in &hypothesis.inventory_finding.affected_files {
        selected.insert(path.clone());
    }
    if let Some(finding) = &hypothesis.analysis.refined_finding {
        for path in &finding.affected_files {
            selected.insert(path.clone());
        }
    }
    selected.into_iter().collect()
}

/// Returns the patch subset for one selected file list, or the full patch when filtering is empty.
fn filtered_patch_for_selection(full_patch: &str, selected_files: &[String]) -> String {
    let filtered = hotspot::filtered_patch_for_files(full_patch, selected_files);
    if filtered.trim().is_empty() {
        full_patch.to_owned()
    } else {
        filtered
    }
}

/// Returns the ranking priority for one reachability verdict.
fn reachability_verdict_priority(verdict: ReachabilityVerdict) -> usize {
    match verdict {
        ReachabilityVerdict::Supported => 3,
        ReachabilityVerdict::Weak => 2,
        ReachabilityVerdict::Rejected => 1,
    }
}

/// Returns the ranking priority for one reachability surface.
fn reachability_surface_priority(surface: ReachabilitySurface) -> usize {
    match surface {
        ReachabilitySurface::Remote => 5,
        ReachabilitySurface::Adjacent => 4,
        ReachabilitySurface::Unknown => 3,
        ReachabilitySurface::LocalApi => 2,
        ReachabilitySurface::InternalOnly => 1,
    }
}

/// Returns the ranking priority for one interaction verdict.
fn interaction_verdict_priority(verdict: InteractionVerdict) -> usize {
    match verdict {
        InteractionVerdict::Strong => 3,
        InteractionVerdict::Plausible => 2,
        InteractionVerdict::Absent => 1,
    }
}

/// Returns the ranking priority for one reachability assessment.
fn reachability_assessment_priority(assessment: ReachabilityAssessment) -> usize {
    match assessment {
        ReachabilityAssessment::DirectReachability => 4,
        ReachabilityAssessment::InteractionDependent => 3,
        ReachabilityAssessment::LocalApiOnly => 2,
        ReachabilityAssessment::Rejected => 1,
    }
}

/// Returns a short label for one interaction kind.
fn interaction_kind_label(kind: InteractionKind) -> &'static str {
    match kind {
        InteractionKind::FeatureInteraction => "feature_interaction",
        InteractionKind::SharedVerificationFlow => "shared_verification_flow",
        InteractionKind::DirectPath => "direct_path",
        InteractionKind::None => "none",
    }
}

/// Returns whether a finalist represents an interaction-heavy security theory.
fn is_interaction_priority_finalist(finalist: &CodexAdjudicationCandidate) -> bool {
    finalist.reachability_assessment == ReachabilityAssessment::InteractionDependent
        || finalist.interaction_verdict != InteractionVerdict::Absent
            && finalist.interaction_kind != InteractionKind::None
}

/// Returns whether a finalist keeps a non-local attacker surface.
fn is_network_priority_finalist(finalist: &CodexAdjudicationCandidate) -> bool {
    matches!(
        finalist.surface,
        ReachabilitySurface::Remote | ReachabilitySurface::Adjacent
    )
}

/// Returns whether a finalist primarily describes local API misuse or contract hardening.
fn is_local_api_only_finalist(finalist: &CodexAdjudicationCandidate) -> bool {
    finalist.reachability_assessment == ReachabilityAssessment::LocalApiOnly
        || finalist.surface == ReachabilitySurface::LocalApi
}

/// Returns the coarse adjudication priority bucket for one finalist.
fn adjudication_track_priority(finalist: &CodexAdjudicationCandidate) -> usize {
    if is_network_priority_finalist(finalist) {
        4
    } else if is_interaction_priority_finalist(finalist) {
        3
    } else if finalist.surface == ReachabilitySurface::Unknown {
        2
    } else if is_local_api_only_finalist(finalist) {
        1
    } else {
        0
    }
}

/// Appends one finalist when it fits the current adjudication byte budget.
fn try_select_finalist(
    selected: &mut Vec<CodexAdjudicationCandidate>,
    selected_indexes: &mut BTreeSet<usize>,
    total_bytes: &mut usize,
    finalist: &CodexAdjudicationCandidate,
) -> Result<bool> {
    if selected_indexes.contains(&finalist.hypothesis_index) {
        return Ok(false);
    }

    let bytes = serde_json::to_vec(finalist)?.len();
    if !selected.is_empty() && *total_bytes + bytes > MAX_ADJUDICATION_INPUT_BYTES {
        return Ok(false);
    }

    *total_bytes += bytes;
    selected_indexes.insert(finalist.hypothesis_index);
    selected.push(finalist.clone());
    Ok(true)
}

/// Shortlists adjudication finalists under a serialized byte budget.
fn select_adjudication_finalists(
    reachability_results: &[CodexReachabilityRecord],
) -> Result<Vec<CodexAdjudicationCandidate>> {
    let mut finalists = reachability_results
        .iter()
        .filter_map(|result| {
            let refined_finding = result.analysis.refined_finding.clone()?;
            if !should_keep_reachability_result(result) {
                return None;
            }

            Some(CodexAdjudicationCandidate {
                hypothesis_index: result.hypothesis_index,
                cluster_title: result.cluster.title.clone(),
                cluster_category: result.cluster.category.clone(),
                interaction_summary: result.interaction_analysis.hypothesis_summary.clone(),
                interaction_verdict: result.interaction_analysis.verdict,
                interaction_kind: result.interaction_analysis.interaction_kind,
                reachability_summary: result.analysis.hypothesis_summary.clone(),
                reachability_verdict: result.analysis.verdict,
                reachability_assessment: result.analysis.assessment,
                surface: result.analysis.surface,
                preconditions: result
                    .interaction_analysis
                    .preconditions
                    .iter()
                    .cloned()
                    .chain(result.analysis.preconditions.iter().cloned())
                    .collect(),
                refined_finding,
            })
        })
        .collect::<Vec<_>>();

    finalists.sort_by(|left, right| {
        adjudication_track_priority(right)
            .cmp(&adjudication_track_priority(left))
            .then_with(|| {
                interaction_verdict_priority(right.interaction_verdict)
                    .cmp(&interaction_verdict_priority(left.interaction_verdict))
            })
            .then_with(|| {
                reachability_assessment_priority(right.reachability_assessment).cmp(
                    &reachability_assessment_priority(left.reachability_assessment),
                )
            })
            .then_with(|| {
                reachability_verdict_priority(right.reachability_verdict)
                    .cmp(&reachability_verdict_priority(left.reachability_verdict))
            })
            .then_with(|| {
                reachability_surface_priority(right.surface)
                    .cmp(&reachability_surface_priority(left.surface))
            })
            .then_with(|| {
                right
                    .refined_finding
                    .confidence
                    .partial_cmp(&left.refined_finding.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let mut selected = Vec::new();
    let mut selected_indexes = BTreeSet::new();
    let mut total_bytes = 0usize;

    for predicate in [
        is_interaction_priority_finalist as fn(&CodexAdjudicationCandidate) -> bool,
        is_network_priority_finalist,
        |finalist: &CodexAdjudicationCandidate| !is_local_api_only_finalist(finalist),
    ] {
        if let Some(finalist) = finalists.iter().find(|candidate| predicate(candidate)) {
            try_select_finalist(
                &mut selected,
                &mut selected_indexes,
                &mut total_bytes,
                finalist,
            )?;
        }
    }

    let mut category_best = Vec::<CodexAdjudicationCandidate>::new();
    for finalist in finalists.iter().cloned() {
        if category_best
            .iter()
            .any(|existing| existing.cluster_category == finalist.cluster_category)
        {
            continue;
        }
        category_best.push(finalist);
    }
    for finalist in &category_best {
        try_select_finalist(
            &mut selected,
            &mut selected_indexes,
            &mut total_bytes,
            finalist,
        )?;
    }

    for finalist in finalists {
        if !try_select_finalist(
            &mut selected,
            &mut selected_indexes,
            &mut total_bytes,
            &finalist,
        )? && total_bytes >= MAX_ADJUDICATION_INPUT_BYTES
        {
            break;
        }
    }

    Ok(selected)
}

/// Builds the Codex adjudication-pass prompt input after shortlisting finalists by budget.
fn build_codex_verify_prompt_input(
    repo_root: &Path,
    pass_dir: &Path,
    candidate: &CommitCandidate,
    hotspot_plan: &HotspotPlan,
    reachability_results: &[CodexReachabilityRecord],
) -> Result<Option<CodexVerifyPromptInput>> {
    let finalists = select_adjudication_finalists(reachability_results)?;
    if finalists.is_empty() {
        return Ok(None);
    }

    let full_patch = git::load_full_patch(repo_root, &candidate.commit.id)?;
    let evidence = persist_codex_evidence_bundle(
        pass_dir,
        repo_root,
        candidate,
        &candidate.commit.files_changed,
        &full_patch,
        hotspot_plan,
    )?;
    Ok(Some(CodexVerifyPromptInput {
        candidate_index: candidate.candidate_index,
        commit: build_codex_prompt_commit(candidate, evidence),
        commit_message: candidate.commit.summary.clone(),
        hotspot_plan: hotspot_plan.clone(),
        finalists,
    }))
}

/// Builds the Codex-facing commit summary that points to persisted evidence files.
fn build_codex_prompt_commit(
    candidate: &CommitCandidate,
    evidence: CodexEvidenceRefs,
) -> CodexPromptCommit {
    CodexPromptCommit {
        id: candidate.commit.id.clone(),
        short_id: candidate.commit.short_id.clone(),
        parent_ids: candidate.commit.parent_ids.clone(),
        files_changed: candidate.commit.files_changed.clone(),
        file_stats: candidate.commit.file_stats.clone(),
        patch_file: evidence.patch_file,
        changed_files_file: evidence.changed_files_file,
        snapshot_manifest_file: evidence.snapshot_manifest_file,
        hotspot_plan_file: evidence.hotspot_plan_file,
    }
}

/// Persists the Codex evidence bundle for one pass with a patch subset and per-file snapshots.
fn persist_codex_evidence_bundle(
    pass_dir: &Path,
    repo_root: &Path,
    candidate: &CommitCandidate,
    selected_files: &[String],
    patch_text: &str,
    hotspot_plan: &HotspotPlan,
) -> Result<CodexEvidenceRefs> {
    let evidence_dir = pass_dir.join("evidence");
    fs::create_dir_all(&evidence_dir)
        .with_context(|| format!("failed to create {}", evidence_dir.display()))?;

    let patch_path = evidence_dir.join("patch.diff");
    fs::write(&patch_path, patch_text)
        .with_context(|| format!("failed to write {}", patch_path.display()))?;

    let changed_files_path = evidence_dir.join("changed-files.txt");
    let changed_files = if selected_files.is_empty() {
        String::new()
    } else {
        format!("{}\n", selected_files.join("\n"))
    };
    fs::write(&changed_files_path, changed_files)
        .with_context(|| format!("failed to write {}", changed_files_path.display()))?;

    let hotspot_path = evidence_dir.join("hotspots.json");
    fs::write(&hotspot_path, serde_json::to_string_pretty(hotspot_plan)?)
        .with_context(|| format!("failed to write {}", hotspot_path.display()))?;

    let snapshot_manifest_path = evidence_dir.join("file-snapshots.json");
    let snapshots =
        persist_codex_file_snapshots(&evidence_dir, repo_root, candidate, selected_files)?;
    fs::write(
        &snapshot_manifest_path,
        serde_json::to_string_pretty(&snapshots)?,
    )
    .with_context(|| format!("failed to write {}", snapshot_manifest_path.display()))?;

    Ok(CodexEvidenceRefs {
        patch_file: absolute_artifact_path(&patch_path)?,
        changed_files_file: absolute_artifact_path(&changed_files_path)?,
        snapshot_manifest_file: absolute_artifact_path(&snapshot_manifest_path)?,
        hotspot_plan_file: absolute_artifact_path(&hotspot_path)?,
    })
}

/// Persists before/after snapshots for selected files inside one Codex evidence bundle.
fn persist_codex_file_snapshots(
    evidence_dir: &Path,
    repo_root: &Path,
    candidate: &CommitCandidate,
    selected_files: &[String],
) -> Result<Vec<CodexSnapshotEntry>> {
    let before_root = evidence_dir.join("before");
    let after_root = evidence_dir.join("after");
    let parent_revision = candidate.commit.parent_ids.first().map(String::as_str);
    let mut snapshots = Vec::with_capacity(selected_files.len());

    for path in selected_files {
        let before_file = if let Some(parent_revision) = parent_revision {
            persist_snapshot_file(repo_root, parent_revision, path, &before_root)?
        } else {
            None
        };
        let after_file = persist_snapshot_file(repo_root, &candidate.commit.id, path, &after_root)?;
        snapshots.push(CodexSnapshotEntry {
            path: path.clone(),
            before_file,
            after_file,
        });
    }

    Ok(snapshots)
}

/// Persists one file snapshot from a specific revision into the pass-local evidence bundle.
fn persist_snapshot_file(
    repo_root: &Path,
    revision: &str,
    repo_relative_path: &str,
    snapshot_root: &Path,
) -> Result<Option<String>> {
    let Some(contents) = git::load_file_at_revision(repo_root, revision, repo_relative_path)?
    else {
        return Ok(None);
    };

    let snapshot_path = bundle_snapshot_path(snapshot_root, repo_relative_path)?;
    if let Some(parent) = snapshot_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&snapshot_path, contents)
        .with_context(|| format!("failed to write {}", snapshot_path.display()))?;

    Ok(Some(absolute_artifact_path(&snapshot_path)?))
}

/// Returns one artifact path in absolute display form for prompt-input references.
fn absolute_artifact_path(path: &Path) -> Result<String> {
    let absolute = if path.exists() {
        fs::canonicalize(path).with_context(|| format!("failed to resolve {}", path.display()))?
    } else if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)
    };
    Ok(absolute.display().to_string())
}

/// Resolves one repo-relative path inside the evidence bundle snapshot tree.
fn bundle_snapshot_path(root: &Path, repo_relative_path: &str) -> Result<PathBuf> {
    let mut resolved = root.to_path_buf();
    for component in Path::new(repo_relative_path).components() {
        match component {
            Component::Normal(segment) => resolved.push(segment),
            _ => bail!(
                "unsupported changed file path for evidence bundle: {}",
                repo_relative_path
            ),
        }
    }

    Ok(resolved)
}

/// Builds one candidate per included commit.
fn build_candidates(
    repo_root: &Path,
    commits: &[String],
    max_patch_bytes: usize,
    verbose: bool,
) -> Result<Vec<CommitCandidate>> {
    let mut candidates = Vec::with_capacity(commits.len());
    for (candidate_index, commit) in commits.iter().enumerate() {
        log_step(
            verbose,
            "git",
            format!(
                "loading commit {} of {} for candidate {:04}: {}",
                candidate_index + 1,
                commits.len(),
                candidate_index,
                short_hash(commit)
            ),
        );
        candidates.push(CommitCandidate {
            candidate_index,
            commit: git::load_commit(repo_root, commit, max_patch_bytes)?,
        });
    }
    Ok(candidates)
}

/// Creates the selected run directory when needed.
fn create_run_dir(out: &Path) -> Result<PathBuf> {
    let path = out.to_path_buf();
    fs::create_dir_all(&path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(path)
}

/// Initializes the persisted progress file for the current run.
fn initialize_progress_state(run_dir: &Path, candidates: &[CommitCandidate]) -> Result<()> {
    let path = progress_state_path(run_dir);
    if path.exists() {
        let mut progress = load_progress_state(run_dir)?;
        reconcile_progress_state(&mut progress, candidates);
        return write_progress_state(run_dir, &progress);
    }

    let progress = ProgressState {
        count_pending: candidates.len(),
        count_complete: 0,
        pending: candidates
            .iter()
            .map(|candidate| ProgressPendingCandidate {
                candidate_index: candidate.candidate_index,
                commit_id: candidate.commit.id.clone(),
                short_id: candidate.commit.short_id.clone(),
                status: ProgressStatus::Pending,
                active_stage: None,
            })
            .collect(),
        complete: Vec::new(),
    };
    write_progress_state(run_dir, &progress)
}

/// Updates one candidate status in the persisted progress file.
fn update_candidate_progress(
    run_dir: &Path,
    candidate_index: usize,
    pending_status: Option<ProgressStatus>,
    active_stage: Option<&str>,
    result: Option<ProgressResult>,
) -> Result<()> {
    let mut progress = load_progress_state(run_dir)?;
    if let Some(result) = result {
        let pending_candidate = remove_pending_candidate(&mut progress, candidate_index)?
            .or_else(|| {
                progress
                    .complete
                    .iter()
                    .find(|candidate| candidate.candidate_index == candidate_index)
                    .map(|candidate| ProgressPendingCandidate {
                        candidate_index: candidate.candidate_index,
                        commit_id: candidate.commit_id.clone(),
                        short_id: candidate.short_id.clone(),
                        status: ProgressStatus::Pending,
                        active_stage: None,
                    })
            })
            .with_context(|| format!("missing candidate {candidate_index:04} in progress.json"))?;

        upsert_complete_candidate(
            &mut progress,
            ProgressCompleteCandidate {
                candidate_index: pending_candidate.candidate_index,
                commit_id: pending_candidate.commit_id,
                short_id: pending_candidate.short_id,
                result,
            },
        );
    } else if pending_status.is_some() || active_stage.is_some() {
        let candidate = progress
            .pending
            .iter_mut()
            .find(|candidate| candidate.candidate_index == candidate_index)
            .with_context(|| format!("missing candidate {candidate_index:04} in progress.json"))?;
        if let Some(status) = pending_status {
            candidate.status = status;
        }
        candidate.active_stage = active_stage.map(ToOwned::to_owned);
    }

    refresh_progress_counts(&mut progress);
    write_progress_state(run_dir, &progress)
}

/// Loads the persisted progress state for one run.
fn load_progress_state(run_dir: &Path) -> Result<ProgressState> {
    let path = progress_state_path(run_dir);
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

/// Writes the persisted progress state for one run.
fn write_progress_state(run_dir: &Path, progress: &ProgressState) -> Result<()> {
    let path = progress_state_path(run_dir);
    fs::write(&path, serde_json::to_string_pretty(progress)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Reconciles an existing progress file with the current candidate list.
fn reconcile_progress_state(progress: &mut ProgressState, candidates: &[CommitCandidate]) {
    let mut next_pending = Vec::new();
    let mut next_complete = Vec::new();

    for candidate in candidates {
        if let Some(existing) = progress
            .complete
            .iter()
            .find(|entry| entry.candidate_index == candidate.candidate_index)
        {
            next_complete.push(existing.clone());
            continue;
        }

        if let Some(existing) = progress
            .pending
            .iter()
            .find(|entry| entry.candidate_index == candidate.candidate_index)
        {
            next_pending.push(existing.clone());
            continue;
        }

        next_pending.push(ProgressPendingCandidate {
            candidate_index: candidate.candidate_index,
            commit_id: candidate.commit.id.clone(),
            short_id: candidate.commit.short_id.clone(),
            status: ProgressStatus::Pending,
            active_stage: None,
        });
    }

    progress.pending = next_pending;
    progress.complete = next_complete;
    refresh_progress_counts(progress);
}

/// Returns the persisted progress file path for one run.
fn progress_state_path(run_dir: &Path) -> PathBuf {
    run_dir.join("progress.json")
}

/// Resets and recreates the work-in-progress directory for one candidate.
fn prepare_wip_candidate_dir(candidate_dir: &Path, verbose: bool) -> Result<()> {
    if candidate_dir.exists() {
        log_step(
            verbose,
            "wip",
            format!(
                "removing stale work-in-progress candidate {}",
                candidate_dir.display()
            ),
        );
        fs::remove_dir_all(candidate_dir)
            .with_context(|| format!("failed to remove {}", candidate_dir.display()))?;
    }

    fs::create_dir_all(candidate_dir)
        .with_context(|| format!("failed to create {}", candidate_dir.display()))
}

/// Finalizes one completed candidate, optionally retaining its artifact directory.
fn finalize_candidate_dir(
    wip_dir: &Path,
    completed_dir: &Path,
    keep_artifacts: bool,
    verbose: bool,
) -> Result<()> {
    if !keep_artifacts {
        log_step(
            verbose,
            "wip",
            format!(
                "dropping clean completed candidate artifacts at {}",
                wip_dir.display()
            ),
        );
        return fs::remove_dir_all(wip_dir)
            .with_context(|| format!("failed to remove {}", wip_dir.display()));
    }

    promote_completed_candidate(wip_dir, completed_dir, verbose)
}

/// Atomically promotes one completed candidate out of `wip/`.
fn promote_completed_candidate(wip_dir: &Path, completed_dir: &Path, verbose: bool) -> Result<()> {
    if completed_dir.exists() {
        fs::remove_dir_all(completed_dir)
            .with_context(|| format!("failed to remove {}", completed_dir.display()))?;
    }

    log_step(
        verbose,
        "wip",
        format!(
            "promoting completed candidate {} -> {}",
            wip_dir.display(),
            completed_dir.display()
        ),
    );
    fs::rename(wip_dir, completed_dir).with_context(|| {
        format!(
            "failed to promote {} to {}",
            wip_dir.display(),
            completed_dir.display()
        )
    })
}

/// Returns true when candidate artifacts should remain on disk after completion.
///
/// Prompt inputs and rendered prompts are primary debugging artifacts, so completed candidates
/// keep their directories even when analysis finishes with no findings.
fn should_retain_candidate_artifacts() -> bool {
    true
}

/// Builds the persisted result metadata for one completed candidate.
fn progress_result_from_outcome(
    outcome: &CandidateOutcome,
    artifacts_retained: bool,
) -> ProgressResult {
    ProgressResult {
        candidate_summary: outcome.final_summary().to_owned(),
        finding_count: outcome.final_findings().len(),
        artifacts_retained,
    }
}

/// Reconstructs a completed clean outcome from `progress.json`.
///
/// This supports legacy runs created before completed candidate directories were always retained.
fn load_completed_clean_outcome(
    run_dir: &Path,
    candidate_index: usize,
) -> Result<Option<CandidateOutcome>> {
    if !progress_state_path(run_dir).exists() {
        return Ok(None);
    }

    let progress = load_progress_state(run_dir)?;
    let Some(candidate) = progress
        .complete
        .iter()
        .find(|candidate| candidate.candidate_index == candidate_index)
    else {
        return Ok(None);
    };

    if candidate.result.artifacts_retained || candidate.result.finding_count != 0 {
        return Ok(None);
    }

    Ok(Some(CandidateOutcome {
        screening: ScreeningAnalysis {
            candidate_summary: candidate.result.candidate_summary.clone(),
            suspicious_findings: Vec::new(),
        },
        verification: None,
    }))
}

/// Removes one pending candidate from the progress state and returns it.
fn remove_pending_candidate(
    progress: &mut ProgressState,
    candidate_index: usize,
) -> Result<Option<ProgressPendingCandidate>> {
    let Some(position) = progress
        .pending
        .iter()
        .position(|candidate| candidate.candidate_index == candidate_index)
    else {
        return Ok(None);
    };

    Ok(Some(progress.pending.remove(position)))
}

/// Inserts or replaces one completed candidate entry.
fn upsert_complete_candidate(progress: &mut ProgressState, candidate: ProgressCompleteCandidate) {
    if let Some(position) = progress
        .complete
        .iter()
        .position(|entry| entry.candidate_index == candidate.candidate_index)
    {
        progress.complete[position] = candidate;
    } else {
        progress.complete.push(candidate);
        progress.complete.sort_by_key(|entry| entry.candidate_index);
    }
}

/// Recomputes the persisted top-level progress counters.
fn refresh_progress_counts(progress: &mut ProgressState) {
    progress.count_pending = progress.pending.len();
    progress.count_complete = progress.complete.len();
}

/// Returns the completed artifact directory for one candidate.
fn completed_candidate_dir(run_dir: &Path, candidate_index: usize) -> PathBuf {
    run_dir.join(format!("candidate-{candidate_index:04}"))
}

/// Returns the work-in-progress artifact directory for one candidate.
fn wip_candidate_dir(run_dir: &Path, candidate_index: usize) -> PathBuf {
    run_dir
        .join("wip")
        .join(format!("candidate-{candidate_index:04}"))
}

/// Returns the pass-specific artifact directory for one candidate.
fn pass_dir(candidate_dir: &Path, phase: AnalysisPhase) -> PathBuf {
    candidate_dir.join(phase.as_str())
}

/// Prints one verbose log line.
fn log_step(verbose: bool, scope: &str, message: String) {
    if !verbose {
        return;
    }

    eprintln!("[vcamper:{scope}] {message}");
}

/// Returns a short commit id prefix for progress display.
fn short_hash(commit: &str) -> &str {
    &commit[..usize::min(commit.len(), 12)]
}

/// Terminal progress UI for commit-candidate execution.
struct ProgressUi {
    overall: ProgressBar,
    active: ProgressBar,
    total_candidates: usize,
    total_commits: usize,
    enabled: bool,
}

impl ProgressUi {
    /// Builds the terminal progress bars for one analysis run.
    fn new(total_candidates: usize, total_commits: usize, verbose: bool) -> Self {
        if verbose {
            return Self {
                overall: ProgressBar::hidden(),
                active: ProgressBar::hidden(),
                total_candidates,
                total_commits,
                enabled: false,
            };
        }

        let overall = ProgressBar::new(total_candidates as u64);
        overall.set_style(
            ProgressStyle::with_template("{bar:40.cyan/blue} {pos}/{len} candidates {msg}")
                .expect("progress template should be valid"),
        );
        overall.set_message("waiting to start");

        let active = ProgressBar::new_spinner();
        active.set_style(
            ProgressStyle::with_template("{spinner} {msg}")
                .expect("spinner template should be valid"),
        );

        Self {
            overall,
            active,
            total_candidates,
            total_commits,
            enabled: true,
        }
    }

    /// Starts the spinner for the active candidate phase.
    fn start_phase(
        &self,
        candidate_index: usize,
        phase: AnalysisPhase,
        provider: &str,
        commit_id: &str,
    ) {
        if !self.enabled {
            return;
        }

        self.overall.set_message(format!(
            "running candidate {}/{} across {} included commit(s)",
            candidate_index + 1,
            self.total_candidates,
            self.total_commits
        ));
        self.active.set_message(format!(
            "{provider} {} pass {}/{}: commit {}",
            phase.as_str(),
            candidate_index + 1,
            self.total_candidates,
            commit_id
        ));
        self.active.enable_steady_tick(Duration::from_millis(120));
    }

    /// Marks one already-completed candidate as reused during resume.
    fn reuse_candidate(&self, candidate_index: usize) {
        if !self.enabled {
            return;
        }

        self.overall.inc(1);
        self.overall.set_message(format!(
            "reused candidate {}/{} across {} included commit(s)",
            candidate_index + 1,
            self.total_candidates,
            self.total_commits
        ));
    }

    /// Marks one candidate as completed and updates the overall status line.
    fn complete_candidate(&self, candidate_index: usize, finding_count: usize, dry_run: bool) {
        if !self.enabled {
            return;
        }

        self.active.finish_and_clear();
        self.overall.inc(1);
        let status = if dry_run { "prepared" } else { "completed" };
        self.overall.set_message(format!(
            "{status} candidate {}/{} across {} included commit(s) ({finding_count} finding(s))",
            candidate_index + 1,
            self.total_candidates,
            self.total_commits
        ));
    }

    /// Finishes the progress bars for the run.
    fn finish(&self) {
        if !self.enabled {
            return;
        }

        self.active.finish_and_clear();
        self.overall.finish_with_message(format!(
            "finished {} candidate(s) across {} included commit(s)",
            self.total_candidates, self.total_commits
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CodexReachabilityRecord, absolute_artifact_path, bundle_snapshot_path, ensure_manifest,
        initialize_progress_state, load_progress_state, load_saved_candidate_outcome,
        merge_codex_inventory_results, persist_candidate_outcome, select_adjudication_finalists,
        should_keep_reachability_result, should_review_reachability, validate_args,
    };
    use crate::cli::{AnalyzeArgs, PipelineStage, ProviderKind};
    use crate::hotspot::HotspotCluster;
    use crate::types::{
        CandidateOutcome, CommitCandidate, CommitRecord, InteractionAnalysis, InteractionKind,
        InteractionVerdict, ProgressResult, ProgressStatus, ReachabilityAnalysis,
        ReachabilityAssessment, ReachabilitySurface, ReachabilityVerdict, RunManifest,
        ScreeningAnalysis, SuspiciousFinding,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_out_of_range_confidence() {
        let args = AnalyzeArgs {
            repo: PathBuf::from("."),
            from: "a".into(),
            to: "b".into(),
            provider: ProviderKind::Codex,
            model: None,
            effort: None,
            screen_effort: None,
            verify_effort: None,
            max_commits: None,
            max_patch_bytes: 100,
            min_confidence: 1.1,
            out: PathBuf::from("out"),
            verbose: false,
            dry_run: true,
            stop_after_stage: None,
        };
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn rejects_stop_after_stage_for_claude() {
        let args = AnalyzeArgs {
            repo: PathBuf::from("."),
            from: "a".into(),
            to: "b".into(),
            provider: ProviderKind::Claude,
            model: None,
            effort: None,
            screen_effort: None,
            verify_effort: None,
            max_commits: None,
            max_patch_bytes: 100,
            min_confidence: 0.5,
            out: PathBuf::from("out"),
            verbose: false,
            dry_run: true,
            stop_after_stage: Some(PipelineStage::Inventory),
        };

        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn rejects_resume_when_manifest_differs() {
        let dir = temp_test_dir("manifest-mismatch");
        let existing = sample_manifest("codex");
        ensure_manifest(&dir, &existing, false).expect("manifest should persist");

        let mismatched = sample_manifest("claude");
        assert!(ensure_manifest(&dir, &mismatched, false).is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn persists_and_loads_candidate_outcome() {
        let dir = temp_test_dir("candidate-outcome");
        let outcome = CandidateOutcome {
            screening: ScreeningAnalysis {
                candidate_summary: "summary".into(),
                suspicious_findings: Vec::new(),
            },
            verification: None,
        };

        persist_candidate_outcome(&dir, &outcome).expect("outcome should persist");
        let loaded = load_saved_candidate_outcome(&dir, &dir, 0, false)
            .expect("outcome should load")
            .expect("outcome should exist");
        assert_eq!(loaded.screening.candidate_summary, "summary");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn initializes_and_updates_progress_state() {
        let dir = temp_test_dir("progress-state");
        let candidates = vec![
            CommitCandidate {
                candidate_index: 0,
                commit: sample_commit("a"),
            },
            CommitCandidate {
                candidate_index: 1,
                commit: sample_commit("b"),
            },
        ];

        initialize_progress_state(&dir, &candidates).expect("progress should initialize");
        super::update_candidate_progress(
            &dir,
            0,
            None,
            None,
            Some(ProgressResult {
                candidate_summary: "summary".into(),
                finding_count: 0,
                artifacts_retained: true,
            }),
        )
        .expect("progress should update");

        let progress = load_progress_state(&dir).expect("progress should load");
        assert_eq!(progress.count_pending, 1);
        assert_eq!(progress.count_complete, 1);
        assert_eq!(progress.pending.len(), 1);
        assert_eq!(progress.complete.len(), 1);
        assert_eq!(progress.complete[0].result.finding_count, 0);
        assert_eq!(progress.pending[0].status, ProgressStatus::Pending);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn loads_legacy_clean_outcome_from_progress_without_artifacts() {
        let dir = temp_test_dir("legacy-clean-outcome");
        let candidates = vec![CommitCandidate {
            candidate_index: 0,
            commit: sample_commit("a"),
        }];

        initialize_progress_state(&dir, &candidates).expect("progress should initialize");
        super::update_candidate_progress(
            &dir,
            0,
            None,
            None,
            Some(ProgressResult {
                candidate_summary: "legacy summary".into(),
                finding_count: 0,
                artifacts_retained: false,
            }),
        )
        .expect("progress should update");

        let loaded = load_saved_candidate_outcome(&dir, &dir.join("candidate-0000"), 0, false)
            .expect("outcome should load")
            .expect("legacy outcome should exist");
        assert_eq!(loaded.screening.candidate_summary, "legacy summary");
        assert!(loaded.screening.suspicious_findings.is_empty());
        assert!(loaded.verification.is_none());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bundle_snapshot_path_preserves_repo_relative_layout() {
        let resolved = bundle_snapshot_path(Path::new("/tmp/bundle"), "src/nested/file.rs")
            .expect("bundle path should resolve");

        assert_eq!(resolved, PathBuf::from("/tmp/bundle/src/nested/file.rs"));
    }

    #[test]
    fn bundle_snapshot_path_rejects_parent_traversal() {
        assert!(bundle_snapshot_path(Path::new("/tmp/bundle"), "../secret").is_err());
    }

    #[test]
    fn absolute_artifact_path_resolves_nonexistent_relative_paths() {
        let relative = Path::new(".tmp/tests/nonexistent/prompt-input.json");
        let resolved =
            absolute_artifact_path(relative).expect("relative artifact path should resolve");

        assert!(resolved.starts_with('/'));
        assert!(resolved.ends_with(".tmp/tests/nonexistent/prompt-input.json"));
    }

    #[test]
    fn interaction_preserve_for_adjudication_still_enters_reachability() {
        let analysis = InteractionAnalysis {
            hypothesis_summary: "interaction".into(),
            verdict: InteractionVerdict::Plausible,
            interaction_kind: InteractionKind::FeatureInteraction,
            preconditions: vec!["mixed algorithm support".into()],
            preserve_for_reachability: false,
            preserve_for_adjudication: true,
            refined_finding: None,
        };

        assert!(should_review_reachability(&analysis));
    }

    #[test]
    fn rejected_reachability_can_survive_when_interaction_preserves_adjudication() {
        let record = sample_reachability_record(
            7,
            "digest_length_verify",
            InteractionAnalysis {
                hypothesis_summary: "shared verification flow".into(),
                verdict: InteractionVerdict::Strong,
                interaction_kind: InteractionKind::SharedVerificationFlow,
                preconditions: vec!["certificate verification path".into()],
                preserve_for_reachability: true,
                preserve_for_adjudication: true,
                refined_finding: Some(sample_finding(
                    "shared verification flow",
                    0.72,
                    "wolfcrypt/src/asn.c",
                )),
            },
            ReachabilityAnalysis {
                hypothesis_summary: "direct path remains weak".into(),
                verdict: ReachabilityVerdict::Rejected,
                surface: ReachabilitySurface::Unknown,
                assessment: ReachabilityAssessment::InteractionDependent,
                preconditions: vec!["mixed feature support".into()],
                keep_for_adjudication: false,
                refined_finding: Some(sample_finding(
                    "shared verification flow",
                    0.72,
                    "wolfcrypt/src/asn.c",
                )),
            },
        );

        assert!(should_keep_reachability_result(&record));
    }

    #[test]
    fn adjudication_finalists_prioritize_interaction_theories_over_local_api_only() {
        let local_api = sample_reachability_record(
            1,
            "digest_length_sign",
            InteractionAnalysis {
                hypothesis_summary: "plain local api".into(),
                verdict: InteractionVerdict::Absent,
                interaction_kind: InteractionKind::DirectPath,
                preconditions: vec![],
                preserve_for_reachability: true,
                preserve_for_adjudication: false,
                refined_finding: Some(sample_finding(
                    "local api overflow",
                    0.96,
                    "wolfcrypt/src/dilithium.c",
                )),
            },
            ReachabilityAnalysis {
                hypothesis_summary: "public hash api overflow".into(),
                verdict: ReachabilityVerdict::Supported,
                surface: ReachabilitySurface::LocalApi,
                assessment: ReachabilityAssessment::LocalApiOnly,
                preconditions: vec!["application exposes hash api".into()],
                keep_for_adjudication: true,
                refined_finding: Some(sample_finding(
                    "local api overflow",
                    0.96,
                    "wolfcrypt/src/dilithium.c",
                )),
            },
        );
        let interaction = sample_reachability_record(
            2,
            "digest_length_verify",
            InteractionAnalysis {
                hypothesis_summary: "mixed-family verification path".into(),
                verdict: InteractionVerdict::Strong,
                interaction_kind: InteractionKind::FeatureInteraction,
                preconditions: vec!["eddsa or ml-dsa enabled".into()],
                preserve_for_reachability: true,
                preserve_for_adjudication: true,
                refined_finding: Some(sample_finding(
                    "ecdsa verification accepted undersized digest",
                    0.78,
                    "src/pk_ec.c",
                )),
            },
            ReachabilityAnalysis {
                hypothesis_summary: "shared verification path not fully proven locally".into(),
                verdict: ReachabilityVerdict::Weak,
                surface: ReachabilitySurface::Unknown,
                assessment: ReachabilityAssessment::InteractionDependent,
                preconditions: vec!["certificate verification flow".into()],
                keep_for_adjudication: true,
                refined_finding: Some(sample_finding(
                    "ecdsa verification accepted undersized digest",
                    0.78,
                    "src/pk_ec.c",
                )),
            },
        );

        let finalists = select_adjudication_finalists(&[local_api, interaction])
            .expect("selection should work");

        assert_eq!(finalists[0].hypothesis_index, 2);
        assert!(
            finalists
                .iter()
                .any(|finalist| finalist.hypothesis_index == 1)
        );
        assert!(
            finalists
                .iter()
                .any(|finalist| finalist.hypothesis_index == 2)
        );
    }

    #[test]
    fn inventory_merge_keeps_only_primary_finding_per_focus() {
        let cluster = sample_cluster("digest_length_verify");
        let merged = merge_codex_inventory_results(
            1,
            vec![(
                cluster,
                ScreeningAnalysis {
                    candidate_summary: "summary".into(),
                    suspicious_findings: vec![
                        sample_finding("lower confidence", 0.61, "src/a.rs"),
                        sample_finding("higher confidence", 0.88, "src/a.rs"),
                    ],
                },
            )],
        );

        assert_eq!(merged.hypotheses.len(), 1);
        assert_eq!(merged.hypotheses[0].finding.title, "higher confidence");
    }

    fn sample_manifest(provider: &str) -> RunManifest {
        RunManifest {
            provider: provider.to_owned(),
            model: Some("gpt-5.4".into()),
            screen_effort: Some("medium".into()),
            verify_effort: Some("high".into()),
            repo_root: "/repo".into(),
            from: "from".into(),
            to: "to".into(),
            commit_count: 1,
            max_patch_bytes: 100,
            dry_run: false,
            stop_after_stage: None,
        }
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vcamper-{label}-{suffix}"));
        fs::create_dir_all(&dir).expect("temp dir should exist");
        dir
    }

    fn sample_commit(id: &str) -> CommitRecord {
        CommitRecord {
            id: id.into(),
            short_id: id.into(),
            parent_ids: vec![],
            author_name: "alice".into(),
            author_email: "alice@example.com".into(),
            authored_at: "2025-01-01T00:00:00Z".into(),
            summary: id.into(),
            files_changed: vec!["src/a.rs".into()],
            file_stats: Vec::new(),
            patch: "patch".into(),
            patch_truncated: false,
        }
    }

    fn sample_finding(title: &str, confidence: f32, path: &str) -> SuspiciousFinding {
        SuspiciousFinding {
            title: title.into(),
            confidence,
            commit_id: "commit".into(),
            rationale: "rationale".into(),
            likely_bug_class: Some("bug_class".into()),
            affected_files: vec![path.into()],
            evidence: vec!["evidence".into()],
            follow_up: vec!["follow_up".into()],
        }
    }

    fn sample_cluster(category: &str) -> HotspotCluster {
        HotspotCluster {
            cluster_index: 0,
            title: format!("{category} cluster"),
            rationale: "rationale".into(),
            category: category.into(),
            files: vec!["src/a.rs".into()],
            function_hints: vec!["function".into()],
            signal_terms: vec!["signal".into()],
            score: 10,
        }
    }

    fn sample_reachability_record(
        hypothesis_index: usize,
        cluster_category: &str,
        interaction_analysis: InteractionAnalysis,
        analysis: ReachabilityAnalysis,
    ) -> CodexReachabilityRecord {
        CodexReachabilityRecord {
            hypothesis_index,
            cluster: sample_cluster(cluster_category),
            interaction_analysis,
            analysis,
        }
    }
}
