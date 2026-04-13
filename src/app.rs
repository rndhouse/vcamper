//! Application orchestration for the VCamper CLI.
//! Ownership: client-only

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

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
    CandidateOutcome, CandidateStageState, CommitCandidate, FileStat, InteractionAnalysis,
    InteractionKind, InteractionVerdict, ProgressCompleteCandidate, ProgressPendingCandidate,
    ProgressResult, ProgressState, ProgressStatus, ReachabilityAnalysis, ReachabilityAssessment,
    ReachabilitySurface, ReachabilityVerdict, RunManifest, ScreeningAnalysis, SuspiciousFinding,
    VerificationAnalysis, VerificationVerdict,
};

#[derive(Debug, Clone, Copy)]
struct StageExecutionPlan {
    start_at: PipelineStage,
    stop_after: PipelineStage,
    rerun_from: Option<PipelineStage>,
}

impl StageExecutionPlan {
    fn from_args(args: &AnalyzeArgs) -> Self {
        let start_at = args.start_at_stage.unwrap_or(PipelineStage::Inventory);
        let stop_after = args.stop_after_stage.unwrap_or(PipelineStage::Verify);
        let rerun_from = args
            .rerun_stages
            .iter()
            .copied()
            .min_by_key(|stage| stage.order());
        Self {
            start_at,
            stop_after,
            rerun_from,
        }
    }

    fn includes(self, stage: PipelineStage) -> bool {
        stage.order() >= self.start_at.order() && stage.order() <= self.stop_after.order()
    }

    fn stops_after(self, stage: PipelineStage) -> bool {
        self.stop_after == stage
    }

    fn should_rerun(self, stage: PipelineStage) -> bool {
        self.rerun_from
            .map(|rerun_from| stage.order() >= rerun_from.order())
            .unwrap_or(false)
    }
}

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
    let execution_plan = StageExecutionPlan::from_args(&args);

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
        start_at_stage: args.start_at_stage.map(|stage| stage.as_str().to_owned()),
        inventory_focuses: args.inventory_focuses.clone(),
        rerun_stages: args
            .rerun_stages
            .iter()
            .map(|stage| stage.as_str().to_owned())
            .collect(),
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
    let synthesis_schema = screening_schema()?;
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
            let saved_outcome = match args.provider {
                ProviderKind::Claude => load_saved_candidate_outcome(
                    &run_dir,
                    &completed_dir,
                    candidate.candidate_index,
                    verbose,
                )?,
                ProviderKind::Codex => {
                    if completed_dir.exists()
                        && candidate_request_satisfied(&completed_dir, execution_plan)?
                    {
                        load_saved_candidate_outcome(
                            &run_dir,
                            &completed_dir,
                            candidate.candidate_index,
                            verbose,
                        )?
                    } else {
                        None
                    }
                }
            };
            if let Some(saved_outcome) = saved_outcome {
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
        prepare_candidate_work_dir(&wip_dir, &completed_dir, verbose)?;
        if matches!(args.provider, ProviderKind::Codex)
            && let Some(rerun_from) = execution_plan.rerun_from
        {
            clear_stage_artifacts(&wip_dir, rerun_from, verbose)?;
        }

        let screen_dir = pass_dir(&wip_dir, AnalysisPhase::Screen);
        fs::create_dir_all(&screen_dir)
            .with_context(|| format!("failed to create {}", screen_dir.display()))?;
        let codex_screen_artifacts = match args.provider {
            ProviderKind::Codex => Some(prepare_codex_screen_plan_artifacts(
                &repo_root,
                &screen_dir,
                candidate,
                &args.inventory_focuses,
            )?),
            ProviderKind::Claude => {
                let screen_prompt = prepare_screen_pass_artifacts(
                    args.provider,
                    &repo_root,
                    &screen_dir,
                    candidate,
                    &args.inventory_focuses,
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
                &synthesis_schema,
                &interaction_review_schema,
                &reachability_review_schema,
                args.model.as_deref(),
                screen_effort,
                execution_plan,
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
        let codex_screening_state =
            codex_screening_output
                .as_ref()
                .map(|output| CandidateStageState {
                    highest_completed_stage: output.highest_completed_stage.as_str().to_owned(),
                    pipeline_complete: output.pipeline_complete,
                });
        if let Some(stage_state) = &codex_screening_state {
            persist_candidate_stage_state(&wip_dir, stage_state)?;
        }

        let verification = if screening.suspicious_findings.is_empty()
            || !execution_plan.includes(PipelineStage::Verify)
        {
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
                Some("verify finalist review"),
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
                if !execution_plan.should_rerun(PipelineStage::Verify)
                    && verify_dir.join("analysis.json").exists()
                {
                    Some(load_json_file(&verify_dir.join("analysis.json"))?)
                } else {
                    if let Some(artifacts) = prepare_codex_verify_artifacts(
                        &repo_root,
                        &verify_dir,
                        candidate,
                        &output.hotspot_plan,
                        &output.reachability_results,
                    )? {
                        let records = run_codex_verification(
                            provider.as_ref(),
                            &repo_root,
                            &artifacts,
                            &run_dir,
                            &verify_schema,
                            candidate.candidate_index,
                            args.model.as_deref(),
                            verify_effort,
                            execution_plan.should_rerun(PipelineStage::Verify),
                            verbose,
                        )?;
                        persist_verify_stage_output(&verify_dir, &records)?;
                        Some(merge_codex_verification_results(&records))
                    } else {
                        Some(VerificationAnalysis {
                            verification_summary:
                                "No reachability-reviewed hypotheses survived into finalist verification."
                                    .to_owned(),
                            verdict: VerificationVerdict::Rejected,
                            confirmed_findings: Vec::new(),
                        })
                    }
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
        let final_stage_state = if outcome.verification.is_some() {
            CandidateStageState {
                highest_completed_stage: PipelineStage::Verify.as_str().to_owned(),
                pipeline_complete: true,
            }
        } else if let Some(stage_state) = codex_screening_state {
            stage_state
        } else {
            CandidateStageState {
                highest_completed_stage: PipelineStage::Verify.as_str().to_owned(),
                pipeline_complete: true,
            }
        };
        persist_candidate_input(&wip_dir, candidate)?;
        persist_candidate_outcome(&wip_dir, &outcome)?;
        persist_candidate_stage_state(&wip_dir, &final_stage_state)?;
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
    if (args.stop_after_stage.is_some()
        || args.start_at_stage.is_some()
        || !args.inventory_focuses.is_empty()
        || !args.rerun_stages.is_empty())
        && !matches!(args.provider, ProviderKind::Codex)
    {
        bail!(
            "--stop-after-stage, --start-at-stage, --inventory-focuses, and --rerun-stages are currently supported only with --provider codex"
        );
    }
    if let (Some(start_at_stage), Some(stop_after_stage)) =
        (args.start_at_stage, args.stop_after_stage)
        && start_at_stage.order() > stop_after_stage.order()
    {
        bail!("--start-at-stage cannot come after --stop-after-stage");
    }
    Ok(())
}

/// Returns whether two manifests describe the same reusable analysis run.
fn manifests_match(existing: &RunManifest, current: &RunManifest) -> bool {
    existing.provider == current.provider
        && existing.model == current.model
        && existing.screen_effort == current.screen_effort
        && existing.verify_effort == current.verify_effort
        && existing.repo_root == current.repo_root
        && existing.from == current.from
        && existing.to == current.to
        && existing.commit_count == current.commit_count
        && existing.max_patch_bytes == current.max_patch_bytes
        && existing.dry_run == current.dry_run
        && existing.inventory_focuses == current.inventory_focuses
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

        if !manifests_match(&existing, manifest) {
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
        return fs::write(&path, serde_json::to_string_pretty(manifest)?)
            .with_context(|| format!("failed to update {}", path.display()));
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

/// Persists one structured stage-result file in pretty JSON form.
fn persist_stage_results<T>(path: &Path, results: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    fs::write(path, serde_json::to_string_pretty(results)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Persists one candidate-stage state file.
fn persist_candidate_stage_state(candidate_dir: &Path, state: &CandidateStageState) -> Result<()> {
    let path = candidate_stage_state_path(candidate_dir);
    persist_stage_results(&path, state)
}

/// Loads one candidate-stage state file when it exists.
fn load_candidate_stage_state(candidate_dir: &Path) -> Result<Option<CandidateStageState>> {
    let path = candidate_stage_state_path(candidate_dir);
    if path.exists() {
        return load_json_file(&path).map(Some);
    }

    infer_candidate_stage_state(candidate_dir)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexInventoryFocusResult {
    cluster: HotspotCluster,
    analysis: ScreeningAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexSynthesisGroup {
    cluster: HotspotCluster,
    focus_results: Vec<CodexInventoryFocusResult>,
}

#[derive(Debug, Serialize)]
struct CodexSynthesisPromptInput {
    candidate_index: usize,
    commit: CodexPromptCommit,
    hotspot_plan: HotspotPlan,
    synthesis_group: CodexSynthesisGroup,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    finalist: CodexAdjudicationCandidate,
}

#[derive(Debug, Clone)]
struct CodexVerifyArtifacts {
    hypothesis_index: usize,
    finalist: CodexAdjudicationCandidate,
    pass_dir: PathBuf,
    prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexVerificationRecord {
    hypothesis_index: usize,
    finalist: CodexAdjudicationCandidate,
    analysis: VerificationAnalysis,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexInventoryHypothesis {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    finding: SuspiciousFinding,
}

#[derive(Debug, Clone)]
struct CodexSynthesisArtifacts {
    group: CodexSynthesisGroup,
    pass_dir: PathBuf,
    prompt: String,
}

#[derive(Debug, Clone)]
struct CodexInteractionArtifacts {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    inventory_finding: SuspiciousFinding,
    pass_dir: PathBuf,
    prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexReachabilityRecord {
    hypothesis_index: usize,
    cluster: HotspotCluster,
    interaction_analysis: InteractionAnalysis,
    analysis: ReachabilityAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexInventoryMergeOutput {
    analysis: ScreeningAnalysis,
    focus_results: Vec<CodexInventoryFocusResult>,
    hypotheses: Vec<CodexInventoryHypothesis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexSynthesisMergeOutput {
    analysis: ScreeningAnalysis,
    hypotheses: Vec<CodexInventoryHypothesis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexInteractionStageOutput {
    analysis: ScreeningAnalysis,
    records: Vec<CodexInteractionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexReachabilityStageOutput {
    analysis: ScreeningAnalysis,
    records: Vec<CodexReachabilityRecord>,
}

#[derive(Debug, Clone)]
struct CodexScreeningPipelineOutput {
    screening: ScreeningAnalysis,
    hotspot_plan: HotspotPlan,
    reachability_results: Vec<CodexReachabilityRecord>,
    highest_completed_stage: PipelineStage,
    pipeline_complete: bool,
}

/// Prepares one screening-pass prompt and pass artifacts for the selected provider.
fn prepare_screen_pass_artifacts(
    provider: ProviderKind,
    repo_root: &Path,
    pass_dir: &Path,
    candidate: &CommitCandidate,
    inventory_focuses: &[usize],
) -> Result<String> {
    match provider {
        ProviderKind::Codex => {
            let artifacts = prepare_codex_screen_plan_artifacts(
                repo_root,
                pass_dir,
                candidate,
                inventory_focuses,
            )?;
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

/// Returns the synthesis-stage artifact root for one screen pass.
fn synthesis_stage_dir(screen_dir: &Path) -> PathBuf {
    screen_dir.join("synthesis")
}

/// Returns the reachability-stage artifact root for one screen pass.
fn reachability_stage_dir(screen_dir: &Path) -> PathBuf {
    screen_dir.join("reachability")
}

/// Returns the interaction-stage artifact root for one screen pass.
fn interaction_stage_dir(screen_dir: &Path) -> PathBuf {
    screen_dir.join("interaction")
}

/// Returns the persisted inventory-stage results path.
fn inventory_results_path(screen_dir: &Path) -> PathBuf {
    inventory_stage_dir(screen_dir).join("results.json")
}

/// Returns the persisted synthesis-stage results path.
fn synthesis_results_path(screen_dir: &Path) -> PathBuf {
    synthesis_stage_dir(screen_dir).join("results.json")
}

/// Returns the persisted interaction-stage results path.
fn interaction_results_path(screen_dir: &Path) -> PathBuf {
    interaction_stage_dir(screen_dir).join("results.json")
}

/// Returns the persisted reachability-stage results path.
fn reachability_results_path(screen_dir: &Path) -> PathBuf {
    reachability_stage_dir(screen_dir).join("results.json")
}

/// Returns the persisted independent verification-stage results path.
fn verify_results_path(verify_dir: &Path) -> PathBuf {
    verify_dir.join("results.json")
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

/// Filters hotspot focus units to an explicit shortlist when one was requested.
fn select_inventory_focuses(
    inventory_focuses: &[HotspotCluster],
    selected_indexes: &[usize],
) -> Result<Vec<HotspotCluster>> {
    if selected_indexes.is_empty() {
        return Ok(inventory_focuses.to_vec());
    }

    let mut selected = Vec::with_capacity(selected_indexes.len());
    for index in selected_indexes {
        let Some(cluster) = inventory_focuses
            .iter()
            .find(|cluster| cluster.cluster_index == *index)
        else {
            bail!("--inventory-focuses references missing hotspot focus index {index}");
        };
        selected.push(cluster.clone());
    }

    Ok(selected)
}

/// Prepares one focused Codex inventory plan and its evidence bundles.
fn prepare_codex_screen_plan_artifacts(
    repo_root: &Path,
    screen_dir: &Path,
    candidate: &CommitCandidate,
    selected_focuses: &[usize],
) -> Result<CodexInventoryPlanArtifacts> {
    let full_patch = git::load_full_patch(repo_root, &candidate.commit.id)?;
    let hotspot_plan = hotspot::build_hotspot_plan(&full_patch);
    let inventory_focuses =
        select_inventory_focuses(&build_inventory_focuses(&hotspot_plan), selected_focuses)?;
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

/// Loads persisted inventory-stage output when it exists.
fn load_inventory_merge_output(screen_dir: &Path) -> Result<Option<CodexInventoryMergeOutput>> {
    let path = inventory_results_path(screen_dir);
    if !path.exists() {
        return Ok(None);
    }
    load_json_file(&path).map(Some)
}

/// Persists merged inventory-stage output.
fn persist_inventory_merge_output(
    screen_dir: &Path,
    output: &CodexInventoryMergeOutput,
) -> Result<()> {
    persist_stage_results(&inventory_results_path(screen_dir), output)
}

/// Loads persisted synthesis-stage output when it exists.
fn load_synthesis_merge_output(screen_dir: &Path) -> Result<Option<CodexSynthesisMergeOutput>> {
    let path = synthesis_results_path(screen_dir);
    if !path.exists() {
        return Ok(None);
    }
    load_json_file(&path).map(Some)
}

/// Persists merged synthesis-stage output.
fn persist_synthesis_merge_output(
    screen_dir: &Path,
    output: &CodexSynthesisMergeOutput,
) -> Result<()> {
    persist_stage_results(&synthesis_results_path(screen_dir), output)
}

/// Loads persisted interaction-stage output when it exists.
fn load_interaction_stage_output(screen_dir: &Path) -> Result<Option<CodexInteractionStageOutput>> {
    let path = interaction_results_path(screen_dir);
    if !path.exists() {
        return Ok(None);
    }
    load_json_file(&path).map(Some)
}

/// Persists merged interaction-stage output.
fn persist_interaction_stage_output(
    screen_dir: &Path,
    output: &CodexInteractionStageOutput,
) -> Result<()> {
    persist_stage_results(&interaction_results_path(screen_dir), output)
}

/// Loads persisted reachability-stage output when it exists.
fn load_reachability_stage_output(
    screen_dir: &Path,
) -> Result<Option<CodexReachabilityStageOutput>> {
    let path = reachability_results_path(screen_dir);
    if !path.exists() {
        return Ok(None);
    }
    load_json_file(&path).map(Some)
}

/// Persists merged reachability-stage output.
fn persist_reachability_stage_output(
    screen_dir: &Path,
    output: &CodexReachabilityStageOutput,
) -> Result<()> {
    persist_stage_results(&reachability_results_path(screen_dir), output)
}

/// Persists the independent per-hypothesis verification results.
fn persist_verify_stage_output(
    verify_dir: &Path,
    results: &[CodexVerificationRecord],
) -> Result<()> {
    persist_stage_results(&verify_results_path(verify_dir), results)
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
    synthesis_schema: &str,
    interaction_schema: &str,
    reachability_schema: &str,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    execution_plan: StageExecutionPlan,
    verbose: bool,
) -> Result<CodexScreeningPipelineOutput> {
    let inventory = if execution_plan.includes(PipelineStage::Inventory) {
        if !execution_plan.should_rerun(PipelineStage::Inventory) {
            if let Some(existing) = load_inventory_merge_output(screen_dir)? {
                existing
            } else {
                run_codex_inventory(
                    provider,
                    artifacts,
                    repo_root,
                    run_dir,
                    inventory_schema,
                    candidate.candidate_index,
                    model,
                    effort,
                    verbose,
                )?
            }
        } else {
            run_codex_inventory(
                provider,
                artifacts,
                repo_root,
                run_dir,
                inventory_schema,
                candidate.candidate_index,
                model,
                effort,
                verbose,
            )?
        }
    } else if let Some(existing) = load_inventory_merge_output(screen_dir)? {
        existing
    } else {
        bail!(
            "inventory stage output is required before starting at {}",
            execution_plan.start_at.as_str()
        );
    };
    let inventory_dir = inventory_stage_dir(screen_dir);
    persist_screening_analysis(&inventory_dir, &inventory.analysis)?;
    persist_inventory_merge_output(screen_dir, &inventory)?;

    if execution_plan.stops_after(PipelineStage::Inventory) {
        return Ok(CodexScreeningPipelineOutput {
            screening: inventory.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
            highest_completed_stage: PipelineStage::Inventory,
            pipeline_complete: false,
        });
    }

    if inventory.hypotheses.is_empty() {
        return Ok(CodexScreeningPipelineOutput {
            screening: inventory.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
            highest_completed_stage: PipelineStage::Inventory,
            pipeline_complete: true,
        });
    }

    update_candidate_progress(
        run_dir,
        candidate.candidate_index,
        Some(ProgressStatus::InProgress),
        Some("screen synthesis"),
        None,
    )?;
    let synthesis = if execution_plan.includes(PipelineStage::Synthesis) {
        if !execution_plan.should_rerun(PipelineStage::Synthesis) {
            if let Some(existing) = load_synthesis_merge_output(screen_dir)? {
                existing
            } else {
                let synthesis_artifacts = prepare_codex_synthesis_artifacts(
                    repo_root, screen_dir, candidate, artifacts, &inventory,
                )?;
                run_codex_synthesis(
                    provider,
                    repo_root,
                    &synthesis_artifacts,
                    run_dir,
                    synthesis_schema,
                    candidate.candidate_index,
                    model,
                    effort,
                    verbose,
                )?
            }
        } else {
            let synthesis_artifacts = prepare_codex_synthesis_artifacts(
                repo_root, screen_dir, candidate, artifacts, &inventory,
            )?;
            run_codex_synthesis(
                provider,
                repo_root,
                &synthesis_artifacts,
                run_dir,
                synthesis_schema,
                candidate.candidate_index,
                model,
                effort,
                verbose,
            )?
        }
    } else if let Some(existing) = load_synthesis_merge_output(screen_dir)? {
        existing
    } else {
        bail!(
            "synthesis stage output is required before starting at {}",
            execution_plan.start_at.as_str()
        );
    };
    let synthesis_dir = synthesis_stage_dir(screen_dir);
    persist_screening_analysis(&synthesis_dir, &synthesis.analysis)?;
    persist_synthesis_merge_output(screen_dir, &synthesis)?;

    if execution_plan.stops_after(PipelineStage::Synthesis) {
        return Ok(CodexScreeningPipelineOutput {
            screening: synthesis.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
            highest_completed_stage: PipelineStage::Synthesis,
            pipeline_complete: false,
        });
    }

    if synthesis.hypotheses.is_empty() {
        return Ok(CodexScreeningPipelineOutput {
            screening: synthesis.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
            highest_completed_stage: PipelineStage::Synthesis,
            pipeline_complete: true,
        });
    }

    update_candidate_progress(
        run_dir,
        candidate.candidate_index,
        Some(ProgressStatus::InProgress),
        Some("screen interaction"),
        None,
    )?;
    let interaction_stage = if execution_plan.includes(PipelineStage::Interaction) {
        if !execution_plan.should_rerun(PipelineStage::Interaction) {
            if let Some(existing) = load_interaction_stage_output(screen_dir)? {
                existing
            } else {
                let interaction_artifacts = prepare_codex_interaction_artifacts(
                    repo_root,
                    screen_dir,
                    candidate,
                    artifacts,
                    &synthesis.hypotheses,
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
                let analysis =
                    merge_codex_interaction_results(artifacts.clusters.len(), &interaction_results);
                CodexInteractionStageOutput {
                    analysis,
                    records: interaction_results,
                }
            }
        } else {
            let interaction_artifacts = prepare_codex_interaction_artifacts(
                repo_root,
                screen_dir,
                candidate,
                artifacts,
                &synthesis.hypotheses,
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
            let analysis =
                merge_codex_interaction_results(artifacts.clusters.len(), &interaction_results);
            CodexInteractionStageOutput {
                analysis,
                records: interaction_results,
            }
        }
    } else if let Some(existing) = load_interaction_stage_output(screen_dir)? {
        existing
    } else {
        bail!(
            "interaction stage output is required before starting at {}",
            execution_plan.start_at.as_str()
        );
    };
    let interaction_dir = interaction_stage_dir(screen_dir);
    persist_screening_analysis(&interaction_dir, &interaction_stage.analysis)?;
    persist_interaction_stage_output(screen_dir, &interaction_stage)?;

    if execution_plan.stops_after(PipelineStage::Interaction) {
        return Ok(CodexScreeningPipelineOutput {
            screening: interaction_stage.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: Vec::new(),
            highest_completed_stage: PipelineStage::Interaction,
            pipeline_complete: false,
        });
    }

    update_candidate_progress(
        run_dir,
        candidate.candidate_index,
        Some(ProgressStatus::InProgress),
        Some("screen reachability"),
        None,
    )?;
    let reachability_stage = if execution_plan.includes(PipelineStage::Reachability) {
        if !execution_plan.should_rerun(PipelineStage::Reachability) {
            if let Some(existing) = load_reachability_stage_output(screen_dir)? {
                existing
            } else {
                let reachability_artifacts = prepare_codex_reachability_artifacts(
                    repo_root,
                    screen_dir,
                    candidate,
                    artifacts,
                    &interaction_stage.records,
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
                let analysis = merge_codex_reachability_results(
                    artifacts.clusters.len(),
                    &reachability_results,
                );
                CodexReachabilityStageOutput {
                    analysis,
                    records: reachability_results,
                }
            }
        } else {
            let reachability_artifacts = prepare_codex_reachability_artifacts(
                repo_root,
                screen_dir,
                candidate,
                artifacts,
                &interaction_stage.records,
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
            let analysis =
                merge_codex_reachability_results(artifacts.clusters.len(), &reachability_results);
            CodexReachabilityStageOutput {
                analysis,
                records: reachability_results,
            }
        }
    } else if let Some(existing) = load_reachability_stage_output(screen_dir)? {
        existing
    } else {
        bail!(
            "reachability stage output is required before starting at {}",
            execution_plan.start_at.as_str()
        );
    };
    let reachability_dir = reachability_stage_dir(screen_dir);
    persist_screening_analysis(&reachability_dir, &reachability_stage.analysis)?;
    persist_reachability_stage_output(screen_dir, &reachability_stage)?;

    let pipeline_complete = reachability_stage.analysis.suspicious_findings.is_empty();
    if execution_plan.stops_after(PipelineStage::Reachability) {
        return Ok(CodexScreeningPipelineOutput {
            screening: reachability_stage.analysis,
            hotspot_plan: artifacts.hotspot_plan.clone(),
            reachability_results: reachability_stage.records,
            highest_completed_stage: PipelineStage::Reachability,
            pipeline_complete,
        });
    }

    Ok(CodexScreeningPipelineOutput {
        screening: reachability_stage.analysis,
        hotspot_plan: artifacts.hotspot_plan.clone(),
        reachability_results: reachability_stage.records,
        highest_completed_stage: PipelineStage::Reachability,
        pipeline_complete: false,
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
    let mut focus_results = Vec::with_capacity(artifacts.clusters.len());
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
        focus_results.push(CodexInventoryFocusResult {
            cluster: cluster_artifact.cluster.clone(),
            analysis,
        });
    }

    Ok(merge_codex_inventory_results(
        artifacts.clusters.len(),
        focus_results,
    ))
}

/// Merges clustered Codex inventory results into a deduplicated hypothesis list.
fn merge_codex_inventory_results(
    cluster_count: usize,
    focus_results: Vec<CodexInventoryFocusResult>,
) -> CodexInventoryMergeOutput {
    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    let mut positive_clusters = Vec::new();

    for focus_result in &focus_results {
        let cluster = &focus_result.cluster;
        let analysis = &focus_result.analysis;
        let primary_finding = analysis
            .suspicious_findings
            .iter()
            .cloned()
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
        focus_results,
        hypotheses: deduped,
    }
}

/// Builds grouped synthesis inputs from per-focus inventory results.
fn build_synthesis_groups(focus_results: &[CodexInventoryFocusResult]) -> Vec<CodexSynthesisGroup> {
    let mut grouped = std::collections::BTreeMap::<String, Vec<CodexInventoryFocusResult>>::new();
    for focus_result in focus_results {
        grouped
            .entry(focus_result.cluster.category.clone())
            .or_default()
            .push(focus_result.clone());
    }

    let mut groups = grouped
        .into_iter()
        .map(|(category, mut entries)| {
            entries.sort_by_key(|entry| entry.cluster.cluster_index);
            let files = entries
                .iter()
                .flat_map(|entry| entry.cluster.files.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let function_hints = entries
                .iter()
                .flat_map(|entry| entry.cluster.function_hints.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(8)
                .collect::<Vec<_>>();
            let signal_terms = entries
                .iter()
                .flat_map(|entry| entry.cluster.signal_terms.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let score = entries
                .iter()
                .map(|entry| entry.cluster.score)
                .sum::<usize>();
            let cluster_index = entries
                .iter()
                .map(|entry| entry.cluster.cluster_index)
                .min()
                .unwrap_or(0);
            let cluster = HotspotCluster {
                cluster_index,
                title: synthesis_group_title(&category),
                rationale: synthesis_group_rationale(&category),
                category,
                files,
                function_hints,
                signal_terms,
                score,
            };

            CodexSynthesisGroup {
                cluster,
                focus_results: entries,
            }
        })
        .collect::<Vec<_>>();

    groups.sort_by(|left, right| {
        right
            .cluster
            .score
            .cmp(&left.cluster.score)
            .then_with(|| left.cluster.cluster_index.cmp(&right.cluster.cluster_index))
    });
    groups
}

/// Returns the human-readable title for one grouped synthesis category.
fn synthesis_group_title(category: &str) -> String {
    match category {
        "digest_length_verify" => "Digest-length verification synthesis".to_owned(),
        "digest_length_sign" => "Digest-length signing synthesis".to_owned(),
        "algorithm_binding" => "Algorithm-binding synthesis".to_owned(),
        "parser_validation" => "Parser-validation synthesis".to_owned(),
        "guarded_state_change" => "Guarded-state synthesis".to_owned(),
        _ => format!("Synthesis: {category}"),
    }
}

/// Returns the synthesis rationale for one grouped hotspot category.
fn synthesis_group_rationale(category: &str) -> String {
    match category {
        "digest_length_verify" => {
            "Synthesize whether several digest-length verification changes describe one stronger shared verification bug across wrappers, helpers, and signed-object paths.".to_owned()
        }
        "algorithm_binding" => {
            "Synthesize whether several algorithm-binding checks describe one shared certificate or signed-object verification flaw.".to_owned()
        }
        "parser_validation" => {
            "Synthesize whether parser and verifier guards combine into one trust-boundary bug rather than separate local cleanups.".to_owned()
        }
        _ => {
            "Synthesize the grouped focus units and keep only stronger shared security stories."
                .to_owned()
        }
    }
}

/// Selects the files and snapshots needed to synthesize one grouped category.
fn selected_files_for_synthesis_group(group: &CodexSynthesisGroup) -> Vec<String> {
    let mut selected = BTreeSet::new();
    for path in &group.cluster.files {
        selected.insert(path.clone());
    }
    for focus_result in &group.focus_results {
        for finding in &focus_result.analysis.suspicious_findings {
            for path in &finding.affected_files {
                selected.insert(path.clone());
            }
        }
    }
    selected.into_iter().collect()
}

/// Prepares one synthesis-review bundle for each grouped hotspot category.
fn prepare_codex_synthesis_artifacts(
    repo_root: &Path,
    screen_dir: &Path,
    candidate: &CommitCandidate,
    artifacts: &CodexInventoryPlanArtifacts,
    inventory: &CodexInventoryMergeOutput,
) -> Result<Vec<CodexSynthesisArtifacts>> {
    let synthesis_dir = synthesis_stage_dir(screen_dir);
    fs::create_dir_all(&synthesis_dir)
        .with_context(|| format!("failed to create {}", synthesis_dir.display()))?;

    let groups = build_synthesis_groups(&inventory.focus_results);
    let mut outputs = Vec::with_capacity(groups.len());
    for (group_index, group) in groups.iter().enumerate() {
        let group_dir = synthesis_dir.join(format!("group-{group_index:04}"));
        fs::create_dir_all(&group_dir)
            .with_context(|| format!("failed to create {}", group_dir.display()))?;
        let selected_files = selected_files_for_synthesis_group(group);
        let filtered_patch = filtered_patch_for_selection(&artifacts.full_patch, &selected_files);
        let evidence = persist_codex_evidence_bundle(
            &group_dir,
            repo_root,
            candidate,
            &selected_files,
            &filtered_patch,
            &artifacts.hotspot_plan,
        )?;
        let prompt_input = CodexSynthesisPromptInput {
            candidate_index: candidate.candidate_index,
            commit: build_codex_prompt_commit(candidate, evidence),
            hotspot_plan: artifacts.hotspot_plan.clone(),
            synthesis_group: group.clone(),
        };
        let prompt_input_path = absolute_artifact_path(&group_dir.join("prompt-input.json"))?;
        let prompt = prompt::render_codex_synthesis_prompt(Path::new(&prompt_input_path));
        persist_pass_artifacts(&group_dir, &prompt_input, &prompt)?;
        outputs.push(CodexSynthesisArtifacts {
            group: group.clone(),
            pass_dir: group_dir,
            prompt,
        });
    }

    Ok(outputs)
}

/// Runs one synthesis review for each grouped hotspot category.
fn run_codex_synthesis(
    provider: &dyn crate::provider::AgentProvider,
    working_dir: &Path,
    artifacts: &[CodexSynthesisArtifacts],
    run_dir: &Path,
    schema: &str,
    candidate_index: usize,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    verbose: bool,
) -> Result<CodexSynthesisMergeOutput> {
    let mut group_results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        update_candidate_progress(
            run_dir,
            candidate_index,
            Some(ProgressStatus::InProgress),
            Some(&format!(
                "screen synthesis category {}",
                artifact.group.cluster.category
            )),
            None,
        )?;
        log_step(
            verbose,
            "synthesis",
            format!("synthesizing category {}", artifact.group.cluster.category),
        );
        let analysis = provider.screen_candidate(ProviderRequest {
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
        persist_screening_analysis(&artifact.pass_dir, &analysis)?;
        group_results.push((artifact.group.clone(), analysis));
    }

    Ok(merge_codex_synthesis_results(group_results))
}

/// Merges category-level synthesis outputs into deduplicated hypotheses.
fn merge_codex_synthesis_results(
    group_results: Vec<(CodexSynthesisGroup, ScreeningAnalysis)>,
) -> CodexSynthesisMergeOutput {
    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    let mut positive_groups = Vec::new();

    for (group, analysis) in group_results {
        let mut findings = analysis.suspicious_findings.clone();
        if findings.is_empty() {
            findings = group
                .focus_results
                .iter()
                .flat_map(|focus_result| focus_result.analysis.suspicious_findings.clone())
                .collect();
        }

        if findings.is_empty() {
            continue;
        }

        positive_groups.push(group.cluster.title.clone());
        for finding in findings {
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
                    cluster: group.cluster.clone(),
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

    let candidate_summary = if positive_groups.is_empty() {
        "Synthesized grouped hotspot categories. No stronger shared theory emerged beyond the isolated focus results.".to_owned()
    } else {
        format!(
            "Synthesized grouped hotspot categories. Stronger shared theories came from: {}.",
            positive_groups.join("; ")
        )
    };

    CodexSynthesisMergeOutput {
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

        if let Some(finding) = effective_reachability_finding(result) {
            supported.push((
                result.cluster.category.clone(),
                result.interaction_analysis.verdict,
                result.analysis.verdict,
                result.analysis.assessment,
                result.analysis.surface,
                finding,
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
        || should_preserve_digest_length_verify_for_adjudication(result)
}

/// Returns the best finding available after reachability review.
fn effective_reachability_finding(result: &CodexReachabilityRecord) -> Option<SuspiciousFinding> {
    result
        .analysis
        .refined_finding
        .clone()
        .or_else(|| result.interaction_analysis.refined_finding.clone())
}

/// Returns the file evidence associated with one reachability-reviewed hypothesis.
fn reachability_result_files(result: &CodexReachabilityRecord) -> BTreeSet<&str> {
    let mut files = BTreeSet::new();
    for path in &result.cluster.files {
        files.insert(path.as_str());
    }
    if let Some(finding) = &result.interaction_analysis.refined_finding {
        for path in &finding.affected_files {
            files.insert(path.as_str());
        }
    }
    if let Some(finding) = &result.analysis.refined_finding {
        for path in &finding.affected_files {
            files.insert(path.as_str());
        }
    }
    files
}

/// Returns whether a rejected digest-length verification theory still deserves adjudication.
fn should_preserve_digest_length_verify_for_adjudication(result: &CodexReachabilityRecord) -> bool {
    if result.cluster.category != "digest_length_verify" {
        return false;
    }

    if !matches!(
        result.analysis.surface,
        ReachabilitySurface::LocalApi | ReachabilitySurface::Unknown
    ) {
        return false;
    }

    if !matches!(
        result.analysis.assessment,
        ReachabilityAssessment::LocalApiOnly
            | ReachabilityAssessment::InteractionDependent
            | ReachabilityAssessment::Rejected
    ) {
        return false;
    }

    let files = reachability_result_files(result);
    files.contains("wolfcrypt/src/ecc.c")
        && files.contains("src/pk_ec.c")
        && files.contains("wolfssl/wolfcrypt/hash.h")
        && (files.contains("src/internal.c") || files.contains("wolfcrypt/src/pkcs7.c"))
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

/// Selects the reachability survivors that should enter independent verification.
fn select_verification_candidates(
    reachability_results: &[CodexReachabilityRecord],
) -> Result<Vec<CodexAdjudicationCandidate>> {
    Ok(reachability_results
        .iter()
        .filter_map(|result| {
            if !should_keep_reachability_result(result) {
                return None;
            }
            let refined_finding = effective_reachability_finding(result)?;

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
        .collect::<Vec<_>>())
}

/// Selects the files and snapshots needed to verify one reachability survivor.
fn selected_files_for_verification_result(result: &CodexReachabilityRecord) -> Vec<String> {
    let mut selected = BTreeSet::new();
    for path in &result.cluster.files {
        selected.insert(path.clone());
    }
    if let Some(finding) = effective_reachability_finding(result) {
        for path in finding.affected_files {
            selected.insert(path);
        }
    }
    selected.into_iter().collect()
}

/// Prepares one independent verification bundle for each reachability survivor.
fn prepare_codex_verify_artifacts(
    repo_root: &Path,
    verify_dir: &Path,
    candidate: &CommitCandidate,
    hotspot_plan: &HotspotPlan,
    reachability_results: &[CodexReachabilityRecord],
) -> Result<Option<Vec<CodexVerifyArtifacts>>> {
    let finalists = select_verification_candidates(reachability_results)?;
    if finalists.is_empty() {
        return Ok(None);
    }

    let full_patch = git::load_full_patch(repo_root, &candidate.commit.id)?;
    let mut artifacts = Vec::with_capacity(finalists.len());

    for finalist in finalists {
        let Some(result) = reachability_results
            .iter()
            .find(|result| result.hypothesis_index == finalist.hypothesis_index)
        else {
            bail!(
                "missing reachability result for verification finalist {}",
                finalist.hypothesis_index
            );
        };
        let hypothesis_dir =
            verify_dir.join(format!("hypothesis-{:04}", finalist.hypothesis_index));
        fs::create_dir_all(&hypothesis_dir)
            .with_context(|| format!("failed to create {}", hypothesis_dir.display()))?;
        let selected_files = selected_files_for_verification_result(result);
        let filtered_patch = filtered_patch_for_selection(&full_patch, &selected_files);
        let evidence = persist_codex_evidence_bundle(
            &hypothesis_dir,
            repo_root,
            candidate,
            &selected_files,
            &filtered_patch,
            hotspot_plan,
        )?;
        let prompt_input = CodexVerifyPromptInput {
            candidate_index: candidate.candidate_index,
            commit: build_codex_prompt_commit(candidate, evidence),
            commit_message: candidate.commit.summary.clone(),
            hotspot_plan: hotspot_plan.clone(),
            finalist: finalist.clone(),
        };
        let prompt_input_path = absolute_artifact_path(&hypothesis_dir.join("prompt-input.json"))?;
        let prompt = prompt::render_codex_verify_prompt(Path::new(&prompt_input_path));
        persist_pass_artifacts(&hypothesis_dir, &prompt_input, &prompt)?;
        artifacts.push(CodexVerifyArtifacts {
            hypothesis_index: finalist.hypothesis_index,
            finalist,
            pass_dir: hypothesis_dir,
            prompt,
        });
    }

    Ok(Some(artifacts))
}

/// Runs one independent verification pass for each verification finalist.
fn run_codex_verification(
    provider: &dyn crate::provider::AgentProvider,
    working_dir: &Path,
    artifacts: &[CodexVerifyArtifacts],
    run_dir: &Path,
    schema: &str,
    candidate_index: usize,
    model: Option<&str>,
    effort: Option<crate::cli::ReasoningEffort>,
    rerun_stage: bool,
    verbose: bool,
) -> Result<Vec<CodexVerificationRecord>> {
    let mut results = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let analysis_path = artifact.pass_dir.join("analysis.json");
        let analysis = if !rerun_stage && analysis_path.exists() {
            load_json_file(&analysis_path)?
        } else {
            update_candidate_progress(
                run_dir,
                candidate_index,
                Some(ProgressStatus::InProgress),
                Some(&format!(
                    "verify hypothesis {:04}",
                    artifact.hypothesis_index
                )),
                None,
            )?;
            log_step(
                verbose,
                "verify",
                format!(
                    "verifying hypothesis {:04} from cluster {}",
                    artifact.hypothesis_index, artifact.finalist.cluster_title
                ),
            );
            let analysis = provider.verify_candidate(ProviderRequest {
                working_dir,
                prompt: &artifact.prompt,
                schema,
                pass_dir: &artifact.pass_dir,
                candidate_index,
                phase: AnalysisPhase::Verify,
                model,
                effort,
                verbose,
            })?;
            persist_verification_analysis(&artifact.pass_dir, &analysis)?;
            analysis
        };
        results.push(CodexVerificationRecord {
            hypothesis_index: artifact.hypothesis_index,
            finalist: artifact.finalist.clone(),
            analysis,
        });
    }

    Ok(results)
}

/// Merges independent verification passes into one final candidate verification result.
fn merge_codex_verification_results(records: &[CodexVerificationRecord]) -> VerificationAnalysis {
    let confirmed_findings = records
        .iter()
        .flat_map(|record| record.analysis.confirmed_findings.iter().cloned())
        .collect::<Vec<_>>();
    let confirmed_hypotheses = records
        .iter()
        .filter(|record| !record.analysis.confirmed_findings.is_empty())
        .map(|record| format!("{:04}", record.hypothesis_index))
        .collect::<Vec<_>>();
    let inconclusive_count = records
        .iter()
        .filter(|record| record.analysis.verdict == VerificationVerdict::Inconclusive)
        .count();
    let rejected_count = records
        .iter()
        .filter(|record| record.analysis.verdict == VerificationVerdict::Rejected)
        .count();

    let verdict = if !confirmed_findings.is_empty() {
        VerificationVerdict::Confirmed
    } else if inconclusive_count > 0 {
        VerificationVerdict::Inconclusive
    } else {
        VerificationVerdict::Rejected
    };

    let verification_summary = if confirmed_findings.is_empty() {
        format!(
            "Independently reviewed {} finalist hypothesis(es). No finalist was confirmed; {} remained inconclusive and {} were rejected.",
            records.len(),
            inconclusive_count,
            rejected_count
        )
    } else {
        format!(
            "Independently reviewed {} finalist hypothesis(es). Confirmed {} finding(s) from hypothesis {}. {} additional hypothesis(es) were inconclusive and {} were rejected.",
            records.len(),
            confirmed_findings.len(),
            confirmed_hypotheses.join(", "),
            inconclusive_count,
            rejected_count
        )
    };

    VerificationAnalysis {
        verification_summary,
        verdict,
        confirmed_findings,
    }
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
        if progress
            .pending
            .iter()
            .all(|candidate| candidate.candidate_index != candidate_index)
            && let Some(position) = progress
                .complete
                .iter()
                .position(|candidate| candidate.candidate_index == candidate_index)
        {
            let completed = progress.complete.remove(position);
            progress.pending.push(ProgressPendingCandidate {
                candidate_index: completed.candidate_index,
                commit_id: completed.commit_id,
                short_id: completed.short_id,
                status: ProgressStatus::Pending,
                active_stage: None,
            });
            progress
                .pending
                .sort_by_key(|candidate| candidate.candidate_index);
        }

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
fn prepare_candidate_work_dir(wip_dir: &Path, completed_dir: &Path, verbose: bool) -> Result<()> {
    if wip_dir.exists() {
        log_step(
            verbose,
            "wip",
            format!(
                "reusing existing work-in-progress candidate {}",
                wip_dir.display()
            ),
        );
        return Ok(());
    }

    if completed_dir.exists() {
        log_step(
            verbose,
            "wip",
            format!(
                "moving completed candidate back into work-in-progress {} -> {}",
                completed_dir.display(),
                wip_dir.display()
            ),
        );
        if let Some(parent) = wip_dir.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        return fs::rename(completed_dir, wip_dir).with_context(|| {
            format!(
                "failed to move {} to {}",
                completed_dir.display(),
                wip_dir.display()
            )
        });
    }

    fs::create_dir_all(wip_dir).with_context(|| format!("failed to create {}", wip_dir.display()))
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

/// Returns the persisted candidate-stage state path for one candidate.
fn candidate_stage_state_path(candidate_dir: &Path) -> PathBuf {
    candidate_dir.join("stage-state.json")
}

/// Returns the pass-specific artifact directory for one candidate.
fn pass_dir(candidate_dir: &Path, phase: AnalysisPhase) -> PathBuf {
    candidate_dir.join(phase.as_str())
}

/// Removes one stage directory and any downstream dependent artifacts before rerun.
fn clear_stage_artifacts(
    candidate_dir: &Path,
    rerun_from: PipelineStage,
    verbose: bool,
) -> Result<()> {
    let screen_dir = pass_dir(candidate_dir, AnalysisPhase::Screen);
    let verify_dir = pass_dir(candidate_dir, AnalysisPhase::Verify);
    let stage_dirs = [
        (PipelineStage::Inventory, inventory_stage_dir(&screen_dir)),
        (PipelineStage::Synthesis, synthesis_stage_dir(&screen_dir)),
        (
            PipelineStage::Interaction,
            interaction_stage_dir(&screen_dir),
        ),
        (
            PipelineStage::Reachability,
            reachability_stage_dir(&screen_dir),
        ),
    ];

    for (stage, path) in stage_dirs {
        if stage.order() < rerun_from.order() || !path.exists() {
            continue;
        }
        log_step(
            verbose,
            "rerun",
            format!(
                "clearing {stage_name} artifacts at {}",
                path.display(),
                stage_name = stage.as_str()
            ),
        );
        fs::remove_dir_all(&path)
            .with_context(|| format!("failed to remove {}", path.display()))?;
    }

    let screen_analysis = screen_dir.join("analysis.json");
    if rerun_from.order() <= PipelineStage::Reachability.order() && screen_analysis.exists() {
        fs::remove_file(&screen_analysis)
            .with_context(|| format!("failed to remove {}", screen_analysis.display()))?;
    }
    if rerun_from.order() <= PipelineStage::Verify.order() && verify_dir.exists() {
        log_step(
            verbose,
            "rerun",
            format!("clearing verify artifacts at {}", verify_dir.display()),
        );
        fs::remove_dir_all(&verify_dir)
            .with_context(|| format!("failed to remove {}", verify_dir.display()))?;
    }

    Ok(())
}

/// Parses one persisted pipeline-stage label.
fn parse_pipeline_stage(value: &str) -> Result<PipelineStage> {
    match value {
        "inventory" => Ok(PipelineStage::Inventory),
        "synthesis" => Ok(PipelineStage::Synthesis),
        "interaction" => Ok(PipelineStage::Interaction),
        "reachability" => Ok(PipelineStage::Reachability),
        "verify" => Ok(PipelineStage::Verify),
        _ => bail!("unknown pipeline stage `{value}`"),
    }
}

/// Infers candidate stage state from the available artifact tree.
fn infer_candidate_stage_state(candidate_dir: &Path) -> Result<Option<CandidateStageState>> {
    let screen_dir = pass_dir(candidate_dir, AnalysisPhase::Screen);
    let verify_dir = pass_dir(candidate_dir, AnalysisPhase::Verify);
    if verify_dir.join("analysis.json").exists() {
        return Ok(Some(CandidateStageState {
            highest_completed_stage: PipelineStage::Verify.as_str().to_owned(),
            pipeline_complete: true,
        }));
    }
    if reachability_results_path(&screen_dir).exists()
        || reachability_stage_dir(&screen_dir)
            .join("analysis.json")
            .exists()
    {
        return Ok(Some(CandidateStageState {
            highest_completed_stage: PipelineStage::Reachability.as_str().to_owned(),
            pipeline_complete: true,
        }));
    }
    if interaction_results_path(&screen_dir).exists()
        || interaction_stage_dir(&screen_dir)
            .join("analysis.json")
            .exists()
    {
        return Ok(Some(CandidateStageState {
            highest_completed_stage: PipelineStage::Interaction.as_str().to_owned(),
            pipeline_complete: false,
        }));
    }
    if synthesis_results_path(&screen_dir).exists()
        || synthesis_stage_dir(&screen_dir)
            .join("analysis.json")
            .exists()
    {
        return Ok(Some(CandidateStageState {
            highest_completed_stage: PipelineStage::Synthesis.as_str().to_owned(),
            pipeline_complete: false,
        }));
    }
    if inventory_results_path(&screen_dir).exists()
        || inventory_stage_dir(&screen_dir)
            .join("analysis.json")
            .exists()
    {
        return Ok(Some(CandidateStageState {
            highest_completed_stage: PipelineStage::Inventory.as_str().to_owned(),
            pipeline_complete: false,
        }));
    }

    Ok(None)
}

/// Returns whether an existing candidate already satisfies the requested staged execution.
fn candidate_request_satisfied(
    candidate_dir: &Path,
    execution_plan: StageExecutionPlan,
) -> Result<bool> {
    let Some(state) = load_candidate_stage_state(candidate_dir)? else {
        return Ok(false);
    };
    let highest_completed_stage = parse_pipeline_stage(&state.highest_completed_stage)?;

    if execution_plan
        .rerun_from
        .map(|rerun_from| rerun_from.order() <= highest_completed_stage.order())
        .unwrap_or(false)
    {
        return Ok(false);
    }

    if state.pipeline_complete {
        return Ok(true);
    }

    Ok(highest_completed_stage.order() >= execution_plan.stop_after.order())
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
        CodexReachabilityRecord, CodexVerificationRecord, absolute_artifact_path,
        bundle_snapshot_path, ensure_manifest, initialize_progress_state, load_progress_state,
        load_saved_candidate_outcome, manifests_match, merge_codex_inventory_results,
        merge_codex_verification_results, persist_candidate_outcome, select_inventory_focuses,
        select_verification_candidates, should_keep_reachability_result,
        should_review_reachability, validate_args,
    };
    use crate::cli::{AnalyzeArgs, PipelineStage, ProviderKind};
    use crate::hotspot::HotspotCluster;
    use crate::types::{
        CandidateOutcome, CommitCandidate, CommitRecord, InteractionAnalysis, InteractionKind,
        InteractionVerdict, ProgressResult, ProgressStatus, ReachabilityAnalysis,
        ReachabilityAssessment, ReachabilitySurface, ReachabilityVerdict, RunManifest,
        ScreeningAnalysis, SuspiciousFinding, VerificationAnalysis, VerificationVerdict,
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
            start_at_stage: None,
            inventory_focuses: Vec::new(),
            rerun_stages: Vec::new(),
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
            start_at_stage: None,
            inventory_focuses: Vec::new(),
            rerun_stages: Vec::new(),
        };

        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn rejects_inventory_focuses_for_claude() {
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
            stop_after_stage: None,
            start_at_stage: None,
            inventory_focuses: vec![1, 4],
            rerun_stages: Vec::new(),
        };

        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn rejects_start_after_stop_stage() {
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
            min_confidence: 0.5,
            out: PathBuf::from("out"),
            verbose: false,
            dry_run: true,
            stop_after_stage: Some(PipelineStage::Interaction),
            start_at_stage: Some(PipelineStage::Reachability),
            inventory_focuses: Vec::new(),
            rerun_stages: Vec::new(),
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
    fn manifest_matching_ignores_execution_controls() {
        let mut existing = sample_manifest("codex");
        existing.stop_after_stage = Some("inventory".into());
        existing.start_at_stage = Some("inventory".into());
        existing.rerun_stages = vec!["inventory".into()];

        let mut current = sample_manifest("codex");
        current.stop_after_stage = Some("verify".into());
        current.start_at_stage = Some("interaction".into());
        current.rerun_stages = vec!["interaction".into()];

        assert!(manifests_match(&existing, &current));
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
    fn rejected_digest_length_verify_survives_shared_verifier_invariant() {
        let record = sample_reachability_record_with_cluster(
            8,
            sample_cluster_with_files(
                "digest_length_verify",
                &[
                    "src/internal.c",
                    "src/pk_ec.c",
                    "wolfcrypt/src/ecc.c",
                    "wolfcrypt/src/pkcs7.c",
                ],
            ),
            InteractionAnalysis {
                hypothesis_summary: "shared digest invariant".into(),
                verdict: InteractionVerdict::Plausible,
                interaction_kind: InteractionKind::SharedVerificationFlow,
                preconditions: vec!["mixed verify helpers".into()],
                preserve_for_reachability: true,
                preserve_for_adjudication: false,
                refined_finding: Some(SuspiciousFinding {
                    affected_files: vec![
                        "src/pk_ec.c".into(),
                        "wolfcrypt/src/ecc.c".into(),
                        "wolfssl/wolfcrypt/hash.h".into(),
                    ],
                    ..sample_finding("ecdsa digest invariant", 0.84, "src/pk_ec.c")
                }),
            },
            ReachabilityAnalysis {
                hypothesis_summary: "looks like local api".into(),
                verdict: ReachabilityVerdict::Rejected,
                surface: ReachabilitySurface::LocalApi,
                assessment: ReachabilityAssessment::Rejected,
                preconditions: vec!["public verify api".into()],
                keep_for_adjudication: false,
                refined_finding: None,
            },
        );

        assert!(should_keep_reachability_result(&record));
    }

    #[test]
    fn verification_candidates_fall_back_to_interaction_refined_finding() {
        let finalists = select_verification_candidates(&[sample_reachability_record_with_cluster(
            9,
            sample_cluster_with_files(
                "digest_length_verify",
                &[
                    "src/internal.c",
                    "src/pk_ec.c",
                    "wolfcrypt/src/ecc.c",
                    "wolfcrypt/src/pkcs7.c",
                ],
            ),
            InteractionAnalysis {
                hypothesis_summary: "shared digest invariant".into(),
                verdict: InteractionVerdict::Strong,
                interaction_kind: InteractionKind::FeatureInteraction,
                preconditions: vec!["eddsa or ml-dsa enabled".into()],
                preserve_for_reachability: true,
                preserve_for_adjudication: false,
                refined_finding: Some(SuspiciousFinding {
                    affected_files: vec![
                        "src/pk_ec.c".into(),
                        "wolfcrypt/src/ecc.c".into(),
                        "wolfssl/wolfcrypt/hash.h".into(),
                    ],
                    ..sample_finding(
                        "ecdsa verification accepted undersized digest",
                        0.88,
                        "src/pk_ec.c",
                    )
                }),
            },
            ReachabilityAnalysis {
                hypothesis_summary: "not proven as remote".into(),
                verdict: ReachabilityVerdict::Rejected,
                surface: ReachabilitySurface::LocalApi,
                assessment: ReachabilityAssessment::LocalApiOnly,
                preconditions: vec!["direct wrapper path".into()],
                keep_for_adjudication: false,
                refined_finding: None,
            },
        )])
        .expect("selection should work");

        assert_eq!(finalists.len(), 1);
        assert_eq!(finalists[0].hypothesis_index, 9);
        assert_eq!(
            finalists[0].refined_finding.title,
            "ecdsa verification accepted undersized digest"
        );
    }

    #[test]
    fn verification_candidates_keep_multiple_theories_without_ranking() {
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

        let finalists = select_verification_candidates(&[local_api, interaction])
            .expect("selection should work");

        assert_eq!(finalists.len(), 2);
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
    fn merged_verification_results_keep_multiple_confirmed_findings() {
        let merged = merge_codex_verification_results(&[
            sample_verification_record(
                1,
                "asn binding",
                VerificationAnalysis {
                    verification_summary: "confirmed asn".into(),
                    verdict: VerificationVerdict::Confirmed,
                    confirmed_findings: vec![sample_finding(
                        "asn binding accepted mismatched oid",
                        0.94,
                        "wolfcrypt/src/asn.c",
                    )],
                },
            ),
            sample_verification_record(
                2,
                "ecdsa digest",
                VerificationAnalysis {
                    verification_summary: "confirmed digest".into(),
                    verdict: VerificationVerdict::Confirmed,
                    confirmed_findings: vec![sample_finding(
                        "ecdsa verify accepted undersized digest",
                        0.88,
                        "src/pk_ec.c",
                    )],
                },
            ),
        ]);

        assert_eq!(merged.verdict, VerificationVerdict::Confirmed);
        assert_eq!(merged.confirmed_findings.len(), 2);
        assert!(
            merged
                .verification_summary
                .contains("Confirmed 2 finding(s) from hypothesis 0001, 0002")
        );
    }

    #[test]
    fn inventory_merge_keeps_only_primary_finding_per_focus() {
        let cluster = sample_cluster("digest_length_verify");
        let merged = merge_codex_inventory_results(
            1,
            vec![super::CodexInventoryFocusResult {
                cluster,
                analysis: ScreeningAnalysis {
                    candidate_summary: "summary".into(),
                    suspicious_findings: vec![
                        sample_finding("lower confidence", 0.61, "src/a.rs"),
                        sample_finding("higher confidence", 0.88, "src/a.rs"),
                    ],
                },
            }],
        );

        assert_eq!(merged.hypotheses.len(), 1);
        assert_eq!(merged.hypotheses[0].finding.title, "higher confidence");
    }

    #[test]
    fn select_inventory_focuses_keeps_requested_indexes_and_order() {
        let cluster0 = sample_cluster("digest_length_verify");
        let mut cluster4 = sample_cluster("digest_length_sign");
        cluster4.cluster_index = 4;
        let mut cluster9 = sample_cluster("pkcs7_verify");
        cluster9.cluster_index = 9;

        let selected = select_inventory_focuses(&[cluster0, cluster4, cluster9], &[9, 0])
            .expect("focus selection should work");

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].cluster_index, 9);
        assert_eq!(selected[1].cluster_index, 0);
    }

    #[test]
    fn select_inventory_focuses_rejects_missing_indexes() {
        let cluster0 = sample_cluster("digest_length_verify");
        let error =
            select_inventory_focuses(&[cluster0], &[3]).expect_err("missing focus should fail");

        assert!(
            error
                .to_string()
                .contains("--inventory-focuses references missing hotspot focus index 3")
        );
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
            start_at_stage: None,
            inventory_focuses: Vec::new(),
            rerun_stages: Vec::new(),
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
        sample_cluster_with_files(category, &["src/a.rs"])
    }

    fn sample_cluster_with_files(category: &str, files: &[&str]) -> HotspotCluster {
        HotspotCluster {
            cluster_index: 0,
            title: format!("{category} cluster"),
            rationale: "rationale".into(),
            category: category.into(),
            files: files.iter().map(|path| (*path).into()).collect(),
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
        sample_reachability_record_with_cluster(
            hypothesis_index,
            sample_cluster(cluster_category),
            interaction_analysis,
            analysis,
        )
    }

    fn sample_reachability_record_with_cluster(
        hypothesis_index: usize,
        cluster: HotspotCluster,
        interaction_analysis: InteractionAnalysis,
        analysis: ReachabilityAnalysis,
    ) -> CodexReachabilityRecord {
        CodexReachabilityRecord {
            hypothesis_index,
            cluster,
            interaction_analysis,
            analysis,
        }
    }

    fn sample_verification_record(
        hypothesis_index: usize,
        title: &str,
        analysis: VerificationAnalysis,
    ) -> CodexVerificationRecord {
        CodexVerificationRecord {
            hypothesis_index,
            finalist: super::CodexAdjudicationCandidate {
                hypothesis_index,
                cluster_title: title.into(),
                cluster_category: "category".into(),
                interaction_summary: "interaction".into(),
                interaction_verdict: InteractionVerdict::Plausible,
                interaction_kind: InteractionKind::DirectPath,
                reachability_summary: "reachability".into(),
                reachability_verdict: ReachabilityVerdict::Weak,
                reachability_assessment: ReachabilityAssessment::InteractionDependent,
                surface: ReachabilitySurface::Unknown,
                preconditions: vec![],
                refined_finding: sample_finding(title, 0.8, "src/a.rs"),
            },
            analysis,
        }
    }
}
