//! Application orchestration for the VCamper CLI.
//! Ownership: client-only

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

use crate::cli::{AnalyzeArgs, Cli, Commands};
use crate::git;
use crate::prompt;
use crate::provider::{
    AnalysisPhase, ProviderRequest, build_provider, screening_schema, verification_schema,
};
use crate::report;
use crate::types::{
    CandidateOutcome, CommitCandidate, ProgressCompleteCandidate, ProgressPendingCandidate,
    ProgressResult, ProgressState, ProgressStatus, RunManifest, ScreeningAnalysis,
    VerificationAnalysis,
};

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
            None,
        )?;
        prepare_wip_candidate_dir(&wip_dir, verbose)?;
        persist_candidate_input(&wip_dir, candidate)?;

        let screen_dir = pass_dir(&wip_dir, AnalysisPhase::Screen);
        fs::create_dir_all(&screen_dir)
            .with_context(|| format!("failed to create {}", screen_dir.display()))?;
        let screen_prompt = prompt::render_screen_prompt(&manifest.repo_root, candidate)?;
        persist_pass_artifacts(
            &screen_dir,
            &prompt::build_prompt_input(candidate),
            &screen_prompt,
        )?;

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
            persist_screening_analysis(&screen_dir, &outcome.screening)?;
            persist_candidate_outcome(&wip_dir, &outcome)?;
            promote_completed_candidate(&wip_dir, &completed_dir, verbose)?;
            update_candidate_progress(
                &run_dir,
                candidate.candidate_index,
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
        log_step(
            verbose,
            "candidate",
            format!(
                "invoking {} screen pass for candidate {:04}",
                manifest.provider, candidate.candidate_index
            ),
        );
        let screening = provider.screen_candidate(ProviderRequest {
            repo_root: &repo_root,
            prompt: &screen_prompt,
            schema: &screen_schema,
            pass_dir: &screen_dir,
            candidate_index: candidate.candidate_index,
            phase: AnalysisPhase::Screen,
            model: args.model.as_deref(),
            effort: screen_effort,
            verbose,
        })?;
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

        let verification = if screening.suspicious_findings.is_empty() {
            None
        } else {
            let verify_dir = pass_dir(&wip_dir, AnalysisPhase::Verify);
            fs::create_dir_all(&verify_dir)
                .with_context(|| format!("failed to create {}", verify_dir.display()))?;
            let verify_prompt =
                prompt::render_verify_prompt(&manifest.repo_root, candidate, &screening)?;
            persist_pass_artifacts(
                &verify_dir,
                &prompt::build_verification_prompt_input(candidate, &screening),
                &verify_prompt,
            )?;
            progress.start_phase(
                candidate.candidate_index,
                AnalysisPhase::Verify,
                manifest.provider.as_str(),
                short_hash(&candidate.commit.id),
            );
            log_step(
                verbose,
                "candidate",
                format!(
                    "invoking {} verify pass for candidate {:04}",
                    manifest.provider, candidate.candidate_index
                ),
            );
            let verification = provider.verify_candidate(ProviderRequest {
                repo_root: &repo_root,
                prompt: &verify_prompt,
                schema: &verify_schema,
                pass_dir: &verify_dir,
                candidate_index: candidate.candidate_index,
                phase: AnalysisPhase::Verify,
                model: args.model.as_deref(),
                effort: verify_effort,
                verbose,
            })?;
            log_step(
                verbose,
                "candidate",
                format!(
                    "candidate {:04} verify pass verdict={} confirmed {} finding(s)",
                    candidate.candidate_index,
                    verification.verdict.as_str(),
                    verification.confirmed_findings.len()
                ),
            );
            persist_verification_analysis(&verify_dir, &verification)?;
            Some(verification)
        };

        let outcome = CandidateOutcome {
            screening,
            verification,
        };
        persist_candidate_outcome(&wip_dir, &outcome)?;
        let keep_candidate_dir = should_retain_candidate_artifacts();
        finalize_candidate_dir(&wip_dir, &completed_dir, keep_candidate_dir, verbose)?;
        update_candidate_progress(
            &run_dir,
            candidate.candidate_index,
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
    } else if let Some(status) = pending_status {
        let candidate = progress
            .pending
            .iter_mut()
            .find(|candidate| candidate.candidate_index == candidate_index)
            .with_context(|| format!("missing candidate {candidate_index:04} in progress.json"))?;
        candidate.status = status;
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
        ensure_manifest, initialize_progress_state, load_progress_state,
        load_saved_candidate_outcome, persist_candidate_outcome, validate_args,
    };
    use crate::cli::{AnalyzeArgs, ProviderKind};
    use crate::types::{
        CandidateOutcome, CommitCandidate, CommitRecord, ProgressResult, ProgressStatus,
        RunManifest, ScreeningAnalysis,
    };
    use std::fs;
    use std::path::PathBuf;
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
}
