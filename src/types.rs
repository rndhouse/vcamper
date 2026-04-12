//! Data models for repository analysis and provider exchange.
//! Ownership: client-only

use serde::{Deserialize, Serialize};

/// Summary of one commit in the analyzed range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitRecord {
    /// Full commit id.
    pub(crate) id: String,
    /// Short commit id for compact display.
    pub(crate) short_id: String,
    /// Parent commit ids in the local repository.
    pub(crate) parent_ids: Vec<String>,
    /// Author name recorded by git.
    pub(crate) author_name: String,
    /// Author email recorded by git.
    pub(crate) author_email: String,
    /// Author timestamp in ISO-8601 form.
    pub(crate) authored_at: String,
    /// Commit summary captured for local artifacts and later passes.
    pub(crate) summary: String,
    /// Changed file paths reported by git.
    pub(crate) files_changed: Vec<String>,
    /// Aggregate line-change counts for each changed file.
    pub(crate) file_stats: Vec<FileStat>,
    /// Unified patch text, truncated when it exceeds the configured byte budget.
    pub(crate) patch: String,
    /// Whether the patch text was truncated before analysis.
    pub(crate) patch_truncated: bool,
}

/// Aggregate line-change counts for one file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FileStat {
    /// Repository-relative file path.
    pub(crate) path: String,
    /// Number of added lines when git reports a count.
    pub(crate) additions: Option<u64>,
    /// Number of deleted lines when git reports a count.
    pub(crate) deletions: Option<u64>,
}

/// One commit candidate analyzed independently by the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CommitCandidate {
    /// Zero-based candidate index within the run.
    pub(crate) candidate_index: usize,
    /// The full commit record for this candidate.
    pub(crate) commit: CommitRecord,
}

/// First-pass screening response for one analyzed commit candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScreeningAnalysis {
    /// Short provider summary for the analyzed commit.
    pub(crate) candidate_summary: String,
    /// Security-relevant findings attributed to this commit.
    pub(crate) suspicious_findings: Vec<SuspiciousFinding>,
}

/// Second-pass verification response for one analyzed commit candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VerificationAnalysis {
    /// Short provider summary for the verification pass.
    pub(crate) verification_summary: String,
    /// Final verification verdict for the candidate.
    pub(crate) verdict: VerificationVerdict,
    /// Security-relevant findings confirmed by the verifier.
    pub(crate) confirmed_findings: Vec<SuspiciousFinding>,
}

/// Reachability review for one screened hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReachabilityAnalysis {
    /// Short provider summary for the reviewed hypothesis.
    pub(crate) hypothesis_summary: String,
    /// Reachability verdict for the reviewed hypothesis.
    pub(crate) verdict: ReachabilityVerdict,
    /// Strongest supported attack surface for the hypothesis.
    pub(crate) surface: ReachabilitySurface,
    /// Preconditions that must hold for the hypothesis to matter.
    pub(crate) preconditions: Vec<String>,
    /// Refined finding when the hypothesis remains security-relevant.
    pub(crate) refined_finding: Option<SuspiciousFinding>,
}

/// Reachability verdict for one screened hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReachabilityVerdict {
    /// The reviewed hypothesis has a concrete attack path in the supplied code.
    Supported,
    /// The reviewed hypothesis still looks security-relevant, but exploitability remains weak.
    Weak,
    /// The reviewed hypothesis does not hold up as a security issue.
    Rejected,
}

/// Strongest supported attack surface for one reviewed hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReachabilitySurface {
    /// A remote or network-originating attacker can plausibly reach the changed path.
    Remote,
    /// A nearby peer or delegated protocol participant can plausibly reach the changed path.
    Adjacent,
    /// The issue depends on an application exposing a public local API to attacker-controlled data.
    LocalApi,
    /// The issue only affects internal-only callers or non-attacker-controlled code paths.
    InternalOnly,
    /// The supplied evidence does not support a stable exposure classification.
    Unknown,
}

impl ReachabilitySurface {
    /// Returns the lowercase surface label used in logs and summaries.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::Adjacent => "adjacent",
            Self::LocalApi => "local_api",
            Self::InternalOnly => "internal_only",
            Self::Unknown => "unknown",
        }
    }
}

/// Final verifier verdict for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationVerdict {
    /// The verifier confirmed one or more security-relevant findings.
    Confirmed,
    /// The verifier rejected the screener hypothesis.
    Rejected,
    /// The verifier could not reach a stable answer from the supplied evidence.
    Inconclusive,
}

impl VerificationVerdict {
    /// Returns the lowercase verdict label used in logs and JSON-facing text.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// Combined outcome for one commit candidate across all provider passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CandidateOutcome {
    /// First-pass screening result.
    pub(crate) screening: ScreeningAnalysis,
    /// Optional second-pass verification result when the screener escalated the candidate.
    pub(crate) verification: Option<VerificationAnalysis>,
}

impl CandidateOutcome {
    /// Returns the final human-readable summary for this candidate.
    pub(crate) fn final_summary(&self) -> &str {
        self.verification
            .as_ref()
            .map(|verification| verification.verification_summary.as_str())
            .unwrap_or(self.screening.candidate_summary.as_str())
    }

    /// Returns the final security-relevant findings for this candidate.
    pub(crate) fn final_findings(&self) -> &[SuspiciousFinding] {
        self.verification
            .as_ref()
            .map(|verification| verification.confirmed_findings.as_slice())
            .unwrap_or_else(|| self.screening.suspicious_findings.as_slice())
    }
}

/// One suspicious security-relevant finding attributed to a single commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SuspiciousFinding {
    /// Short finding title.
    pub(crate) title: String,
    /// Provider confidence from 0.0 to 1.0.
    pub(crate) confidence: f32,
    /// Commit id that contains the suspicious change.
    pub(crate) commit_id: String,
    /// Technical explanation of the security consequence.
    pub(crate) rationale: String,
    /// Optional bug-class label.
    pub(crate) likely_bug_class: Option<String>,
    /// Files that support the finding.
    pub(crate) affected_files: Vec<String>,
    /// Concrete evidence lines or code references.
    pub(crate) evidence: Vec<String>,
    /// Follow-up questions or audit steps.
    pub(crate) follow_up: Vec<String>,
}

/// Persisted metadata for one CLI run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RunManifest {
    /// Selected provider name.
    pub(crate) provider: String,
    /// Optional explicit model override.
    pub(crate) model: Option<String>,
    /// Optional screening-pass reasoning-effort override.
    pub(crate) screen_effort: Option<String>,
    /// Optional verification-pass reasoning-effort override.
    pub(crate) verify_effort: Option<String>,
    /// Canonical repository root path.
    pub(crate) repo_root: String,
    /// Inclusive lower range boundary.
    pub(crate) from: String,
    /// Inclusive upper range boundary.
    pub(crate) to: String,
    /// Number of included commits in the range.
    pub(crate) commit_count: usize,
    /// Maximum diff bytes supplied per commit.
    pub(crate) max_patch_bytes: usize,
    /// Whether provider execution was skipped.
    pub(crate) dry_run: bool,
}

/// Persisted progress state for one analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProgressState {
    /// Number of candidates that are still pending or currently in progress.
    pub(crate) count_pending: usize,
    /// Number of candidates that have completed.
    pub(crate) count_complete: usize,
    /// Ordered unfinished candidates for the current run.
    pub(crate) pending: Vec<ProgressPendingCandidate>,
    /// Ordered completed candidates for the current run.
    pub(crate) complete: Vec<ProgressCompleteCandidate>,
}

/// Persisted unfinished status for one commit candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProgressPendingCandidate {
    /// Zero-based candidate index within the run.
    pub(crate) candidate_index: usize,
    /// Canonical full commit id.
    pub(crate) commit_id: String,
    /// Short commit id for compact display.
    pub(crate) short_id: String,
    /// Current persisted status for the unfinished candidate.
    pub(crate) status: ProgressStatus,
    /// Optional detailed stage label for staged Codex execution.
    pub(crate) active_stage: Option<String>,
}

/// Persisted completed status for one commit candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProgressCompleteCandidate {
    /// Zero-based candidate index within the run.
    pub(crate) candidate_index: usize,
    /// Canonical full commit id.
    pub(crate) commit_id: String,
    /// Short commit id for compact display.
    pub(crate) short_id: String,
    /// Persisted result summary for the completed candidate.
    pub(crate) result: ProgressResult,
}

/// Persisted lifecycle state for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProgressStatus {
    /// Candidate has not started yet.
    Pending,
    /// Candidate is currently being analyzed under `wip/`.
    InProgress,
}

/// Persisted result metadata for one completed candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProgressResult {
    /// Final authoritative provider summary for the candidate.
    pub(crate) candidate_summary: String,
    /// Number of suspicious findings retained from analysis.
    pub(crate) finding_count: usize,
    /// Whether a completed candidate directory is available on disk.
    pub(crate) artifacts_retained: bool,
}

/// Final merged report for all analyzed commit candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AnalysisReport {
    /// Run metadata.
    pub(crate) manifest: RunManifest,
    /// Number of analyzed commit candidates.
    pub(crate) candidate_count: usize,
    /// Ranked suspicious findings across the run.
    pub(crate) findings: Vec<RankedFinding>,
}

/// Deduplicated suspicious finding carried into the final report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RankedFinding {
    /// Short finding title.
    pub(crate) title: String,
    /// Provider confidence from 0.0 to 1.0.
    pub(crate) confidence: f32,
    /// Commit id that contains the suspicious change.
    pub(crate) commit_id: String,
    /// Technical explanation of the security consequence.
    pub(crate) rationale: String,
    /// Optional bug-class label.
    pub(crate) likely_bug_class: Option<String>,
    /// Files that support the finding.
    pub(crate) affected_files: Vec<String>,
    /// Concrete evidence lines or code references.
    pub(crate) evidence: Vec<String>,
    /// Follow-up questions or audit steps.
    pub(crate) follow_up: Vec<String>,
    /// Candidate indexes that produced the finding.
    pub(crate) source_candidates: Vec<usize>,
}
