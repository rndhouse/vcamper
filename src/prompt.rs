//! Prompt rendering for commit-candidate analysis.
//! Ownership: client-only

use anyhow::Result;
use serde::Serialize;
use serde_json::to_string_pretty;

use crate::types::{CommitCandidate, FileStat, ScreeningAnalysis};

const SCREEN_COMMIT_TEMPLATE: &str = include_str!("../prompts/analyze_commit.md");
const VERIFY_COMMIT_TEMPLATE: &str = include_str!("../prompts/verify_commit.md");

/// Code-first evidence exposed to the provider for one commit candidate.
///
/// Commit summaries are intentionally withheld so first-pass classification stays anchored on
/// code and patch semantics instead of commit-message framing.
#[derive(Debug, Serialize)]
pub(crate) struct PromptCommitCandidate {
    /// Zero-based candidate index within the analyzed range.
    pub(crate) candidate_index: usize,
    /// Code-centric commit record included in the prompt.
    pub(crate) commit: PromptCommitRecord,
}

/// Verifier evidence exposed to the provider for one commit candidate.
#[derive(Debug, Serialize)]
pub(crate) struct PromptVerificationCandidate {
    /// Zero-based candidate index within the analyzed range.
    pub(crate) candidate_index: usize,
    /// Code-centric commit record included in the prompt.
    pub(crate) commit: PromptCommitRecord,
    /// Commit subject restored as secondary context for the verifier.
    pub(crate) commit_message: String,
    /// First-pass screening hypothesis that the verifier must confirm or reject.
    pub(crate) screening_hypothesis: ScreeningAnalysis,
}

/// Code-centric commit evidence used during first-pass prompt analysis.
#[derive(Debug, Serialize)]
pub(crate) struct PromptCommitRecord {
    /// Full commit id for evidence references.
    pub(crate) id: String,
    /// Short commit id for compact display.
    pub(crate) short_id: String,
    /// Parent ids for local commit-order reasoning.
    pub(crate) parent_ids: Vec<String>,
    /// Paths changed by the commit.
    pub(crate) files_changed: Vec<String>,
    /// Aggregate per-file line counts from `git show --numstat`.
    pub(crate) file_stats: Vec<FileStat>,
    /// Unified patch text, truncated when it exceeds the configured byte limit.
    pub(crate) patch: String,
    /// Whether the patch was truncated before prompting.
    pub(crate) patch_truncated: bool,
}

/// Builds the code-first provider evidence for one commit candidate.
pub(crate) fn build_prompt_input(candidate: &CommitCandidate) -> PromptCommitCandidate {
    PromptCommitCandidate {
        candidate_index: candidate.candidate_index,
        commit: PromptCommitRecord {
            id: candidate.commit.id.clone(),
            short_id: candidate.commit.short_id.clone(),
            parent_ids: candidate.commit.parent_ids.clone(),
            files_changed: candidate.commit.files_changed.clone(),
            file_stats: candidate.commit.file_stats.clone(),
            patch: candidate.commit.patch.clone(),
            patch_truncated: candidate.commit.patch_truncated,
        },
    }
}

/// Builds the verifier evidence for one commit candidate.
pub(crate) fn build_verification_prompt_input(
    candidate: &CommitCandidate,
    screening: &ScreeningAnalysis,
) -> PromptVerificationCandidate {
    PromptVerificationCandidate {
        candidate_index: candidate.candidate_index,
        commit: build_prompt_input(candidate).commit,
        commit_message: candidate.commit.summary.clone(),
        screening_hypothesis: screening.clone(),
    }
}

/// Renders the first-pass provider prompt for one commit candidate.
pub(crate) fn render_screen_prompt(repo_root: &str, candidate: &CommitCandidate) -> Result<String> {
    let prompt_input = build_prompt_input(candidate);
    let commit_json = to_string_pretty(&prompt_input)?;

    Ok(format!(
        "{SCREEN_COMMIT_TEMPLATE}\n\n\
         Repository root: {repo_root}\n\
         Commit under analysis: {commit_id}\n\n\
         Commit messages are intentionally withheld for this first-pass analysis.\n\
         Return a JSON object that matches the supplied schema.\n\
         Use an empty suspicious_findings array when this commit does not look security-relevant.\n\n\
         Code-first commit evidence:\n\
         ```json\n\
         {commit_json}\n\
         ```\n",
        commit_id = candidate.commit.id,
    ))
}

/// Renders the second-pass verifier prompt for one commit candidate.
pub(crate) fn render_verify_prompt(
    repo_root: &str,
    candidate: &CommitCandidate,
    screening: &ScreeningAnalysis,
) -> Result<String> {
    let prompt_input = build_verification_prompt_input(candidate, screening);
    let commit_json = to_string_pretty(&prompt_input)?;

    Ok(format!(
        "{VERIFY_COMMIT_TEMPLATE}\n\n\
         Repository root: {repo_root}\n\
         Commit under analysis: {commit_id}\n\n\
         Return a JSON object that matches the supplied schema.\n\
         Use an empty confirmed_findings array when the screener hypothesis does not hold up.\n\n\
         Verification evidence:\n\
         ```json\n\
         {commit_json}\n\
         ```\n",
        commit_id = candidate.commit.id,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        build_prompt_input, build_verification_prompt_input, render_screen_prompt,
        render_verify_prompt,
    };
    use crate::types::{CommitCandidate, CommitRecord, FileStat, ScreeningAnalysis};

    #[test]
    fn prompt_input_omits_commit_summary() {
        let candidate = CommitCandidate {
            candidate_index: 0,
            commit: CommitRecord {
                id: "abc".into(),
                short_id: "abc".into(),
                parent_ids: vec!["def".into()],
                author_name: "Author".into(),
                author_email: "author@example.com".into(),
                authored_at: "2026-04-08T00:00:00Z".into(),
                summary: "fix subtle auth bug".into(),
                files_changed: vec!["src/lib.rs".into()],
                file_stats: vec![FileStat {
                    path: "src/lib.rs".into(),
                    additions: Some(1),
                    deletions: Some(0),
                }],
                patch: "@@ -1 +1 @@\n-old\n+new".into(),
                patch_truncated: false,
            },
        };

        let prompt_input = build_prompt_input(&candidate);
        let json =
            serde_json::to_string_pretty(&prompt_input).expect("prompt input should serialize");

        assert!(!json.contains("fix subtle auth bug"));
        assert!(json.contains("\"patch\""));
        assert!(json.contains("\"files_changed\""));
    }

    #[test]
    fn rendered_prompt_mentions_message_redaction() {
        let candidate = CommitCandidate {
            candidate_index: 0,
            commit: CommitRecord {
                id: "abc".into(),
                short_id: "abc".into(),
                parent_ids: vec![],
                author_name: "Author".into(),
                author_email: "author@example.com".into(),
                authored_at: "2026-04-08T00:00:00Z".into(),
                summary: "routine message".into(),
                files_changed: vec!["src/lib.rs".into()],
                file_stats: Vec::new(),
                patch: "@@ -1 +1 @@\n-old\n+new".into(),
                patch_truncated: false,
            },
        };

        let prompt = render_screen_prompt("/repo", &candidate).expect("prompt should render");

        assert!(prompt.contains("Commit messages are intentionally withheld"));
        assert!(!prompt.contains("routine message"));
        assert!(!prompt.contains("Release range"));
    }

    #[test]
    fn verification_prompt_restores_commit_message_and_screening_hypothesis() {
        let candidate = CommitCandidate {
            candidate_index: 0,
            commit: CommitRecord {
                id: "abc".into(),
                short_id: "abc".into(),
                parent_ids: vec![],
                author_name: "Author".into(),
                author_email: "author@example.com".into(),
                authored_at: "2026-04-08T00:00:00Z".into(),
                summary: "routine message".into(),
                files_changed: vec!["src/lib.rs".into()],
                file_stats: Vec::new(),
                patch: "@@ -1 +1 @@\n-old\n+new".into(),
                patch_truncated: false,
            },
        };
        let screening = ScreeningAnalysis {
            candidate_summary: "screening summary".into(),
            suspicious_findings: Vec::new(),
        };

        let prompt_input = build_verification_prompt_input(&candidate, &screening);
        let json =
            serde_json::to_string_pretty(&prompt_input).expect("prompt input should serialize");
        let prompt = render_verify_prompt("/repo", &candidate, &screening)
            .expect("verification prompt should render");

        assert!(json.contains("routine message"));
        assert!(json.contains("screening summary"));
        assert!(prompt.contains("confirmed_findings"));
    }
}
