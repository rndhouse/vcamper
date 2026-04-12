//! Prompt rendering for commit-candidate analysis.
//! Ownership: client-only

use anyhow::Result;
use serde::Serialize;
use serde_json::to_string_pretty;
use std::path::Path;

use crate::hotspot::HotspotCluster;
use crate::types::{CommitCandidate, FileStat, ScreeningAnalysis};

const SCREEN_COMMIT_TEMPLATE: &str = include_str!("../prompts/analyze_commit.md");
const REACHABILITY_TEMPLATE: &str = include_str!("../prompts/reachability_commit.md");
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

/// Renders the Codex-specific screening-plan prompt for one commit candidate.
pub(crate) fn render_codex_screen_plan_prompt(
    cluster_count: usize,
    prompt_input_path: &Path,
) -> String {
    format!(
        "{SCREEN_COMMIT_TEMPLATE}\n\n\
         This screening pass is the inventory stage of a clustered analysis.\n\
         Start with `{prompt_input_path}` to review the hotspot plan.\n\
         Then inspect the cluster-specific bundles listed there.\n\
         The current candidate has {cluster_count} hotspot cluster(s).\n\
         Commit messages are intentionally withheld for this first-pass analysis.\n\
         The actual provider runs happen inside each cluster bundle.\n\
         The goal of this stage is breadth. Inventory distinct security hypotheses without trying\n\
         to settle which one is strongest overall.\n",
        prompt_input_path = prompt_input_path.display(),
    )
}

/// Renders the Codex-specific prompt for one clustered screening pass.
pub(crate) fn render_codex_screen_cluster_prompt(
    cluster: &HotspotCluster,
    prompt_input_path: &Path,
) -> String {
    format!(
        "{SCREEN_COMMIT_TEMPLATE}\n\n\
         All evidence for this inventory cluster is available in the bundle referenced by\n\
         `{prompt_input_path}`.\n\
         Start with that `prompt-input.json` file.\n\
         Analyze only hotspot cluster `{title}`.\n\
         Cluster rationale: {rationale}\n\
         Inspect the cluster patch and snapshots through the absolute file paths in that bundle.\n\
         Commit messages are intentionally withheld for this first-pass analysis.\n\
         Return all materially distinct hypotheses from this cluster that have concrete code\n\
         evidence. Prefer breadth over early adjudication, but drop near-duplicates and keep the\n\
         response compact.\n\
         Return a JSON object that matches the supplied schema.\n\
         Use an empty suspicious_findings array when this cluster does not look security-relevant.\n",
        title = cluster.title,
        rationale = cluster.rationale,
        prompt_input_path = prompt_input_path.display(),
    )
}

/// Renders the Codex-specific reachability prompt for one screened hypothesis.
pub(crate) fn render_codex_reachability_prompt(prompt_input_path: &Path) -> String {
    format!(
        "{REACHABILITY_TEMPLATE}\n\n\
         All evidence for this reachability review is available in the bundle referenced by\n\
         `{prompt_input_path}`.\n\
         Start with that `prompt-input.json` file.\n\
         Inspect the absolute file paths it provides for the hypothesis-local patch subset,\n\
         hotspot plan, and before/after snapshots.\n\
         Treat the supplied finding as a claim to test, not a conclusion to repeat.\n\
         Return a JSON object that matches the supplied schema.\n\
         Use `rejected` with `refined_finding: null` when the hypothesis does not survive\n\
         attacker-path review.\n",
        prompt_input_path = prompt_input_path.display(),
    )
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

/// Renders the Codex-specific second-pass verifier prompt for one commit candidate.
pub(crate) fn render_codex_verify_prompt(prompt_input_path: &Path) -> String {
    format!(
        "{VERIFY_COMMIT_TEMPLATE}\n\n\
         All evidence for this adjudication pass is available in the bundle referenced by\n\
         `{prompt_input_path}`.\n\
         Start with that `prompt-input.json` file.\n\
         Then inspect the absolute file paths it provides for the patch, hotspot plan, snapshots,\n\
         and adjudication finalists.\n\
         Use the commit message as secondary context.\n\
         Compare the shortlisted finalists head-to-head and pick the strongest supported security\n\
         story, or reject them all.\n\
         Do not union all finalists into the output. Prefer one winner, or none, when several\n\
         hypotheses describe the same commit from different angles.\n\
         Return a JSON object that matches the supplied schema.\n\
         Use an empty confirmed_findings array when no finalist holds up.\n",
        prompt_input_path = prompt_input_path.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_prompt_input, build_verification_prompt_input, render_codex_reachability_prompt,
        render_codex_screen_cluster_prompt, render_codex_screen_plan_prompt,
        render_codex_verify_prompt, render_screen_prompt, render_verify_prompt,
    };
    use crate::hotspot::HotspotCluster;
    use crate::types::{CommitCandidate, CommitRecord, FileStat, ScreeningAnalysis};
    use std::path::Path;

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
    fn codex_screen_plan_prompt_points_to_cluster_bundles() {
        let prompt = render_codex_screen_plan_prompt(3, Path::new("/tmp/bundle/prompt-input.json"));

        assert!(prompt.contains("/tmp/bundle/prompt-input.json"));
        assert!(prompt.contains("3 hotspot cluster(s)"));
        assert!(prompt.contains("Commit messages are intentionally withheld"));
        assert!(prompt.contains("inventory stage"));
        assert!(!prompt.contains("Repository root:"));
    }

    #[test]
    fn codex_screen_cluster_prompt_mentions_cluster_focus() {
        let cluster = HotspotCluster {
            cluster_index: 0,
            title: "Digest-length checks on verification paths".into(),
            rationale: "Look for caller-controlled digest-length guards in verification code."
                .into(),
            category: "digest_length_verify".into(),
            files: vec!["src/pk_ec.c".into()],
            function_hints: vec!["int wolfSSL_ECDSA_verify(...)".into()],
            signal_terms: vec!["digest-length guard".into()],
            score: 10,
        };
        let prompt = render_codex_screen_cluster_prompt(
            &cluster,
            Path::new("/tmp/cluster/prompt-input.json"),
        );

        assert!(prompt.contains("Analyze only hotspot cluster"));
        assert!(prompt.contains("materially distinct hypotheses"));
        assert!(prompt.contains("verification code"));
    }

    #[test]
    fn codex_reachability_prompt_points_to_bundle_files() {
        let prompt =
            render_codex_reachability_prompt(Path::new("/tmp/reachability/prompt-input.json"));

        assert!(prompt.contains("/tmp/reachability/prompt-input.json"));
        assert!(prompt.contains("claim to test"));
        assert!(prompt.contains("refined_finding: null"));
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

    #[test]
    fn codex_verify_prompt_points_to_bundle_files() {
        let prompt = render_codex_verify_prompt(Path::new("/tmp/verify/prompt-input.json"));

        assert!(prompt.contains("/tmp/verify/prompt-input.json"));
        assert!(prompt.contains("adjudication finalists"));
        assert!(prompt.contains("one winner, or none"));
        assert!(!prompt.contains("Repository root:"));
    }
}
