//! Final report generation and terminal output.
//! Ownership: client-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::types::{
    AnalysisReport, CandidateOutcome, CommitCandidate, RankedFinding, RunManifest,
    SuspiciousFinding,
};

/// Merges final candidate findings into the report.
pub(crate) fn merge_findings(
    manifest: RunManifest,
    candidates: &[CommitCandidate],
    outcomes: &[(usize, CandidateOutcome)],
    min_confidence: f32,
) -> AnalysisReport {
    let mut by_key: BTreeMap<(String, String, String), RankedFinding> = BTreeMap::new();

    for (candidate_index, outcome) in outcomes {
        let Some(candidate) = candidates
            .iter()
            .find(|current| current.candidate_index == *candidate_index)
        else {
            continue;
        };

        for finding in outcome.final_findings() {
            if finding.confidence < min_confidence {
                continue;
            }

            if let Some(normalized) = normalize_finding(finding, candidate, *candidate_index) {
                let key = (
                    normalized.commit_id.clone(),
                    normalized.title.to_lowercase(),
                    normalized
                        .likely_bug_class
                        .clone()
                        .unwrap_or_default()
                        .to_lowercase(),
                );

                if let Some(existing) = by_key.get_mut(&key) {
                    merge_into(existing, normalized);
                } else {
                    by_key.insert(key, normalized);
                }
            }
        }
    }

    let mut findings: Vec<RankedFinding> = by_key.into_values().collect();
    findings.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.commit_id.cmp(&right.commit_id))
    });

    AnalysisReport {
        manifest,
        candidate_count: candidates.len(),
        findings,
    }
}

/// Writes both machine-readable and Markdown report outputs.
pub(crate) fn write_report(run_dir: &Path, report: &AnalysisReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    fs::write(run_dir.join("report.json"), json)
        .with_context(|| format!("failed to write {}/report.json", run_dir.display()))?;
    fs::write(run_dir.join("summary.md"), render_summary(report))
        .with_context(|| format!("failed to write {}/summary.md", run_dir.display()))?;
    Ok(())
}

/// Prints a concise terminal summary for the finished run.
pub(crate) fn print_terminal_summary(report: &AnalysisReport, run_dir: &Path) {
    println!(
        "Analyzed {} commits as {} candidate(s).",
        report.manifest.commit_count, report.candidate_count
    );

    if report.findings.is_empty() {
        println!("No suspicious findings met the configured confidence threshold.");
    } else {
        println!("Flagged {} suspicious finding(s):", report.findings.len());
        for finding in &report.findings {
            println!(
                "- {:.2} {} [{}]",
                finding.confidence,
                finding.title,
                short_hash(&finding.commit_id)
            );
        }
    }

    println!("Artifacts: {}", run_dir.display());
}

/// Returns a short commit id prefix for display.
fn short_hash(commit: &str) -> &str {
    &commit[..usize::min(commit.len(), 12)]
}

/// Normalizes one finding against its source candidate.
fn normalize_finding(
    finding: &SuspiciousFinding,
    candidate: &CommitCandidate,
    candidate_index: usize,
) -> Option<RankedFinding> {
    let commit_id = normalize_commit_id(finding, candidate)?;

    Some(RankedFinding {
        title: finding.title.trim().to_owned(),
        confidence: finding.confidence,
        commit_id,
        rationale: finding.rationale.trim().to_owned(),
        likely_bug_class: finding.likely_bug_class.clone(),
        affected_files: dedup_preserve(finding.affected_files.clone()),
        evidence: dedup_preserve(finding.evidence.clone()),
        follow_up: dedup_preserve(finding.follow_up.clone()),
        source_candidates: vec![candidate_index],
    })
}

/// Resolves the provider-supplied commit id to the canonical candidate commit id.
fn normalize_commit_id(finding: &SuspiciousFinding, candidate: &CommitCandidate) -> Option<String> {
    if finding.commit_id == candidate.commit.id || finding.commit_id == candidate.commit.short_id {
        return Some(candidate.commit.id.clone());
    }

    None
}

/// Merges a duplicate normalized finding into an existing one.
fn merge_into(existing: &mut RankedFinding, incoming: RankedFinding) {
    if incoming.confidence > existing.confidence {
        existing.title = incoming.title;
        existing.confidence = incoming.confidence;
        existing.rationale = incoming.rationale;
        existing.likely_bug_class = incoming.likely_bug_class;
    }

    existing.affected_files = dedup_preserve(
        existing
            .affected_files
            .iter()
            .cloned()
            .chain(incoming.affected_files)
            .collect(),
    );
    existing.evidence = dedup_preserve(
        existing
            .evidence
            .iter()
            .cloned()
            .chain(incoming.evidence)
            .collect(),
    );
    existing.follow_up = dedup_preserve(
        existing
            .follow_up
            .iter()
            .cloned()
            .chain(incoming.follow_up)
            .collect(),
    );
    existing.source_candidates = dedup_preserve(
        existing
            .source_candidates
            .iter()
            .copied()
            .chain(incoming.source_candidates)
            .collect(),
    );
}

/// Removes duplicates while preserving the first-seen order.
fn dedup_preserve<T>(items: Vec<T>) -> Vec<T>
where
    T: Clone + Ord,
{
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();

    for item in items {
        if seen.insert(item.clone()) {
            deduped.push(item);
        }
    }

    deduped
}

/// Renders the Markdown summary artifact.
fn render_summary(report: &AnalysisReport) -> String {
    let mut output = String::new();
    output.push_str("# VCamper Analysis Summary\n\n");
    let stop_after = report
        .manifest
        .stop_after_stage
        .clone()
        .unwrap_or_else(|| "full pipeline".to_owned());
    let inventory_focuses = if report.manifest.inventory_focuses.is_empty() {
        "full hotspot set".to_owned()
    } else {
        report
            .manifest
            .inventory_focuses
            .iter()
            .map(|focus| focus.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    output.push_str(&format!(
        "- Repo: `{}`\n- Range: `{}`..`{}`\n- Provider: `{}`\n- Model: `{}`\n- Screen effort: `{}`\n- Verify effort: `{}`\n- Stop after stage: `{}`\n- Inventory focuses: `{}`\n- Commits analyzed: `{}`\n- Candidates: `{}`\n\n",
        report.manifest.repo_root,
        report.manifest.from,
        report.manifest.to,
        report.manifest.provider,
        report
            .manifest
            .model
            .clone()
            .unwrap_or_else(|| "provider default".to_owned()),
        report
            .manifest
            .screen_effort
            .clone()
            .unwrap_or_else(|| "provider default".to_owned()),
        report
            .manifest
            .verify_effort
            .clone()
            .unwrap_or_else(|| "provider default".to_owned()),
        stop_after,
        inventory_focuses,
        report.manifest.commit_count,
        report.candidate_count
    ));

    if report.findings.is_empty() {
        output.push_str("No suspicious findings met the configured confidence threshold.\n");
        return output;
    }

    output.push_str("## Findings\n\n");
    for finding in &report.findings {
        output.push_str(&format!(
            "### {:.2} {}\n\n- Commit: `{}`\n- Bug class: `{}`\n- Source candidates: `{}`\n- Files: `{}`\n\n{}\n\n",
            finding.confidence,
            finding.title,
            finding.commit_id,
            finding
                .likely_bug_class
                .clone()
                .unwrap_or_else(|| "unspecified".to_owned()),
            finding
                .source_candidates
                .iter()
                .map(|candidate| candidate.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            finding.affected_files.join(", "),
            finding.rationale
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use crate::types::{
        CandidateOutcome, CommitCandidate, CommitRecord, FileStat, RunManifest, ScreeningAnalysis,
        SuspiciousFinding,
    };

    use super::merge_findings;

    #[test]
    fn merges_duplicate_findings_for_one_commit() {
        let commit = CommitRecord {
            id: "a".into(),
            short_id: "a".into(),
            parent_ids: vec![],
            author_name: "alice".into(),
            author_email: "alice@example.com".into(),
            authored_at: "2025-01-01T00:00:00Z".into(),
            summary: "a".into(),
            files_changed: vec!["src/a.rs".into()],
            file_stats: vec![FileStat {
                path: "src/a.rs".into(),
                additions: Some(1),
                deletions: Some(0),
            }],
            patch: "patch".into(),
            patch_truncated: false,
        };

        let candidates = vec![CommitCandidate {
            candidate_index: 0,
            commit,
        }];

        let finding = SuspiciousFinding {
            title: "guard added".into(),
            confidence: 0.9,
            commit_id: "a".into(),
            rationale: "tightens validation".into(),
            likely_bug_class: Some("input validation".into()),
            affected_files: vec!["src/a.rs".into()],
            evidence: vec!["validation".into()],
            follow_up: vec!["check tag".into()],
        };

        let outcomes = vec![
            (
                0,
                CandidateOutcome {
                    screening: ScreeningAnalysis {
                        candidate_summary: "x".into(),
                        suspicious_findings: vec![finding.clone()],
                    },
                    verification: None,
                },
            ),
            (
                0,
                CandidateOutcome {
                    screening: ScreeningAnalysis {
                        candidate_summary: "y".into(),
                        suspicious_findings: vec![finding],
                    },
                    verification: None,
                },
            ),
        ];

        let report = merge_findings(
            RunManifest {
                provider: "codex".into(),
                model: None,
                screen_effort: None,
                verify_effort: None,
                repo_root: "/repo".into(),
                from: "from".into(),
                to: "to".into(),
                commit_count: 1,
                max_patch_bytes: 100,
                dry_run: false,
                stop_after_stage: None,
                inventory_focuses: Vec::new(),
            },
            &candidates,
            &outcomes,
            0.5,
        );

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].source_candidates, vec![0]);
    }
}
