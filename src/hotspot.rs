//! Hotspot extraction and clustering for Codex commit screening.
//! Ownership: client-only

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

const MAX_CLUSTERS: usize = 4;
const MIN_CLUSTER_SCORE: usize = 8;

/// Ranked hotspot plan for one commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HotspotPlan {
    /// Ranked file-level hotspots extracted from the full patch.
    pub(crate) files: Vec<HotspotFile>,
    /// Screening clusters built from the ranked hotspots.
    pub(crate) clusters: Vec<HotspotCluster>,
}

/// One file-level hotspot extracted from the full patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HotspotFile {
    /// Repository-relative file path.
    pub(crate) path: String,
    /// Ranked hotspot category.
    pub(crate) category: String,
    /// Relative hotspot strength within the commit.
    pub(crate) score: usize,
    /// Short explanation for why the file was promoted as a hotspot.
    pub(crate) rationale: String,
    /// Function or hunk-context hints extracted from the patch.
    pub(crate) function_hints: Vec<String>,
    /// Signal terms that contributed to the hotspot score.
    pub(crate) signal_terms: Vec<String>,
}

/// One screening cluster derived from related hotspot files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HotspotCluster {
    /// Zero-based cluster index within the plan.
    pub(crate) cluster_index: usize,
    /// Short title shown in artifacts and prompts.
    pub(crate) title: String,
    /// Focus explanation for the cluster.
    pub(crate) rationale: String,
    /// Category label for the cluster.
    pub(crate) category: String,
    /// Files included in the cluster bundle.
    pub(crate) files: Vec<String>,
    /// Representative function hints for the cluster.
    pub(crate) function_hints: Vec<String>,
    /// Signal terms aggregated across the cluster files.
    pub(crate) signal_terms: Vec<String>,
    /// Aggregate ranking score.
    pub(crate) score: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HotspotCategory {
    AlgorithmBinding,
    DigestLengthVerify,
    DigestLengthSign,
    ParserValidation,
    GuardedStateChange,
    GenericGuardedChange,
}

impl HotspotCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::AlgorithmBinding => "algorithm_binding",
            Self::DigestLengthVerify => "digest_length_verify",
            Self::DigestLengthSign => "digest_length_sign",
            Self::ParserValidation => "parser_validation",
            Self::GuardedStateChange => "guarded_state_change",
            Self::GenericGuardedChange => "generic_guarded_change",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::AlgorithmBinding => "Signature algorithm binding checks",
            Self::DigestLengthVerify => "Digest-length checks on verification paths",
            Self::DigestLengthSign => "Digest-length checks on signing APIs",
            Self::ParserValidation => "Parser and decoder trust-boundary checks",
            Self::GuardedStateChange => "New guarded state transitions",
            Self::GenericGuardedChange => "Other guarded changes",
        }
    }

    fn rationale(self) -> &'static str {
        match self {
            Self::AlgorithmBinding => {
                "Look for signature/OID/key-agreement checks that change certificate, OCSP, or signed-object verification semantics."
            }
            Self::DigestLengthVerify => {
                "Look for caller-controlled digest-length guards in verification code and whether remote inputs can reach them."
            }
            Self::DigestLengthSign => {
                "Look for digest-length constraints in sign or detached-signature APIs that might close exploitable verification or parser gaps."
            }
            Self::ParserValidation => {
                "Look for parser/decoder guards that fence attacker-controlled metadata or state-machine transitions."
            }
            Self::GuardedStateChange => {
                "Look for newly guarded state transitions that block malformed or attacker-controlled inputs."
            }
            Self::GenericGuardedChange => {
                "Inspect this cluster for security-significant validation, bounds, or trust-boundary changes."
            }
        }
    }
}

#[derive(Debug, Clone)]
struct FilePatchSegment {
    path: String,
    diff: String,
    lower_diff: String,
    function_hints: Vec<String>,
}

#[derive(Debug, Clone)]
struct RankedFileHotspot {
    path: String,
    category: HotspotCategory,
    score: usize,
    rationale: String,
    function_hints: Vec<String>,
    signal_terms: Vec<String>,
}

/// Builds a ranked hotspot plan from the full patch text for one commit.
pub(crate) fn build_hotspot_plan(full_patch: &str) -> HotspotPlan {
    let mut files: Vec<RankedFileHotspot> = split_patch_by_file(full_patch)
        .into_iter()
        .map(rank_file_hotspot)
        .filter(|hotspot| hotspot.score > 0)
        .collect();
    files.sort_by_key(|hotspot| (Reverse(hotspot.score), hotspot.path.clone()));

    let mut clusters = build_category_clusters(&files);
    if clusters.is_empty() {
        clusters = build_fallback_file_clusters(&files);
    }
    clusters.sort_by_key(|cluster| (Reverse(cluster.score), cluster.cluster_index));
    clusters.truncate(MAX_CLUSTERS);
    for (cluster_index, cluster) in clusters.iter_mut().enumerate() {
        cluster.cluster_index = cluster_index;
    }

    HotspotPlan {
        files: files
            .into_iter()
            .map(|hotspot| HotspotFile {
                path: hotspot.path,
                category: hotspot.category.as_str().to_owned(),
                score: hotspot.score,
                rationale: hotspot.rationale,
                function_hints: hotspot.function_hints,
                signal_terms: hotspot.signal_terms,
            })
            .collect(),
        clusters,
    }
}

/// Filters a full patch down to the selected repository-relative files.
pub(crate) fn filtered_patch_for_files(full_patch: &str, files: &[String]) -> String {
    let selected: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    split_patch_by_file(full_patch)
        .into_iter()
        .filter(|segment| selected.contains(segment.path.as_str()))
        .map(|segment| segment.diff)
        .collect::<Vec<_>>()
        .join("\n")
}

fn split_patch_by_file(full_patch: &str) -> Vec<FilePatchSegment> {
    let mut segments = Vec::new();
    let mut current = Vec::new();

    for line in full_patch.lines() {
        if line.starts_with("diff --git ") && !current.is_empty() {
            if let Some(segment) = finalize_segment(&current.join("\n")) {
                segments.push(segment);
            }
            current.clear();
        }
        current.push(line.to_owned());
    }

    if !current.is_empty() {
        if let Some(segment) = finalize_segment(&current.join("\n")) {
            segments.push(segment);
        }
    }

    segments
}

fn finalize_segment(raw: &str) -> Option<FilePatchSegment> {
    let path = raw
        .lines()
        .find_map(|line| line.strip_prefix("+++ b/"))
        .or_else(|| raw.lines().find_map(|line| line.strip_prefix("--- a/")))?;
    let function_hints = raw
        .lines()
        .filter_map(parse_hunk_hint)
        .take(6)
        .collect::<Vec<_>>();
    Some(FilePatchSegment {
        path: path.to_owned(),
        diff: format!("{raw}\n"),
        lower_diff: raw.to_ascii_lowercase(),
        function_hints,
    })
}

fn parse_hunk_hint(line: &str) -> Option<String> {
    let suffix = line.split("@@").nth(2)?.trim();
    if suffix.is_empty() {
        return None;
    }
    Some(suffix.to_owned())
}

fn rank_file_hotspot(segment: FilePatchSegment) -> RankedFileHotspot {
    let lower = segment.lower_diff.as_str();
    let is_test_path = segment.path.contains("/test") || segment.path.starts_with("tests/");
    let mut score = 0usize;
    let mut terms = BTreeSet::new();

    let has_sigoid = contains_signal(lower, &["sigoid"], &mut terms, "sigoid");
    let has_keyoid = contains_signal(lower, &["keyoid"], &mut terms, "keyoid");
    let has_asn_sig_oid = contains_signal(lower, &["asn_sig_oid_e"], &mut terms, "asn_sig_oid_e");
    let has_confirm_signature =
        contains_signal(lower, &["confirmsignature"], &mut terms, "ConfirmSignature");
    let has_digest_bounds = contains_signal(
        lower,
        &["wc_min_digest_size", "wc_max_digest_size", "bad_length_e"],
        &mut terms,
        "digest-length guard",
    );
    let has_verify = contains_signal(lower, &["verify"], &mut terms, "verify");
    let has_sign = contains_signal(lower, &["sign"], &mut terms, "sign");
    let has_ocsp = contains_signal(lower, &["ocsp"], &mut terms, "ocsp");
    let has_cert = contains_signal(
        lower,
        &["certificate", "decodedcert", "checkcertsigpubkey", "cert"],
        &mut terms,
        "certificate",
    );
    let has_parser = contains_signal(
        lower,
        &["asn", "parse", "decode", "parser"],
        &mut terms,
        "parser",
    );
    let has_guard = lower.contains("if (") || lower.contains("if(");

    if has_sigoid {
        score += 10;
    }
    if has_keyoid {
        score += 6;
    }
    if has_asn_sig_oid {
        score += 6;
    }
    if has_confirm_signature {
        score += 8;
    }
    if has_digest_bounds {
        score += 9;
    }
    if has_verify {
        score += 5;
    }
    if has_sign {
        score += 3;
    }
    if has_ocsp {
        score += 5;
    }
    if has_cert {
        score += 4;
    }
    if has_parser {
        score += 4;
    }
    if has_guard {
        score += 2;
    }
    if is_test_path {
        score = score.saturating_sub(4);
    }

    let category = if has_sigoid && has_keyoid {
        HotspotCategory::AlgorithmBinding
    } else if has_digest_bounds && has_verify {
        HotspotCategory::DigestLengthVerify
    } else if has_digest_bounds && has_sign {
        HotspotCategory::DigestLengthSign
    } else if has_parser && (has_cert || has_ocsp || has_asn_sig_oid) {
        HotspotCategory::ParserValidation
    } else if has_guard && (has_verify || has_parser) {
        HotspotCategory::GuardedStateChange
    } else {
        HotspotCategory::GenericGuardedChange
    };

    let rationale = if score == 0 {
        "This file did not expose a strong screening signal.".to_owned()
    } else {
        format!(
            "Ranked as `{}` because the diff mixes {}.",
            category.as_str(),
            describe_terms(&terms)
        )
    };

    RankedFileHotspot {
        path: segment.path,
        category,
        score,
        rationale,
        function_hints: segment.function_hints,
        signal_terms: terms.into_iter().collect(),
    }
}

fn contains_signal(
    haystack: &str,
    needles: &[&str],
    terms: &mut BTreeSet<String>,
    label: &str,
) -> bool {
    if needles.iter().any(|needle| haystack.contains(needle)) {
        terms.insert(label.to_owned());
        return true;
    }

    false
}

fn describe_terms(terms: &BTreeSet<String>) -> String {
    let mut listed = terms.iter().take(3).cloned().collect::<Vec<_>>();
    if listed.is_empty() {
        return "guarded logic changes".to_owned();
    }
    if terms.len() > listed.len() {
        listed.push("other nearby validation signals".to_owned());
    }
    listed.join(", ")
}

fn build_category_clusters(files: &[RankedFileHotspot]) -> Vec<HotspotCluster> {
    let mut grouped: BTreeMap<HotspotCategory, Vec<RankedFileHotspot>> = BTreeMap::new();
    for hotspot in files {
        if hotspot.score < MIN_CLUSTER_SCORE {
            continue;
        }
        grouped
            .entry(hotspot.category)
            .or_default()
            .push(hotspot.clone());
    }

    let mut clusters = grouped
        .into_iter()
        .map(|(category, mut entries)| {
            entries.sort_by_key(|entry| (Reverse(entry.score), entry.path.clone()));
            let score = entries.iter().map(|entry| entry.score).sum::<usize>();
            let files = entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>();
            let function_hints = entries
                .iter()
                .flat_map(|entry| entry.function_hints.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(6)
                .collect::<Vec<_>>();
            let signal_terms = entries
                .iter()
                .flat_map(|entry| entry.signal_terms.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();

            HotspotCluster {
                cluster_index: 0,
                title: category.title().to_owned(),
                rationale: category.rationale().to_owned(),
                category: category.as_str().to_owned(),
                files,
                function_hints,
                signal_terms,
                score,
            }
        })
        .collect::<Vec<_>>();

    clusters.sort_by_key(|cluster| (Reverse(cluster.score), cluster.title.clone()));
    clusters
}

fn build_fallback_file_clusters(files: &[RankedFileHotspot]) -> Vec<HotspotCluster> {
    files
        .iter()
        .filter(|hotspot| hotspot.score >= MIN_CLUSTER_SCORE)
        .take(MAX_CLUSTERS)
        .map(|hotspot| HotspotCluster {
            cluster_index: 0,
            title: format!("Focused review: {}", hotspot.path),
            rationale: hotspot.rationale.clone(),
            category: hotspot.category.as_str().to_owned(),
            files: vec![hotspot.path.clone()],
            function_hints: hotspot.function_hints.clone(),
            signal_terms: hotspot.signal_terms.clone(),
            score: hotspot.score,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{build_hotspot_plan, filtered_patch_for_files};

    #[test]
    fn builds_digest_and_algorithm_clusters() {
        let patch = r#"diff --git a/src/pk_ec.c b/src/pk_ec.c
index 1111111..2222222 100644
--- a/src/pk_ec.c
+++ b/src/pk_ec.c
@@ -10,6 +10,10 @@ int wolfSSL_ECDSA_verify(...)
+    if ((digestSz > WC_MAX_DIGEST_SIZE) ||
+        (digestSz < WC_MIN_DIGEST_SIZE)) {
+        return BAD_LENGTH_E;
+    }
diff --git a/wolfcrypt/src/asn.c b/wolfcrypt/src/asn.c
index 3333333..4444444 100644
--- a/wolfcrypt/src/asn.c
+++ b/wolfcrypt/src/asn.c
@@ -20,6 +20,8 @@ int ConfirmSignature(...)
+    if (!SigOidMatchesKeyOid(sigOID, keyOID)) {
+        return ASN_SIG_OID_E;
+    }
"#;

        let plan = build_hotspot_plan(patch);
        assert!(
            plan.clusters
                .iter()
                .any(|cluster| cluster.category == "algorithm_binding")
        );
        assert!(
            plan.clusters
                .iter()
                .any(|cluster| cluster.category == "digest_length_verify")
        );
    }

    #[test]
    fn filters_patch_to_selected_files() {
        let patch = r#"diff --git a/src/a.c b/src/a.c
index 1111111..2222222 100644
--- a/src/a.c
+++ b/src/a.c
@@ -1 +1 @@
-old
+new
diff --git a/src/b.c b/src/b.c
index 3333333..4444444 100644
--- a/src/b.c
+++ b/src/b.c
@@ -1 +1 @@
-old
+new
"#;

        let filtered = filtered_patch_for_files(patch, &[String::from("src/b.c")]);
        assert!(filtered.contains("src/b.c"));
        assert!(!filtered.contains("src/a.c"));
    }
}
