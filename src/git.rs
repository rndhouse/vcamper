//! Git CLI integration for collecting commit-range evidence.
//! Ownership: client-only

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use crate::types::{CommitRecord, FileStat};

pub(crate) fn repo_root(repo: &Path) -> Result<PathBuf> {
    let output = run_git(repo, ["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(output.trim()))
}

pub(crate) fn resolve_revision(repo: &Path, revision: &str) -> Result<String> {
    let output = run_git(repo, ["rev-parse", revision])?;
    Ok(output.trim().to_owned())
}

/// Lists commits on the ancestry path from `from` through `to`, including both boundary commits.
///
/// The selected start commit must be an ancestor of the end commit so the range has one clear
/// direction through history.
pub(crate) fn list_commits(repo: &Path, from: &str, to: &str) -> Result<Vec<String>> {
    if from == to {
        return Ok(vec![from.to_owned()]);
    }

    if !is_ancestor(repo, from, to)? {
        bail!(
            "range start {} is not an ancestor of range end {}; choose commits on one ancestry path",
            from,
            to
        );
    }

    let range = format!("{from}..{to}");
    let output = run_git(repo, ["rev-list", "--reverse", &range])?;
    let commits: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    Ok(inclusive_commit_list(from, commits))
}

pub(crate) fn load_commit(
    repo: &Path,
    revision: &str,
    max_patch_bytes: usize,
) -> Result<CommitRecord> {
    let format = "%H%x00%h%x00%P%x00%an%x00%ae%x00%aI%x00%s";
    let meta = run_git(
        repo,
        [
            "show",
            "--no-patch",
            &format!("--format={format}"),
            revision,
        ],
    )?;
    let mut parts = meta.split('\0');

    let id = next_meta(&mut parts, "full commit hash")?;
    let short_id = next_meta(&mut parts, "short commit hash")?;
    let parent_ids = next_meta(&mut parts, "parent ids")?
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    let author_name = next_meta(&mut parts, "author name")?;
    let author_email = next_meta(&mut parts, "author email")?;
    let authored_at = next_meta(&mut parts, "author timestamp")?;
    let summary = next_meta(&mut parts, "summary")?;

    let files_changed = run_git(repo, ["show", "--format=", "--name-only", revision])?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    let file_stats = parse_numstat(&run_git(
        repo,
        ["show", "--format=", "--numstat", revision],
    )?);

    let patch_output = load_full_patch(repo, revision)?;
    let (patch, patch_truncated) = truncate_text(patch_output, max_patch_bytes);

    Ok(CommitRecord {
        id,
        short_id,
        parent_ids,
        author_name,
        author_email,
        authored_at,
        summary,
        files_changed,
        file_stats,
        patch,
        patch_truncated,
    })
}

/// Loads the full unified patch text for one commit without applying prompt-size limits.
pub(crate) fn load_full_patch(repo: &Path, revision: &str) -> Result<String> {
    run_git(
        repo,
        [
            "show",
            "--format=",
            "--patch",
            "--unified=3",
            "--find-renames",
            revision,
        ],
    )
}

/// Loads one tracked file as raw bytes from a specific revision.
///
/// Returns `Ok(None)` when the path does not exist at the requested revision.
pub(crate) fn load_file_at_revision(
    repo: &Path,
    revision: &str,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    let spec = format!("{revision}:{path}");
    if !git_object_exists(repo, &spec)? {
        return Ok(None);
    }

    run_git_bytes(repo, ["show", &spec]).map(Some)
}

fn next_meta<'a, I>(parts: &mut I, label: &'static str) -> Result<String>
where
    I: Iterator<Item = &'a str>,
{
    parts
        .next()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("missing git metadata field: {label}"))
}

fn parse_numstat(output: &str) -> Vec<FileStat> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let additions = parts.next()?;
            let deletions = parts.next()?;
            let path = parts.next()?.trim();
            if path.is_empty() {
                return None;
            }

            Some(FileStat {
                path: path.to_owned(),
                additions: parse_count(additions),
                deletions: parse_count(deletions),
            })
        })
        .collect()
}

fn parse_count(value: &str) -> Option<u64> {
    if value == "-" {
        return None;
    }
    value.parse::<u64>().ok()
}

fn truncate_text(text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }

    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = text[..end].to_owned();
    truncated.push_str("\n\n[vcamper: patch truncated]");
    (truncated, true)
}

/// Returns true when `ancestor` is an ancestor of `descendant`.
fn is_ancestor(repo: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .current_dir(repo)
        .status()
        .with_context(|| {
            format!("failed to start git merge-base --is-ancestor {ancestor} {descendant}")
        })?;

    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "git merge-base --is-ancestor {} {} failed with status {}",
            ancestor,
            descendant,
            status
        ),
    }
}

/// Prepends the inclusive lower bound to a `from..to` commit list.
fn inclusive_commit_list(from: &str, commits: Vec<String>) -> Vec<String> {
    let mut inclusive = Vec::with_capacity(commits.len() + 1);
    inclusive.push(from.to_owned());
    inclusive.extend(commits);
    inclusive
}

/// Returns true when one git object expression resolves successfully.
fn git_object_exists(repo: &Path, spec: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["cat-file", "-e", spec])
        .current_dir(repo)
        .status()
        .with_context(|| format!("failed to start git cat-file -e {spec}"))?;

    match status.code() {
        Some(0) => Ok(true),
        Some(1 | 128) => Ok(false),
        _ => bail!("git cat-file -e {} failed with status {}", spec, status),
    }
}

fn run_git<I, S>(repo: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let collected: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect();
    let output = Command::new("git")
        .args(&collected)
        .current_dir(repo)
        .output()
        .with_context(|| format!("failed to start git {}", collected.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", collected.join(" "), stderr.trim());
    }

    String::from_utf8(output.stdout)
        .map(|value| value.trim_end_matches('\n').to_owned())
        .context("git output was not valid UTF-8")
}

fn run_git_bytes<I, S>(repo: &Path, args: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let collected: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect();
    let output = Command::new("git")
        .args(&collected)
        .current_dir(repo)
        .output()
        .with_context(|| format!("failed to start git {}", collected.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", collected.join(" "), stderr.trim());
    }

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::{inclusive_commit_list, truncate_text};

    #[test]
    fn prepends_lower_bound_for_inclusive_ranges() {
        let commits = inclusive_commit_list("from", vec!["mid".into(), "to".into()]);
        assert_eq!(commits, vec!["from", "mid", "to"]);
    }

    #[test]
    fn inclusive_range_with_same_boundary_keeps_single_commit() {
        let commits = inclusive_commit_list("from", Vec::new());
        assert_eq!(commits, vec!["from"]);
    }

    #[test]
    fn truncates_large_strings_and_marks_them() {
        let input = "abcdef".repeat(5);
        let (truncated, was_truncated) = truncate_text(input, 10);
        assert!(was_truncated);
        assert!(truncated.contains("[vcamper: patch truncated]"));
    }
}
