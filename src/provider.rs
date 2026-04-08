//! Agent CLI adapters used by VCamper.
//! Ownership: client-only

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::cli::{ProviderKind, ReasoningEffort};
use crate::types::{ScreeningAnalysis, VerificationAnalysis};

/// Provider invocation request for one commit candidate.
pub(crate) struct ProviderRequest<'a> {
    /// Repository root used as the provider working directory.
    pub(crate) repo_root: &'a Path,
    /// Rendered prompt text.
    pub(crate) prompt: &'a str,
    /// JSON schema for structured output.
    pub(crate) schema: &'a str,
    /// Artifact directory for this pass.
    pub(crate) pass_dir: &'a Path,
    /// Zero-based candidate index within the run.
    pub(crate) candidate_index: usize,
    /// Analysis phase represented by this request.
    pub(crate) phase: AnalysisPhase,
    /// Optional explicit model override.
    pub(crate) model: Option<&'a str>,
    /// Optional reasoning-effort override.
    pub(crate) effort: Option<ReasoningEffort>,
    /// Whether verbose terminal output is enabled.
    pub(crate) verbose: bool,
}

/// Analysis phase handled by the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnalysisPhase {
    /// First-pass commit screening.
    Screen,
    /// Second-pass skeptical verification.
    Verify,
}

impl AnalysisPhase {
    /// Returns the lowercase phase label used in logs and artifact names.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Screen => "screen",
            Self::Verify => "verify",
        }
    }
}

/// Provider interface for one-commit candidate analysis.
pub(crate) trait AgentProvider {
    /// Runs the first-pass screener for one commit candidate.
    fn screen_candidate(&self, request: ProviderRequest<'_>) -> Result<ScreeningAnalysis>;

    /// Runs the second-pass verifier for one commit candidate.
    fn verify_candidate(&self, request: ProviderRequest<'_>) -> Result<VerificationAnalysis>;
}

/// Builds the selected provider adapter.
pub(crate) fn build_provider(kind: ProviderKind) -> Box<dyn AgentProvider> {
    match kind {
        ProviderKind::Codex => Box::new(CodexProvider),
        ProviderKind::Claude => Box::new(ClaudeProvider),
    }
}

/// Returns the structured output schema required from screening passes.
pub(crate) fn screening_schema() -> Result<String> {
    Ok(serde_json::to_string_pretty(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "candidate_summary": { "type": "string" },
            "suspicious_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "title": { "type": "string" },
                        "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                        "commit_id": { "type": "string" },
                        "rationale": { "type": "string" },
                        "likely_bug_class": { "type": ["string", "null"] },
                        "affected_files": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "evidence": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "follow_up": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    },
                    "required": [
                        "title",
                        "confidence",
                        "commit_id",
                        "rationale",
                        "likely_bug_class",
                        "affected_files",
                        "evidence",
                        "follow_up"
                    ]
                }
            }
        },
        "required": ["candidate_summary", "suspicious_findings"]
    }))?)
}

/// Returns the structured output schema required from verification passes.
pub(crate) fn verification_schema() -> Result<String> {
    Ok(serde_json::to_string_pretty(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "verification_summary": { "type": "string" },
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "rejected", "inconclusive"]
            },
            "confirmed_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "title": { "type": "string" },
                        "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                        "commit_id": { "type": "string" },
                        "rationale": { "type": "string" },
                        "likely_bug_class": { "type": ["string", "null"] },
                        "affected_files": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "evidence": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "follow_up": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    },
                    "required": [
                        "title",
                        "confidence",
                        "commit_id",
                        "rationale",
                        "likely_bug_class",
                        "affected_files",
                        "evidence",
                        "follow_up"
                    ]
                }
            }
        },
        "required": ["verification_summary", "verdict", "confirmed_findings"]
    }))?)
}

/// Codex CLI adapter.
struct CodexProvider;

impl AgentProvider for CodexProvider {
    fn screen_candidate(&self, request: ProviderRequest<'_>) -> Result<ScreeningAnalysis> {
        run_codex_structured(request)
    }

    fn verify_candidate(&self, request: ProviderRequest<'_>) -> Result<VerificationAnalysis> {
        run_codex_structured(request)
    }
}

/// Claude CLI adapter.
struct ClaudeProvider;

impl AgentProvider for ClaudeProvider {
    fn screen_candidate(&self, request: ProviderRequest<'_>) -> Result<ScreeningAnalysis> {
        run_claude_structured(request)
    }

    fn verify_candidate(&self, request: ProviderRequest<'_>) -> Result<VerificationAnalysis> {
        run_claude_structured(request)
    }
}

/// Runs one structured Codex CLI invocation and parses its typed result.
fn run_codex_structured<T>(request: ProviderRequest<'_>) -> Result<T>
where
    T: DeserializeOwned,
{
    let schema_path = request.pass_dir.join("schema.json");
    let response_path = request.pass_dir.join("response.json");
    fs::write(&schema_path, request.schema)
        .with_context(|| format!("failed to write {}", schema_path.display()))?;

    let mut command = Command::new("codex");
    command
        .arg("exec")
        .arg("--cd")
        .arg(request.repo_root)
        .arg("--sandbox")
        .arg("read-only")
        .arg("--skip-git-repo-check")
        .arg("--json")
        .arg("--output-schema")
        .arg(&schema_path)
        .arg("--output-last-message")
        .arg(&response_path)
        .arg("-");

    if let Some(model) = request.model {
        command.arg("--model").arg(model);
    }
    if let Some(effort) = request.effort {
        command
            .arg("-c")
            .arg(format!("model_reasoning_effort=\"{}\"", effort.as_str()));
    }

    log_provider(
        "codex",
        request.phase,
        request.candidate_index,
        request.model,
        request.effort,
        request.verbose,
    );
    let output = run_command(
        command,
        Some(request.prompt),
        request.pass_dir,
        "codex",
        request.phase,
        request.candidate_index,
        request.verbose,
    )?;
    ensure_success(&output)?;

    let raw = fs::read_to_string(&response_path)
        .with_context(|| format!("failed to read {}", response_path.display()))?;
    rewrite_json_file_pretty(&response_path, &raw)?;
    parse_structured_output(&raw)
}

/// Runs one structured Claude CLI invocation and parses its typed result.
fn run_claude_structured<T>(request: ProviderRequest<'_>) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut command = Command::new("claude");
    command
        .arg("-p")
        .arg("--output-format")
        .arg("json")
        .arg("--json-schema")
        .arg(request.schema)
        .arg("--permission-mode")
        .arg("default")
        .arg("--tools")
        .arg("");

    if let Some(model) = request.model {
        command.arg("--model").arg(model);
    }
    if let Some(effort) = request.effort {
        command.arg("--effort").arg(effort.as_str());
    }

    log_provider(
        "claude",
        request.phase,
        request.candidate_index,
        request.model,
        request.effort,
        request.verbose,
    );
    let output = run_command(
        command,
        Some(request.prompt),
        request.pass_dir,
        "claude",
        request.phase,
        request.candidate_index,
        request.verbose,
    )?;
    ensure_success(&output)?;
    let raw = String::from_utf8(output.stdout).context("claude stdout was not valid UTF-8")?;
    parse_structured_output(&raw)
}

/// Captured provider process output.
struct CapturedOutput {
    /// Captured stdout bytes.
    stdout: Vec<u8>,
    /// Captured stderr bytes.
    stderr: Vec<u8>,
    /// Process exit status.
    status: ExitStatus,
}

/// Runs a provider command and captures its streamed output.
fn run_command(
    mut command: Command,
    stdin: Option<&str>,
    pass_dir: &Path,
    provider: &str,
    phase: AnalysisPhase,
    candidate_index: usize,
    verbose: bool,
) -> Result<CapturedOutput> {
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to launch {:?}", command))?;

    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("stdin pipe was unavailable"))?
            .write_all(input.as_bytes())
            .context("failed to write provider prompt")?;
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("stderr pipe was unavailable"))?;

    let stdout_thread = stream_pipe(
        stdout,
        pass_dir.join("stdout.txt"),
        format!("{provider}:{}:{candidate_index:04}:stdout", phase.as_str()),
        verbose,
    );
    let stderr_thread = stream_pipe(
        stderr,
        pass_dir.join("stderr.txt"),
        format!("{provider}:{}:{candidate_index:04}:stderr", phase.as_str()),
        verbose,
    );

    let status = child.wait().context("failed to wait for provider")?;
    let stdout = stdout_thread
        .join()
        .map_err(|_| anyhow!("stdout stream thread panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| anyhow!("stderr stream thread panicked"))??;

    Ok(CapturedOutput {
        stdout,
        stderr,
        status,
    })
}

/// Fails when the provider process exits unsuccessfully.
fn ensure_success(output: &CapturedOutput) -> Result<()> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("provider command failed: {}", stderr.trim());
    }

    Ok(())
}

/// Writes a verbose provider-launch log line.
fn log_provider(
    provider: &str,
    phase: AnalysisPhase,
    candidate_index: usize,
    model: Option<&str>,
    effort: Option<ReasoningEffort>,
    verbose: bool,
) {
    if !verbose {
        return;
    }

    let model = model.unwrap_or("provider default");
    let effort = effort
        .map(ReasoningEffort::as_str)
        .unwrap_or("provider default");
    eprintln!(
        "[vcamper:provider] launching {provider} {phase} pass for candidate {candidate_index:04} with model={model} effort={effort}",
        phase = phase.as_str(),
    );
}

/// Streams one provider pipe to disk and, when verbose, to stderr.
fn stream_pipe<R>(
    reader: R,
    path: PathBuf,
    prefix: String,
    verbose: bool,
) -> thread::JoinHandle<Result<Vec<u8>>>
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || -> Result<Vec<u8>> {
        let mut reader = BufReader::new(reader);
        let mut writer =
            File::create(&path).with_context(|| format!("failed to create {}", path.display()))?;
        let mut collected = Vec::new();

        loop {
            let mut line = Vec::new();
            let bytes = reader.read_until(b'\n', &mut line)?;
            if bytes == 0 {
                break;
            }

            let file_render = render_json_pretty_or_original(&line);
            writer.write_all(file_render.as_bytes())?;
            writer.flush()?;
            collected.extend_from_slice(&line);

            let terminal_render = render_json_pretty_or_original(&line);
            if verbose {
                print_prefixed(&prefix, &terminal_render);
            }
        }

        Ok(collected)
    })
}

/// Rewrites one JSON file in pretty-printed form when the file contains valid JSON.
fn rewrite_json_file_pretty(path: &Path, raw: &str) -> Result<()> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Ok(());
    };

    fs::write(path, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("failed to rewrite {} as pretty JSON", path.display()))
}

/// Pretty-prints one JSON event line when possible.
fn render_json_pretty_or_original(bytes: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(bytes).trim().to_owned();
    if trimmed.is_empty() {
        return String::new();
    }

    match serde_json::from_str::<Value>(&trimmed) {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(pretty) => format!("{pretty}\n"),
            Err(_) => String::from_utf8_lossy(bytes).into_owned(),
        },
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Prints a streamed provider line with a prefix.
fn print_prefixed(prefix: &str, text: &str) {
    for line in text.lines() {
        eprintln!("[vcamper:{prefix}] {line}");
    }
}

/// Parses one structured provider object from provider output.
fn parse_structured_output<T>(raw: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    if let Ok(direct) = serde_json::from_str::<T>(raw) {
        return Ok(direct);
    }

    let value: Value = serde_json::from_str(raw).context("provider output was not valid JSON")?;
    if let Some(parsed) = extract_structured_output(value) {
        return Ok(parsed);
    }

    Err(anyhow!(
        "provider output did not contain a matching structured object"
    ))
}

/// Extracts the first nested structured object that matches the requested type.
fn extract_structured_output<T>(value: Value) -> Option<T>
where
    T: DeserializeOwned,
{
    if let Ok(parsed) = serde_json::from_value::<T>(value.clone()) {
        return Some(parsed);
    }

    ["result", "response", "output", "data"]
        .iter()
        .filter_map(|key| value.get(*key).cloned())
        .find_map(|nested| {
            if let Ok(parsed) = serde_json::from_value::<T>(nested.clone()) {
                Some(parsed)
            } else if let Some(text) = nested.as_str() {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .and_then(extract_structured_output::<T>)
            } else if nested.is_object() {
                extract_structured_output::<T>(nested)
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::parse_structured_output;
    use crate::types::{ScreeningAnalysis, VerificationAnalysis, VerificationVerdict};

    #[test]
    fn parses_direct_screening_output() {
        let raw = r#"{
          "candidate_summary": "one suspicious finding",
          "suspicious_findings": [{
            "title": "validation tightening",
            "confidence": 0.91,
            "commit_id": "a",
            "rationale": "boundary validation",
            "likely_bug_class": "input validation",
            "affected_files": ["src/lib.rs"],
            "evidence": ["adds validation"],
            "follow_up": ["check release notes"]
          }]
        }"#;
        let parsed: ScreeningAnalysis =
            parse_structured_output(raw).expect("schema output should parse");
        assert_eq!(parsed.suspicious_findings.len(), 1);
    }

    #[test]
    fn parses_nested_verification_output() {
        let raw = r#"{
          "result": {
            "verification_summary": "confirmed",
            "verdict": "confirmed",
            "confirmed_findings": []
          }
        }"#;
        let parsed: VerificationAnalysis =
            parse_structured_output(raw).expect("verification output should parse");
        assert_eq!(parsed.verdict, VerificationVerdict::Confirmed);
    }
}
