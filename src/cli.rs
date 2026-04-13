//! Command-line interface for VCamper.
//! Ownership: client-only

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Top-level VCamper CLI options.
#[derive(Debug, Parser)]
#[command(
    name = "vcamper",
    version,
    about = "Analyze Git release ranges for likely silent security patches"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

/// Supported VCamper commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    Analyze(AnalyzeArgs),
}

/// Analyze a commit range for suspicious security-relevant commits.
#[derive(Debug, Args, Clone)]
pub(crate) struct AnalyzeArgs {
    /// Git repository to inspect.
    #[arg(long)]
    pub(crate) repo: PathBuf,

    /// Older release commit or tag. Included in the analysis range.
    #[arg(long)]
    pub(crate) from: String,

    /// Newer release commit or tag. Included in the analysis range.
    #[arg(long)]
    pub(crate) to: String,

    /// Agent CLI provider to invoke.
    #[arg(long, value_enum)]
    pub(crate) provider: ProviderKind,

    /// Explicit model name to pass to the provider CLI.
    #[arg(long)]
    pub(crate) model: Option<String>,

    /// Reasoning effort to request from the selected provider when supported.
    #[arg(long, value_enum)]
    pub(crate) effort: Option<ReasoningEffort>,

    /// Screening-pass reasoning effort. Overrides `--effort` for the first pass.
    #[arg(long, value_enum)]
    pub(crate) screen_effort: Option<ReasoningEffort>,

    /// Verification-pass reasoning effort. Overrides `--effort` for the second pass.
    #[arg(long, value_enum)]
    pub(crate) verify_effort: Option<ReasoningEffort>,

    /// Maximum commits allowed in the selected range.
    #[arg(long)]
    pub(crate) max_commits: Option<usize>,

    /// Maximum diff bytes to include per commit in the prompt bundle.
    #[arg(long, default_value_t = 40_000)]
    pub(crate) max_patch_bytes: usize,

    /// Minimum confidence required for a finding to appear in the final report.
    #[arg(long, default_value_t = 0.65)]
    pub(crate) min_confidence: f32,

    /// Write run artifacts into this directory.
    #[arg(long)]
    pub(crate) out: PathBuf,

    /// Print detailed internal logs and streamed provider output.
    #[arg(long, default_value_t = false)]
    pub(crate) verbose: bool,

    /// Render prompts and Git evidence without invoking an agent CLI.
    #[arg(long, default_value_t = false)]
    pub(crate) dry_run: bool,

    /// Stop after the selected staged analysis step instead of running the full pipeline.
    #[arg(long, value_enum)]
    pub(crate) stop_after_stage: Option<PipelineStage>,

    /// Start execution at the selected staged analysis step and reuse earlier artifacts.
    #[arg(long, value_enum)]
    pub(crate) start_at_stage: Option<PipelineStage>,

    /// Restrict Codex inventory to specific hotspot focus indexes.
    #[arg(long, value_delimiter = ',')]
    pub(crate) inventory_focuses: Vec<usize>,

    /// Force rerunning the selected stages and all later dependent stages.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) rerun_stages: Vec<PipelineStage>,
}

/// Agent providers supported by the CLI proof of concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ProviderKind {
    Codex,
    Claude,
}

impl ProviderKind {
    /// Returns the provider name expected by manifests and logs.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

/// Reasoning effort level for supported agent providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReasoningEffort {
    Low,
    Medium,
    High,
    Xhigh,
}

/// Staged analysis boundary used for partial Codex runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PipelineStage {
    Inventory,
    Synthesis,
    Interaction,
    #[value(name = "composite_synthesis")]
    CompositeSynthesis,
    Reachability,
    Verify,
}

impl PipelineStage {
    /// Returns the lowercase stage label used in manifests and logs.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Synthesis => "synthesis",
            Self::Interaction => "interaction",
            Self::CompositeSynthesis => "composite_synthesis",
            Self::Reachability => "reachability",
            Self::Verify => "verify",
        }
    }

    /// Returns the fixed pipeline order for stage comparisons.
    pub(crate) fn order(self) -> usize {
        match self {
            Self::Inventory => 0,
            Self::Synthesis => 1,
            Self::Interaction => 2,
            Self::CompositeSynthesis => 3,
            Self::Reachability => 4,
            Self::Verify => 5,
        }
    }
}

impl ReasoningEffort {
    /// Returns the provider-specific lowercase effort string.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
        }
    }
}

impl AnalyzeArgs {
    /// Returns the effective reasoning effort for the screening pass.
    pub(crate) fn resolved_screen_effort(&self) -> Option<ReasoningEffort> {
        self.screen_effort.or(self.effort)
    }

    /// Returns the effective reasoning effort for the verification pass.
    pub(crate) fn resolved_verify_effort(&self) -> Option<ReasoningEffort> {
        self.verify_effort.or(self.effort)
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, PipelineStage};
    use clap::Parser;

    #[test]
    fn analyze_has_no_grouping_flags() {
        let cli = Cli::parse_from([
            "vcamper",
            "analyze",
            "--repo",
            ".",
            "--from",
            "a",
            "--to",
            "b",
            "--provider",
            "codex",
            "--out",
            "out",
        ]);

        let Commands::Analyze(args) = cli.command;
        assert_eq!(args.max_patch_bytes, 40_000);
        assert_eq!(args.min_confidence, 0.65);
        assert_eq!(args.stop_after_stage, None);
        assert_eq!(args.start_at_stage, None);
        assert!(args.inventory_focuses.is_empty());
        assert!(args.rerun_stages.is_empty());
    }

    #[test]
    fn analyze_parses_stop_after_stage() {
        let cli = Cli::parse_from([
            "vcamper",
            "analyze",
            "--repo",
            ".",
            "--from",
            "a",
            "--to",
            "b",
            "--provider",
            "codex",
            "--out",
            "out",
            "--stop-after-stage",
            "inventory",
        ]);

        let Commands::Analyze(args) = cli.command;
        assert_eq!(args.stop_after_stage, Some(PipelineStage::Inventory));
    }

    #[test]
    fn analyze_parses_start_at_stage() {
        let cli = Cli::parse_from([
            "vcamper",
            "analyze",
            "--repo",
            ".",
            "--from",
            "a",
            "--to",
            "b",
            "--provider",
            "codex",
            "--out",
            "out",
            "--start-at-stage",
            "interaction",
        ]);

        let Commands::Analyze(args) = cli.command;
        assert_eq!(args.start_at_stage, Some(PipelineStage::Interaction));
    }

    #[test]
    fn analyze_parses_inventory_focuses() {
        let cli = Cli::parse_from([
            "vcamper",
            "analyze",
            "--repo",
            ".",
            "--from",
            "a",
            "--to",
            "b",
            "--provider",
            "codex",
            "--out",
            "out",
            "--inventory-focuses",
            "0,1,4,9",
        ]);

        let Commands::Analyze(args) = cli.command;
        assert_eq!(args.inventory_focuses, vec![0, 1, 4, 9]);
    }

    #[test]
    fn analyze_parses_rerun_stages() {
        let cli = Cli::parse_from([
            "vcamper",
            "analyze",
            "--repo",
            ".",
            "--from",
            "a",
            "--to",
            "b",
            "--provider",
            "codex",
            "--out",
            "out",
            "--rerun-stages",
            "interaction,verify",
        ]);

        let Commands::Analyze(args) = cli.command;
        assert_eq!(
            args.rerun_stages,
            vec![PipelineStage::Interaction, PipelineStage::Verify]
        );
    }

    #[test]
    fn analyze_parses_composite_synthesis_stage() {
        let cli = Cli::parse_from([
            "vcamper",
            "analyze",
            "--repo",
            ".",
            "--from",
            "a",
            "--to",
            "b",
            "--provider",
            "codex",
            "--out",
            "out",
            "--start-at-stage",
            "composite_synthesis",
        ]);

        let Commands::Analyze(args) = cli.command;
        assert_eq!(args.start_at_stage, Some(PipelineStage::CompositeSynthesis));
    }
}
