mod app;
mod cli;
mod git;
mod prompt;
mod provider;
mod report;
mod types;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    app::run(cli)
}
