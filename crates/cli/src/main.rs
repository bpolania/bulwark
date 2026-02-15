//! Bulwark CLI — binary entry point for the `bulwark` command.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

/// Governance layer for AI agents.
#[derive(Parser)]
#[command(name = "bulwark", about = "Governance layer for AI agents", version)]
struct Cli {
    /// Path to config file.
    #[arg(long, default_value = "bulwark.yaml", global = true)]
    config: PathBuf,

    /// Override the log level (trace, debug, info, warn, error).
    #[arg(long, global = true)]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the governance proxy.
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Initialize a new Bulwark project.
    Init {
        /// Directory to initialize (defaults to current directory).
        path: Option<PathBuf>,
    },
    /// Manage the Bulwark CA certificate.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Run the MCP governance gateway.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Print the CA certificate PEM to stdout.
    Export,
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the MCP gateway (stdio mode).
    Start,
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Start the proxy server.
    Start {
        /// Override the listen address (e.g. 127.0.0.1:9090).
        #[arg(long)]
        listen: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy { action } => match action {
            ProxyAction::Start { listen } => {
                commands::proxy::start(&cli.config, cli.log_level.as_deref(), listen.as_deref())
            }
        },
        Commands::Init { path } => commands::init::run(path.as_deref()),
        Commands::Ca { action } => match action {
            CaAction::Export => commands::ca::export(&cli.config),
        },
        Commands::Mcp { action } => match action {
            McpAction::Start => commands::mcp::start(&cli.config, cli.log_level.as_deref()),
        },
    }
}
