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
    /// Manage policies.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Manage vault credentials.
    Cred {
        #[command(subcommand)]
        action: CredAction,
    },
    /// Manage sessions.
    Session {
        #[command(subcommand)]
        action: SessionAction,
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
enum PolicyAction {
    /// Validate policy files in a directory.
    Validate {
        /// Path to the policies directory.
        #[arg(default_value = "./policies")]
        path: PathBuf,
    },
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

#[derive(Subcommand)]
enum CredAction {
    /// Add a new credential to the vault.
    Add {
        /// Credential name (e.g. github-token).
        name: String,
        /// Credential type: bearer, basic, api-key, custom-header.
        #[arg(long, default_value = "bearer")]
        r#type: String,
        /// Description of this credential.
        #[arg(long)]
        description: Option<String>,
        /// For api-key / custom-header: the header name.
        #[arg(long)]
        header: Option<String>,
        /// For basic auth: the username.
        #[arg(long)]
        username: Option<String>,
    },
    /// List all credentials in the vault.
    List,
    /// Remove a credential from the vault.
    Remove {
        /// Credential name to remove.
        name: String,
    },
    /// Test credential resolution for a tool + session.
    Test {
        /// Tool name (e.g. github__push).
        tool: String,
        /// Session token.
        #[arg(long)]
        session: String,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// Create a new session.
    Create {
        /// Operator name.
        #[arg(long)]
        operator: String,
        /// Team.
        #[arg(long)]
        team: Option<String>,
        /// Project.
        #[arg(long)]
        project: Option<String>,
        /// Environment (e.g. staging, production).
        #[arg(long)]
        environment: Option<String>,
        /// Agent type (e.g. coding, research).
        #[arg(long)]
        agent_type: Option<String>,
        /// Time-to-live in seconds.
        #[arg(long)]
        ttl: Option<u64>,
        /// Description.
        #[arg(long)]
        description: Option<String>,
    },
    /// List active sessions.
    List {
        /// Include revoked sessions.
        #[arg(long)]
        all: bool,
    },
    /// Revoke a session.
    Revoke {
        /// Session ID to revoke.
        id: String,
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
        Commands::Policy { action } => match action {
            PolicyAction::Validate { path } => commands::policy::validate(&path),
        },
        Commands::Cred { action } => match action {
            CredAction::Add {
                name,
                r#type,
                description,
                header,
                username,
            } => commands::cred::add(
                &cli.config,
                &name,
                &r#type,
                description.as_deref(),
                header.as_deref(),
                username.as_deref(),
            ),
            CredAction::List => commands::cred::list(&cli.config),
            CredAction::Remove { name } => commands::cred::remove(&cli.config, &name),
            CredAction::Test { tool, session } => {
                commands::cred::test_resolve(&cli.config, &tool, &session)
            }
        },
        Commands::Session { action } => match action {
            SessionAction::Create {
                operator,
                team,
                project,
                environment,
                agent_type,
                ttl,
                description,
            } => commands::session::create(
                &cli.config,
                &operator,
                team.as_deref(),
                project.as_deref(),
                environment.as_deref(),
                agent_type.as_deref(),
                ttl,
                description.as_deref(),
            ),
            SessionAction::List { all } => commands::session::list(&cli.config, all),
            SessionAction::Revoke { id } => commands::session::revoke(&cli.config, &id),
        },
    }
}
