//! `bulwark session` — session management commands.

use std::path::Path;

use anyhow::{Context, Result};
use bulwark_config::load_config;
use bulwark_vault::session::CreateSessionParams;
use bulwark_vault::store::Vault;

/// Create a new session.
#[allow(clippy::too_many_arguments)]
pub fn create(
    config_path: &Path,
    operator: &str,
    team: Option<&str>,
    project: Option<&str>,
    environment: Option<&str>,
    agent_type: Option<&str>,
    ttl: Option<u64>,
    description: Option<&str>,
) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    let params = CreateSessionParams {
        operator: operator.to_string(),
        team: team.map(String::from),
        project: project.map(String::from),
        environment: environment.map(String::from),
        agent_type: agent_type.map(String::from),
        ttl_seconds: ttl,
        description: description.map(String::from),
    };

    let session = vault.create_session(params).context("creating session")?;

    println!("Session created:");
    println!("  ID:       {}", session.id);
    println!("  Token:    {}", session.token);
    println!("  Operator: {}", session.operator);
    if let Some(ref team) = session.team {
        println!("  Team:     {team}");
    }
    if let Some(ref project) = session.project {
        println!("  Project:  {project}");
    }
    if let Some(ref env) = session.environment {
        println!("  Env:      {env}");
    }
    if let Some(ref expires) = session.expires_at {
        println!("  Expires:  {expires}");
    }
    println!();
    println!("Give the token to the agent. Set it as:");
    println!("  HTTP: X-Bulwark-Session: {}", session.token);
    println!("  MCP:  via initialize params");

    Ok(())
}

/// List sessions.
pub fn list(config_path: &Path, include_revoked: bool) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    let sessions = vault
        .list_sessions(include_revoked)
        .context("listing sessions")?;

    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    println!(
        "{:<38} {:<12} {:<10} {:<10} CREATED",
        "ID", "OPERATOR", "TEAM", "STATUS"
    );
    println!("{}", "-".repeat(90));
    for s in &sessions {
        let status = if s.revoked {
            "revoked"
        } else if s.expires_at.is_some_and(|e| e < chrono::Utc::now()) {
            "expired"
        } else {
            "active"
        };
        let team = s.team.as_deref().unwrap_or("-");
        println!(
            "{:<38} {:<12} {:<10} {:<10} {}",
            s.id,
            s.operator,
            team,
            status,
            s.created_at.format("%Y-%m-%d %H:%M")
        );
    }
    Ok(())
}

/// Revoke a session.
pub fn revoke(config_path: &Path, session_id: &str) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let vault = Vault::open(&config.vault).context("opening vault")?;

    vault
        .revoke_session(session_id)
        .context("revoking session")?;

    println!("Session '{session_id}' revoked.");
    Ok(())
}
