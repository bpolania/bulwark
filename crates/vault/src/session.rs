//! Session token creation, validation, and persistence.
//!
//! Sessions are the mechanism by which agents authenticate to Bulwark.
//! An operator creates a session with specific scope, receives a token,
//! and gives it to the agent.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A Bulwark session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID (UUID).
    pub id: String,
    /// The session token (presented by the agent). Format: `bwk_sess_<32 hex chars>`.
    pub token: String,
    /// Who created this session (the human operator).
    pub operator: String,
    /// Optional team scope.
    pub team: Option<String>,
    /// Optional project scope.
    pub project: Option<String>,
    /// Optional environment scope.
    pub environment: Option<String>,
    /// Agent type this session is for.
    pub agent_type: Option<String>,
    /// When this session was created.
    pub created_at: DateTime<Utc>,
    /// When this session expires (`None` = no expiry).
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this session has been revoked.
    pub revoked: bool,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// Parameters for creating a new session.
pub struct CreateSessionParams {
    /// Operator name.
    pub operator: String,
    /// Optional team scope.
    pub team: Option<String>,
    /// Optional project scope.
    pub project: Option<String>,
    /// Optional environment scope.
    pub environment: Option<String>,
    /// Agent type.
    pub agent_type: Option<String>,
    /// TTL in seconds (None = no expiry).
    pub ttl_seconds: Option<u64>,
    /// Optional description.
    pub description: Option<String>,
}

/// Generate a session token: `bwk_sess_` + 32 random hex characters.
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rand::Rng::r#gen(&mut rng);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("bwk_sess_{hex}")
}

/// SQLite-backed session store.
pub struct SessionStore {
    db: rusqlite::Connection,
}

impl SessionStore {
    /// Open or create the session database.
    pub fn open(path: &Path) -> bulwark_common::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                bulwark_common::BulwarkError::Vault(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let db = rusqlite::Connection::open(path).map_err(|e| {
            bulwark_common::BulwarkError::Vault(format!("failed to open sessions database: {e}"))
        })?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                operator TEXT NOT NULL,
                team TEXT,
                project TEXT,
                environment TEXT,
                agent_type TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                description TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);",
        )
        .map_err(|e| {
            bulwark_common::BulwarkError::Vault(format!("failed to create sessions table: {e}"))
        })?;

        Ok(Self { db })
    }

    /// Create a new session. Returns the session with its generated token.
    pub fn create(&self, params: CreateSessionParams) -> bulwark_common::Result<Session> {
        let id = uuid::Uuid::new_v4().to_string();
        let token = generate_token();
        let now = Utc::now();
        let expires_at = params
            .ttl_seconds
            .filter(|&ttl| ttl > 0)
            .map(|ttl| now + chrono::Duration::seconds(ttl as i64));

        let session = Session {
            id: id.clone(),
            token: token.clone(),
            operator: params.operator,
            team: params.team,
            project: params.project,
            environment: params.environment,
            agent_type: params.agent_type,
            created_at: now,
            expires_at,
            revoked: false,
            description: params.description,
        };

        self.db
            .execute(
                "INSERT INTO sessions (id, token, operator, team, project, environment, agent_type, created_at, expires_at, revoked, description)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    session.id,
                    session.token,
                    session.operator,
                    session.team,
                    session.project,
                    session.environment,
                    session.agent_type,
                    session.created_at.to_rfc3339(),
                    session.expires_at.map(|t| t.to_rfc3339()),
                    session.revoked as i32,
                    session.description,
                ],
            )
            .map_err(|e| {
                bulwark_common::BulwarkError::Vault(format!("failed to create session: {e}"))
            })?;

        Ok(session)
    }

    /// Validate a token. Returns the session if valid, not expired, and not revoked.
    ///
    /// Returns `None` for invalid, expired, or revoked tokens (no distinction
    /// to prevent token enumeration).
    pub fn validate(&self, token: &str) -> bulwark_common::Result<Option<Session>> {
        if !token.starts_with("bwk_sess_") {
            return Ok(None);
        }

        let result = self.db.query_row(
            "SELECT id, token, operator, team, project, environment, agent_type, created_at, expires_at, revoked, description
             FROM sessions WHERE token = ?1",
            rusqlite::params![token],
            |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    token: row.get(1)?,
                    operator: row.get(2)?,
                    team: row.get(3)?,
                    project: row.get(4)?,
                    environment: row.get(5)?,
                    agent_type: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    revoked: row.get(9)?,
                    description: row.get(10)?,
                })
            },
        );

        match result {
            Ok(row) => {
                let session = row.into_session()?;
                if session.revoked {
                    return Ok(None);
                }
                if let Some(expires) = session.expires_at {
                    if expires < Utc::now() {
                        return Ok(None);
                    }
                }
                Ok(Some(session))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(bulwark_common::BulwarkError::Vault(format!(
                "session lookup error: {e}"
            ))),
        }
    }

    /// List all sessions.
    pub fn list(&self, include_revoked: bool) -> bulwark_common::Result<Vec<Session>> {
        let query = if include_revoked {
            "SELECT id, token, operator, team, project, environment, agent_type, created_at, expires_at, revoked, description FROM sessions ORDER BY created_at DESC"
        } else {
            "SELECT id, token, operator, team, project, environment, agent_type, created_at, expires_at, revoked, description FROM sessions WHERE revoked = 0 ORDER BY created_at DESC"
        };

        let mut stmt = self.db.prepare(query).map_err(|e| {
            bulwark_common::BulwarkError::Vault(format!("failed to prepare query: {e}"))
        })?;

        let rows = stmt
            .query_map([], |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    token: row.get(1)?,
                    operator: row.get(2)?,
                    team: row.get(3)?,
                    project: row.get(4)?,
                    environment: row.get(5)?,
                    agent_type: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    revoked: row.get(9)?,
                    description: row.get(10)?,
                })
            })
            .map_err(|e| bulwark_common::BulwarkError::Vault(format!("session list error: {e}")))?;

        let mut sessions = Vec::new();
        for row in rows {
            let row = row
                .map_err(|e| bulwark_common::BulwarkError::Vault(format!("row read error: {e}")))?;
            sessions.push(row.into_session()?);
        }
        Ok(sessions)
    }

    /// Revoke a session by ID.
    pub fn revoke(&self, session_id: &str) -> bulwark_common::Result<()> {
        let updated = self
            .db
            .execute(
                "UPDATE sessions SET revoked = 1 WHERE id = ?1",
                rusqlite::params![session_id],
            )
            .map_err(|e| {
                bulwark_common::BulwarkError::Vault(format!("failed to revoke session: {e}"))
            })?;

        if updated == 0 {
            return Err(bulwark_common::BulwarkError::Vault(format!(
                "session not found: {session_id}"
            )));
        }
        Ok(())
    }

    /// Clean up expired sessions (delete from DB). Returns the number of rows deleted.
    pub fn cleanup_expired(&self) -> bulwark_common::Result<u64> {
        let now = Utc::now().to_rfc3339();
        let count = self
            .db
            .execute(
                "DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?1",
                rusqlite::params![now],
            )
            .map_err(|e| bulwark_common::BulwarkError::Vault(format!("cleanup error: {e}")))?;
        Ok(count as u64)
    }
}

/// Internal helper for reading session rows from SQLite.
struct SessionRow {
    id: String,
    token: String,
    operator: String,
    team: Option<String>,
    project: Option<String>,
    environment: Option<String>,
    agent_type: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    revoked: i32,
    description: Option<String>,
}

impl SessionRow {
    fn into_session(self) -> bulwark_common::Result<Session> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|e| bulwark_common::BulwarkError::Vault(format!("invalid created_at: {e}")))?
            .with_timezone(&Utc);

        let expires_at = self
            .expires_at
            .map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| {
                        bulwark_common::BulwarkError::Vault(format!("invalid expires_at: {e}"))
                    })
            })
            .transpose()?;

        Ok(Session {
            id: self.id,
            token: self.token,
            operator: self.operator,
            team: self.team,
            project: self.project,
            environment: self.environment,
            agent_type: self.agent_type,
            created_at,
            expires_at,
            revoked: self.revoked != 0,
            description: self.description,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, SessionStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(&dir.path().join("sessions.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn create_session_returns_valid_token() {
        let (_dir, store) = temp_store();
        let session = store
            .create(CreateSessionParams {
                operator: "alice".to_string(),
                team: Some("engineering".to_string()),
                project: None,
                environment: Some("staging".to_string()),
                agent_type: None,
                ttl_seconds: Some(3600),
                description: Some("test".to_string()),
            })
            .unwrap();

        assert!(session.token.starts_with("bwk_sess_"));
        assert_eq!(session.token.len(), 9 + 32); // prefix + 32 hex chars
        assert_eq!(session.operator, "alice");
        assert_eq!(session.team, Some("engineering".to_string()));
        assert!(!session.revoked);
    }

    #[test]
    fn validate_valid_token() {
        let (_dir, store) = temp_store();
        let session = store
            .create(CreateSessionParams {
                operator: "bob".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();

        let validated = store.validate(&session.token).unwrap();
        assert!(validated.is_some());
        assert_eq!(validated.unwrap().operator, "bob");
    }

    #[test]
    fn validate_unknown_token_returns_none() {
        let (_dir, store) = temp_store();
        let result = store
            .validate("bwk_sess_00000000000000000000000000000000")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn validate_invalid_prefix_returns_none() {
        let (_dir, store) = temp_store();
        let result = store.validate("not_a_valid_token").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn validate_expired_token_returns_none() {
        let (_dir, store) = temp_store();
        // Create with 0 TTL (which means no expiry via the filter), so use 1 second.
        let session = store
            .create(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: Some(1),
                description: None,
            })
            .unwrap();

        // Manually set the expires_at to the past.
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        store
            .db
            .execute(
                "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
                rusqlite::params![past, session.id],
            )
            .unwrap();

        let result = store.validate(&session.token).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn validate_revoked_token_returns_none() {
        let (_dir, store) = temp_store();
        let session = store
            .create(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();

        store.revoke(&session.id).unwrap();
        let result = store.validate(&session.token).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_sessions() {
        let (_dir, store) = temp_store();
        store
            .create(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();
        store
            .create(CreateSessionParams {
                operator: "bob".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();

        let all = store.list(true).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_excludes_revoked() {
        let (_dir, store) = temp_store();
        let s1 = store
            .create(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();
        store
            .create(CreateSessionParams {
                operator: "bob".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: None,
                description: None,
            })
            .unwrap();

        store.revoke(&s1.id).unwrap();
        let active = store.list(false).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].operator, "bob");
    }

    #[test]
    fn cleanup_expired_sessions() {
        let (_dir, store) = temp_store();
        let session = store
            .create(CreateSessionParams {
                operator: "alice".to_string(),
                team: None,
                project: None,
                environment: None,
                agent_type: None,
                ttl_seconds: Some(1),
                description: None,
            })
            .unwrap();

        // Set expires_at to the past.
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        store
            .db
            .execute(
                "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
                rusqlite::params![past, session.id],
            )
            .unwrap();

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(store.list(true).unwrap().len(), 0);
    }

    #[test]
    fn token_format_is_correct() {
        let token = generate_token();
        assert!(token.starts_with("bwk_sess_"));
        assert_eq!(token.len(), 9 + 32);
        // Check that the hex part is valid hex.
        let hex_part = &token[9..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
