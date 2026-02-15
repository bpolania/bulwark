//! Query builder for filtering and searching audit events.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{Channel, EventOutcome, EventType};

/// Filter for querying audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by event type.
    #[serde(default)]
    pub event_types: Vec<EventType>,
    /// Filter by outcome.
    #[serde(default)]
    pub outcomes: Vec<EventOutcome>,
    /// Filter by channel.
    #[serde(default)]
    pub channels: Vec<Channel>,
    /// Filter by operator.
    #[serde(default)]
    pub operators: Vec<String>,
    /// Filter by team.
    #[serde(default)]
    pub teams: Vec<String>,
    /// Filter by tool (supports * wildcard).
    pub tool: Option<String>,
    /// Filter by action (supports * wildcard).
    pub action: Option<String>,
    /// Filter by session ID.
    pub session_id: Option<String>,
    /// Filter by credential name.
    pub credential_name: Option<String>,
    /// Events after this timestamp.
    pub after: Option<DateTime<Utc>>,
    /// Events before this timestamp.
    pub before: Option<DateTime<Utc>>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
    /// Sort order.
    #[serde(default)]
    pub sort: SortOrder,
}

/// Sort order for query results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    /// Newest first (default).
    #[default]
    Descending,
    /// Oldest first.
    Ascending,
}

/// Aggregate statistics from the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total number of events.
    pub total_events: u64,
    /// Events by type.
    pub by_event_type: HashMap<String, u64>,
    /// Events by outcome.
    pub by_outcome: HashMap<String, u64>,
    /// Events by channel.
    pub by_channel: HashMap<String, u64>,
    /// Top operators by event count.
    pub top_operators: Vec<(String, u64)>,
    /// Top tools by event count.
    pub top_tools: Vec<(String, u64)>,
    /// Events in the last hour.
    pub last_hour: u64,
    /// Events in the last day.
    pub last_day: u64,
    /// Events in the last week.
    pub last_week: u64,
}

/// Internal: a SQL parameter value.
pub(crate) enum SqlParam {
    /// A string parameter.
    Text(String),
}

impl rusqlite::types::ToSql for SqlParam {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            SqlParam::Text(s) => s.to_sql(),
        }
    }
}

impl AuditFilter {
    /// Build a SQL WHERE clause and parameters from this filter.
    pub(crate) fn to_sql(&self) -> (String, Vec<SqlParam>) {
        let mut conditions = Vec::new();
        let mut params: Vec<SqlParam> = Vec::new();

        if !self.event_types.is_empty() {
            let placeholders: Vec<String> = self
                .event_types
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("event_type IN ({})", placeholders.join(",")));
            for et in &self.event_types {
                let s = serde_json::to_value(et)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                params.push(SqlParam::Text(s));
            }
        }

        if !self.outcomes.is_empty() {
            let placeholders: Vec<String> = self
                .outcomes
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("outcome IN ({})", placeholders.join(",")));
            for o in &self.outcomes {
                let s = serde_json::to_value(o)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                params.push(SqlParam::Text(s));
            }
        }

        if !self.channels.is_empty() {
            let placeholders: Vec<String> = self
                .channels
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("channel IN ({})", placeholders.join(",")));
            for c in &self.channels {
                let s = serde_json::to_value(c)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                params.push(SqlParam::Text(s));
            }
        }

        if !self.operators.is_empty() {
            let placeholders: Vec<String> = self
                .operators
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("operator IN ({})", placeholders.join(",")));
            for o in &self.operators {
                params.push(SqlParam::Text(o.clone()));
            }
        }

        if !self.teams.is_empty() {
            let placeholders: Vec<String> = self
                .teams
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", params.len() + i + 1))
                .collect();
            conditions.push(format!("team IN ({})", placeholders.join(",")));
            for t in &self.teams {
                params.push(SqlParam::Text(t.clone()));
            }
        }

        if let Some(ref tool) = self.tool {
            conditions.push(format!("tool LIKE ?{}", params.len() + 1));
            params.push(SqlParam::Text(tool.replace('*', "%")));
        }

        if let Some(ref action) = self.action {
            conditions.push(format!("action LIKE ?{}", params.len() + 1));
            params.push(SqlParam::Text(action.replace('*', "%")));
        }

        if let Some(ref sid) = self.session_id {
            conditions.push(format!("session_id = ?{}", params.len() + 1));
            params.push(SqlParam::Text(sid.clone()));
        }

        if let Some(ref cn) = self.credential_name {
            conditions.push(format!("credential_name = ?{}", params.len() + 1));
            params.push(SqlParam::Text(cn.clone()));
        }

        if let Some(ref after) = self.after {
            conditions.push(format!("timestamp >= ?{}", params.len() + 1));
            params.push(SqlParam::Text(after.to_rfc3339()));
        }

        if let Some(ref before) = self.before {
            conditions.push(format!("timestamp <= ?{}", params.len() + 1));
            params.push(SqlParam::Text(before.to_rfc3339()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        (where_clause, params)
    }

    /// Build the ORDER BY + LIMIT + OFFSET clause.
    pub(crate) fn order_limit_sql(&self) -> String {
        let order = match self.sort {
            SortOrder::Descending => "ORDER BY timestamp DESC",
            SortOrder::Ascending => "ORDER BY timestamp ASC",
        };
        let limit = self
            .limit
            .map(|l| format!(" LIMIT {l}"))
            .unwrap_or_default();
        let offset = self
            .offset
            .map(|o| format!(" OFFSET {o}"))
            .unwrap_or_default();
        format!("{order}{limit}{offset}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_produces_no_where() {
        let filter = AuditFilter::default();
        let (clause, params) = filter.to_sql();
        assert!(clause.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn single_event_type_filter() {
        let filter = AuditFilter {
            event_types: vec![EventType::RequestProcessed],
            ..Default::default()
        };
        let (clause, params) = filter.to_sql();
        assert!(clause.contains("event_type IN"));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn multiple_filters_produce_and() {
        let filter = AuditFilter {
            event_types: vec![EventType::RequestProcessed],
            outcomes: vec![EventOutcome::Denied],
            ..Default::default()
        };
        let (clause, _) = filter.to_sql();
        assert!(clause.contains(" AND "));
    }

    #[test]
    fn time_range_filter() {
        let filter = AuditFilter {
            after: Some(Utc::now() - chrono::Duration::hours(1)),
            before: Some(Utc::now()),
            ..Default::default()
        };
        let (clause, params) = filter.to_sql();
        assert!(clause.contains("timestamp >="));
        assert!(clause.contains("timestamp <="));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn glob_to_like_conversion() {
        let filter = AuditFilter {
            tool: Some("github__*".into()),
            ..Default::default()
        };
        let (clause, params) = filter.to_sql();
        assert!(clause.contains("tool LIKE"));
        match &params[0] {
            SqlParam::Text(s) => assert_eq!(s, "github__%"),
        }
    }

    #[test]
    fn order_limit_offset() {
        let filter = AuditFilter {
            limit: Some(10),
            offset: Some(20),
            sort: SortOrder::Ascending,
            ..Default::default()
        };
        let sql = filter.order_limit_sql();
        assert!(sql.contains("ASC"));
        assert!(sql.contains("LIMIT 10"));
        assert!(sql.contains("OFFSET 20"));
    }
}
