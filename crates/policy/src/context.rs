//! Request context — the input to every policy evaluation.

use std::collections::HashMap;

/// Context describing a request to be evaluated against policies.
///
/// Constructed by the proxy or MCP gateway before calling the policy engine.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The tool or service being accessed (e.g. `"github"`, `"api.example.com"`).
    pub tool: String,
    /// The action being performed (e.g. `"create_issue"`, `"GET /repos"`).
    pub action: String,
    /// Optional resource being accessed (e.g. a repo name, file path).
    pub resource: Option<String>,
    /// The operator (human or service account) making the request.
    pub operator: Option<String>,
    /// The team the operator belongs to.
    pub team: Option<String>,
    /// The project context.
    pub project: Option<String>,
    /// The environment (e.g. `"production"`, `"staging"`).
    pub environment: Option<String>,
    /// The type of agent making the request (e.g. `"coding"`, `"research"`).
    pub agent_type: Option<String>,
    /// Arbitrary key-value labels for matching.
    pub labels: HashMap<String, String>,
}

impl RequestContext {
    /// Create a new context with the required tool and action fields.
    pub fn new(tool: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            action: action.into(),
            resource: None,
            operator: None,
            team: None,
            project: None,
            environment: None,
            agent_type: None,
            labels: HashMap::new(),
        }
    }

    /// Set the resource.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Set the operator.
    pub fn with_operator(mut self, operator: impl Into<String>) -> Self {
        self.operator = Some(operator.into());
        self
    }

    /// Set the team.
    pub fn with_team(mut self, team: impl Into<String>) -> Self {
        self.team = Some(team.into());
        self
    }

    /// Set the project.
    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Set the environment.
    pub fn with_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Set the agent type.
    pub fn with_agent_type(mut self, agent_type: impl Into<String>) -> Self {
        self.agent_type = Some(agent_type.into());
        self
    }

    /// Add a label.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_required_fields() {
        let ctx = RequestContext::new("github", "create_issue");
        assert_eq!(ctx.tool, "github");
        assert_eq!(ctx.action, "create_issue");
        assert!(ctx.resource.is_none());
        assert!(ctx.labels.is_empty());
    }

    #[test]
    fn builder_methods_chain() {
        let ctx = RequestContext::new("github", "read_file")
            .with_resource("my-repo")
            .with_operator("alice")
            .with_team("platform")
            .with_environment("production");

        assert_eq!(ctx.resource.as_deref(), Some("my-repo"));
        assert_eq!(ctx.operator.as_deref(), Some("alice"));
        assert_eq!(ctx.team.as_deref(), Some("platform"));
        assert_eq!(ctx.environment.as_deref(), Some("production"));
    }

    #[test]
    fn labels_are_stored() {
        let ctx = RequestContext::new("api", "POST /data")
            .with_label("priority", "high")
            .with_label("source", "ci");

        assert_eq!(ctx.labels.len(), 2);
        assert_eq!(ctx.labels.get("priority").unwrap(), "high");
    }

    #[test]
    fn clone_works() {
        let ctx = RequestContext::new("tool", "action").with_operator("bob");
        let ctx2 = ctx.clone();
        assert_eq!(ctx2.operator, ctx.operator);
    }
}
