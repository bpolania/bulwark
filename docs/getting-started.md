# Getting Started with Bulwark

Bulwark is an open-source governance layer for AI agents. This guide will walk you through installation, creating your first policy, and making your first governed request in under 10 minutes.

## Prerequisites

- Rust 1.85 or later
- Git (for building from source)

## Installation

### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/bulwark.git
cd bulwark

# Build the project
cargo build --release

# The binary will be at target/release/bulwark
# Optionally, add it to your PATH or install it
cargo install --path crates/cli
```

### Option 2: Install from crates.io

```bash
cargo install bulwark-cli
```

Verify the installation:

```bash
bulwark --version
```

## Initialize a Project

Create a new Bulwark project to hold your policies, credentials, and audit logs:

```bash
bulwark init my-project
cd my-project
```

This creates the following structure:

```
my-project/
├── bulwark.yaml          # Main configuration file
├── policies/             # Directory for policy YAML files
│   └── default.yaml      # Starter policy
├── credentials/          # Directory for encrypted credential files
├── audit.db              # SQLite audit log (created on first use)
└── sessions.db           # SQLite session store (created on first use)
```

## Create Your First Policy

Let's create a simple policy that allows read operations but denies writes. Open `policies/first-policy.yaml` and add:

```yaml
metadata:
  name: "Read-Only Policy"
  scope: Global

rules:
  - name: "Allow Read Operations"
    verdict: allow
    match:
      tools:
        - "filesystem:read"
        - "database:query"
        - "api:get"
    priority: 10

  - name: "Deny Write Operations"
    verdict: deny
    match:
      tools:
        - "filesystem:write"
        - "filesystem:delete"
        - "database:update"
        - "database:delete"
        - "api:post"
        - "api:put"
        - "api:delete"
    priority: 20

  - name: "Deny By Default"
    verdict: deny
    match:
      tools:
        - "*"
    priority: 0
```

### Understanding the Policy Format

- **metadata**: Describes the policy
  - **name**: Human-readable policy name
  - **scope**: One of Global, Agent, Team, Project, or Override (in precedence order)

- **rules**: List of rules evaluated in order
  - **name**: Human-readable rule name
  - **verdict**: `allow`, `deny`, or `escalate`
  - **match**: Patterns for tools, actions, or resources (supports glob patterns: `*`, `?`, `{a,b}`, `[abc]`)
  - **priority**: Higher numbers evaluated first (within same scope)
  - **conditions** (optional): Additional constraints like operators, teams, environments, agent_types, or labels

### Policy Evaluation Rules

1. Rules are grouped by scope: Override > Project > Team > Agent > Global
2. Within each scope, rules are sorted by priority (highest first)
3. Deny verdicts beat allow verdicts
4. If no rules match, the default is deny

## Create a Session

Sessions authenticate operators and track their actions. Create one:

```bash
bulwark session create --operator you@example.com
```

This outputs a session token like:

```
bwk_sess_a1b2c3d4e5f6789012345678901234567890abcdef01234567890abcdef0123
```

Save this token - you'll need it for every request.

To list active sessions:

```bash
bulwark session list
```

To revoke a session:

```bash
bulwark session revoke bwk_sess_a1b2c3d4...
```

## Start the Proxy

Start Bulwark in HTTP proxy mode:

```bash
bulwark proxy start
```

By default, this starts a proxy on `http://localhost:8080`. You'll see output like:

```
[INFO] Bulwark proxy starting on 127.0.0.1:8080
[INFO] Loaded 2 policies from policies/
[INFO] Ready to accept connections
```

To run in the background:

```bash
bulwark proxy start --daemon
```

To use a different port:

```bash
bulwark proxy start --port 9090
```

## Make a Governed Request

With the proxy running, make a request through it. Every request must include the `X-Bulwark-Session` header with your session token.

### Example: Allowed Request

```bash
curl -x http://localhost:8080 \
  -H "X-Bulwark-Session: bwk_sess_a1b2c3d4..." \
  -H "X-Tool-Name: filesystem:read" \
  https://api.example.com/data
```

If the policy allows it, the request goes through and you'll see the upstream response.

### Example: Denied Request

```bash
curl -x http://localhost:8080 \
  -H "X-Bulwark-Session: bwk_sess_a1b2c3d4..." \
  -H "X-Tool-Name: filesystem:write" \
  -X POST \
  https://api.example.com/data
```

This will be blocked with a 403 Forbidden response:

```json
{
  "error": "Policy violation",
  "rule": "Deny Write Operations",
  "policy": "Read-Only Policy"
}
```

### Tool Name Header

The `X-Tool-Name` header tells Bulwark which tool is being invoked. This is how it matches against policy rules. In MCP mode, this is automatically extracted from the JSON-RPC method.

## View the Audit Log

Every governed request is logged to the audit trail. View recent entries:

```bash
bulwark audit tail 5
```

This shows the last 5 audit events in JSON format, including:
- Timestamp
- Session ID and operator
- Tool invoked
- Policy verdict (allow/deny/escalate)
- Request/response hashes
- Hash chain (links to previous event via blake3)

View audit statistics:

```bash
bulwark audit stats
```

This shows:
- Total events
- Events by verdict (allowed, denied, escalated)
- Top operators
- Top tools
- Events by time period

Query specific events:

```bash
# Events by operator
bulwark audit query --operator you@example.com

# Events by verdict
bulwark audit query --verdict deny

# Events in time range
bulwark audit query --since 2026-02-01 --until 2026-02-15
```

## Run Doctor

Bulwark includes a diagnostic tool to check your setup:

```bash
bulwark doctor
```

This validates:
- Configuration file syntax
- Policy file syntax and rule conflicts
- Credential file encryption and accessibility
- Database integrity (audit log hash chain)
- Session store health
- File permissions

If something is wrong, `doctor` will report specific issues and suggest fixes.

## Next Steps

Congratulations! You've set up Bulwark, created a policy, and made your first governed request.

Here's what to explore next:

1. **Advanced Policies**: Learn about conditions, scopes, and priority in the [Policy Reference](policy-reference.md)

2. **Credential Management**: Store and inject credentials securely with age encryption. See [Credential Vault Guide](credential-vault.md)

3. **Content Inspection**: Enable automatic scanning for secrets, PII, and prompt injection. See [Content Inspection Guide](content-inspection.md)

4. **Rate Limiting**: Configure token-bucket rate limits per session, operator, tool, or globally. See [Rate Limiting Guide](rate-limiting.md)

5. **Cost Tracking**: Monitor per-operator costs with monthly budgets. See [Cost Tracking Guide](cost-tracking.md)

6. **MCP Integration**: Use Bulwark as an MCP gateway for stdio-based agents. See [MCP Gateway Guide](mcp-gateway.md)

7. **Architecture**: Understand how Bulwark works under the hood. See [Architecture Overview](architecture.md)

8. **Production Deployment**: Best practices for running Bulwark in production. See [Deployment Guide](deployment.md)

## Getting Help

- Documentation: `/docs` directory in the repository
- Issues: [GitHub Issues](https://github.com/yourusername/bulwark/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/bulwark/discussions)

## Quick Reference

```bash
# Project management
bulwark init <name>              # Create new project
bulwark doctor                   # Validate setup

# Session management
bulwark session create --operator <email>
bulwark session list
bulwark session revoke <token>

# Proxy operations
bulwark proxy start              # Start proxy on :8080
bulwark proxy start --port 9090  # Custom port
bulwark proxy start --daemon     # Background mode

# Audit log
bulwark audit tail <n>           # Last N events
bulwark audit stats              # Statistics
bulwark audit query <filters>    # Query events

# Policy management
bulwark policy validate          # Check policy syntax
bulwark policy test              # Run policy tests
bulwark policy reload            # Hot-reload policies

# Credential management
bulwark vault add <name>         # Add encrypted credential
bulwark vault list               # List credentials
bulwark vault rotate <name>      # Rotate credential
```
