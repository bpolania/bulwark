# Bulwark

**Open-source governance layer for AI agents.**

Bulwark sits between AI agents and external tools, enforcing policies, managing credentials, inspecting content, and maintaining a complete audit trail. One policy governs all your agents — Claude Code, OpenClaw, Codex, or any MCP/HTTP client.

## Why Bulwark?

AI agents are powerful but ungoverned. They can access any tool, leak any credential, and leave no audit trail. Bulwark fixes this:

- **Policy enforcement** — YAML-based rules control which tools agents can use, with glob patterns, scope-based precedence, and hot-reload
- **Credential management** — Agents never see real secrets. Bulwark injects credentials at the last mile, encrypted at rest with age
- **Content inspection** — Scan requests and responses for secrets, PII, and prompt injection. Block or redact automatically
- **Audit logging** — Every action recorded in a tamper-evident SQLite database with blake3 hash chains
- **Rate limiting** — Token-bucket rate limits per session, operator, tool, or globally. Cost tracking with budget enforcement
- **MCP-native** — Works as an MCP gateway or HTTP forward proxy. Governance metadata on every tool call response

## Quick Start

```bash
# Initialize a project
bulwark init my-project && cd my-project

# Create a session for yourself
bulwark session create --operator alice@acme.com

# Start the MCP gateway
bulwark mcp start

# Or start the HTTP proxy
bulwark proxy start
```

Configure Claude Code to use Bulwark as its MCP gateway, or point any HTTP client at `localhost:8080`.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────┐     ┌──────────────┐
│             │     │                  Bulwark                      │     │              │
│  AI Agent   │────>│  Session > Inspect > Policy > Inject > Proxy │────>│  Upstream    │
│  (Claude,   │<────│  <── Audit <── Inspect <── Response <─────── │<────│  Tool/API    │
│   Codex,    │     │                                              │     │              │
│   custom)   │     └──────────────────────────────────────────────┘     └──────────────┘
└─────────────┘
```

## Integration Modes

| Mode | Transport | Best For |
|------|-----------|----------|
| MCP Gateway | stdio/JSON-RPC | Claude Code, OpenClaw, any MCP client |
| HTTP Proxy | HTTP/HTTPS | Codex, curl, any HTTP client |

## Example Policy

```yaml
# policies/base.yaml
metadata:
  name: my-policy
  scope: global

rules:
  - name: allow-reads
    verdict: allow
    priority: 10
    match:
      actions: ["read*", "get*", "list*"]

  - name: block-destructive-in-prod
    verdict: deny
    priority: 100
    match:
      actions: ["delete*", "drop*"]
    conditions:
      environments: ["production"]

  - name: default-deny
    verdict: deny
    match: {}
```

See [examples/policies/](./examples/policies/) for complete policy sets (startup, enterprise, development, multi-agent).

## CLI

```
bulwark init <path>              # Scaffold a new project
bulwark proxy start              # Start HTTP/HTTPS proxy
bulwark mcp start                # Start MCP gateway
bulwark doctor                   # Diagnose setup issues
bulwark status                   # Health dashboard
bulwark policy validate          # Validate policy files
bulwark policy test --dir <path> # Test policies against audit log
bulwark session create|list|revoke|inspect
bulwark cred add|list|remove|test
bulwark audit search|tail|stats|export|verify
bulwark inspect scan|rules       # Content inspection
bulwark completions <shell>      # Shell completions (bash/zsh/fish)
```

## Documentation

- [Getting Started](./docs/getting-started.md)
- [Architecture Overview](./docs/architecture.md)
- [Policy Reference](./docs/policy-reference.md)
- [Configuration Reference](./docs/configuration.md)
- [Credential Management](./docs/credentials.md)
- [Audit System](./docs/audit.md)
- [Content Inspector](./docs/content-inspector.md)
- [Rate Limiting](./docs/rate-limiting.md)
- [Threat Model](./docs/threat-model.md)
- Agent Guides: [Claude Code](./docs/agents/claude-code.md) | [Codex](./docs/agents/codex.md) | [OpenClaw](./docs/agents/openclaw.md)

## Development

```bash
git clone https://github.com/anthropics/bulwark.git
cd bulwark
cargo build --workspace
cargo test --workspace          # 350+ tests
cargo clippy --workspace --all-targets -- -D warnings
```

### Project Structure

```
crates/
  cli/        # CLI binary and commands
  proxy/      # HTTP/HTTPS forward proxy with TLS MITM
  mcp/        # MCP governance gateway
  config/     # Configuration loading and types
  policy/     # YAML policy engine with hot-reload
  vault/      # Credential storage and session management
  audit/      # Tamper-evident audit logging
  inspect/    # Content inspection (secrets, PII, injection)
  ratelimit/  # Token-bucket rate limiter and cost tracker
  common/     # Shared types and error definitions
```

## License

Apache 2.0. See [LICENSE](./LICENSE).
