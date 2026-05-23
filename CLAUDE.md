# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security MCP is a Rust MCP server providing security enrichment, passive recon, CVE intelligence, and defensive decision support. It exposes a JSON-RPC MCP interface at `/mcp` and a server-rendered analyst UI.

## Common Commands

```bash
# Development
cargo run                    # Start the server
cargo build                  # Build
cargo test                   # Run all tests
cargo test <test_name>       # Run a single test
cargo clippy --workspace --all-targets -- -D warnings  # Lint
cargo fmt --check            # Check formatting

# Release build
cargo build --release
```

## Architecture

### Core Layers

- **main.rs** — Entry point. Creates Axum app, wires middleware (compression, rate limits, trace, security headers), binds TCP listener
- **mcp.rs** — JSON-RPC 2.0 handler at `/mcp`. Dispatches `tools/list` and `tools/call` to module functions
- **ui.rs** — Server-rendered analyst UI routes: `/`, `/tools`, `/sources`, `/cache`, `/audit`, `/settings`

### Authentication

- **auth.rs** — AuthLayer middleware supporting bearer token and API key (header or query)
- **oauth.rs** — OAuth 2.0 authorization code + PKCE facade. Issues short-lived opaque tokens

### Data Layer

- **db.rs** — SQLite via sqlx. Stores cache and audit log
- **cache.rs** — Response caching with TTL

### Module System

- **modules/registry.rs** — Central registry of security modules with categories: cve, exploit, risk, network, domain, threat, devsecops
- **modules/workflows/high_level.rs** — High-level orchestration tools (`security_investigate`, `security_investigate_cve`, etc.)
- **modules/workflows/sources_*.rs** — Individual source integrations (NVD, EPSS, KEV, GreyNoise, Shodan, etc.)

### Key Types

- **types.rs** — `AppState` holds config, db, registry, http_client, rate limiters
- **config.rs** — `Config` and `Cli` parse environment variables and CLI args
- **validation.rs** — Input sanitization, SSRF checks

## MCP Tools

Six high-level tools exposed by default (see `high_level_tools()` in registry.rs):
- `security_investigate` — General indicator investigation
- `security_investigate_cve` — CVE-focused investigation
- `security_investigate_indicator` — Indicator type detection and routing
- `security_scan_dependencies` — Dependency file scanning
- `security_compare` — Compare multiple entities
- `security_tool_catalog` — Browse available modules

One additional tool when `SECURITY_MCP_EXPERT_TOOL_ENABLED=true`:
- `security_run_tool` — Direct module execution

## Data Flow

1. Request hits Axum router with AuthLayer
2. Rate limiting checked (auth rate limit for auth ops, lookup rate limit for tool calls)
3. JSON-RPC parsed in `mcp.rs::handle_mcp`
4. Tool dispatch calls module functions in `modules/workflows/`
5. Source integrations fetch from external APIs (NVD, GreyNoise, etc.) or use built-in parsers
6. Results cached in SQLite and returned as JSON-RPC response

## Environment Variables

Required for auth (pick one):
- `SECURITY_MCP_BEARER_TOKEN`
- `SECURITY_MCP_API_KEY`
- `SECURITY_MCP_OAUTH_ENABLED=true` + `SECURITY_MCP_CONNECTOR_TOKEN`

Source API keys (optional): `NVD_API_KEY`, `SHODAN_API_KEY`, `GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `GITHUB_TOKEN`, `CIRCL_PD_USER`, `CIRCL_PD_PASSWORD`

## Running Tests

E2E tests in `tests/e2e.rs` require database and network access. Unit tests in module files run with `cargo test`.
