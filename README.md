# Security MCP

Security MCP is a Rust MCP server for security enrichment, passive recon, CVE intelligence, exposure context, attack-vector analysis, and defensive decision support.

## V1 Features

- Remote MCP JSON-RPC endpoint at `/mcp` with a compact high-level tool surface:
  - `security_investigate`
  - `security_investigate_cve`
  - `security_investigate_indicator`
  - `security_scan_dependencies`
  - `security_compare`
  - `security_tool_catalog`
  - Optional: `security_run_tool` via `SECURITY_MCP_EXPERT_TOOL_ENABLED=true`
- Registry-first internal module catalog for CVE, exposure, threat, and dependency workflows.
- SQLite-backed cache and audit log.
- Server-rendered analyst UI:
  - `/`
  - `/tools`
  - `/sources`
  - `/cache`
  - `/audit`
  - `/settings`
  - localhost-only by default via `SECURITY_MCP_UI_LOCALHOST_ONLY=true`
- Security defaults:
  - loopback bind by default
  - strict request size limit
  - rate limits for auth and lookups
  - basic SSRF/private target checks
  - secret redaction in config views
  - security response headers

## Authentication Modes

The server accepts any configured mode:

- Direct bearer token: `Authorization: Bearer <token>`
- API key header mode: configurable header, default `X-API-Key`
- API key query mode: disabled by default, enable with `SECURITY_MCP_API_KEY_QUERY_ENABLED=true`
- OAuth-compatible token-login facade:
  - `GET /.well-known/oauth-authorization-server`
  - `GET /.well-known/openid-configuration`
  - `GET /.well-known/oauth-protected-resource`
  - `GET|POST /oauth/authorize`
  - `POST /oauth/token`
  - `POST /oauth/register`

OAuth flow supports authorization code with PKCE S256 and issues short-lived opaque access tokens.

## Sources in V1

- NVD
- FIRST EPSS
- CISA KEV
- AbuseIPDB
- GreyNoise
- Shodan
- CIRCL passive DNS
- RDAP
- Cloudflare DNS over HTTPS
- crt.sh
- VirusTotal
- URLScan
- MalwareBazaar
- ThreatFox
- Ransomwhere
- OSV
- GitHub advisories search

Missing API keys are returned as explicit source status instead of fake success.

## Quick Start

1. Copy `.env.example` to `.env`
2. Set at least one auth mode:
   - `SECURITY_MCP_BEARER_TOKEN`, or
   - `SECURITY_MCP_API_KEY`, or
   - OAuth with `SECURITY_MCP_OAUTH_ENABLED=true` and `SECURITY_MCP_CONNECTOR_TOKEN`
3. Run:

```bash
cargo run
```

Open [http://127.0.0.1:8080/](http://127.0.0.1:8080/) for UI.

## First-Use Workflow

1. Pick one auth mode for initial client onboarding.
2. Validate auth and tool discovery.
3. Add source API keys incrementally and confirm source status on `/sources`.

### Bearer mode first use

1. Set `SECURITY_MCP_BEARER_TOKEN`.
2. Call MCP:

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### API key mode first use

1. Set `SECURITY_MCP_API_KEY`.
2. Call MCP:

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H "X-API-Key: change-me" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### OAuth facade first use

1. Set `SECURITY_MCP_OAUTH_ENABLED=true` and `SECURITY_MCP_CONNECTOR_TOKEN`.
2. Register a client at `POST /oauth/register`.
3. Run authorization code + PKCE with `resource=<public_base_url>/mcp`.
4. Exchange code at `POST /oauth/token`.
5. Use returned bearer access token on `/mcp`.

## API Keys and Source Setup

Set only keys for sources you use. Missing keys are reported as `not_configured` in source status.

- `NVD_API_KEY` for NVD
- `SHODAN_API_KEY` for Shodan
- `GREYNOISE_API_KEY` for GreyNoise
- `ABUSEIPDB_API_KEY` for AbuseIPDB
- `VIRUSTOTAL_API_KEY` for VirusTotal
- `URLSCAN_API_KEY` for URLScan
- `GITHUB_TOKEN` for GitHub advisories
- `CIRCL_PD_USER` and `CIRCL_PD_PASSWORD` for CIRCL passive DNS

## Deployment Notes

- Public deployment should use HTTPS and a reverse proxy such as Cloudflare.
- Keep `SECURITY_MCP_PUBLIC_MODE=true` only when auth is configured.
- Keep `SECURITY_MCP_PUBLIC_BASE_URL` and `SECURITY_MCP_OAUTH_ISSUER` set to the public HTTPS origin.
- Do not enable query-token auth unless required by a connector.
- Keep web UI internal only. Expose MCP endpoint externally, not analyst UI routes.

## Contributing

Run before opening PR:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

## License

MIT
