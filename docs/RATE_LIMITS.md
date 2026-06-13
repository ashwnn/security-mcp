# Rate Limits and Quota Awareness

Security MCP uses two local guardrails:

1. Authentication and MCP request rate limits to reduce brute-force and accidental loop risk.
2. Source quota tracking so expensive or limited enrichment providers can be skipped before their quotas are exhausted.

## Runtime knobs

```bash
SECURITY_MCP_AUTH_RATE_LIMIT_PER_MINUTE=120
SECURITY_MCP_LOOKUP_RATE_LIMIT_PER_MINUTE=120
SECURITY_MCP_RATE_LIMIT_DEFAULT_PLAN=free
SECURITY_MCP_RATE_LIMIT_WARN_REMAINING_PERCENT=20
SECURITY_MCP_RATE_LIMIT_BLOCK_REMAINING_PERCENT=5
SECURITY_MCP_RATE_LIMIT_ENABLE_SOFT_BLOCK=true
```

## Semantics

- `warn_remaining_percent` marks a source as near limit.
- `block_remaining_percent` marks a source as quota protected when soft blocking is enabled.
- Missing credentials and source request failures are source-health states, not target findings.
- Source-health states must not increase target risk scores.

## Current limitations

The quota tracker is still mostly in-memory and not every provider integration records provider response headers yet. Treat the `/rate-limits` and source-health views as operator guidance, not provider billing source of truth.

## Next hardening steps

- Persist per-source quota windows into SQLite.
- Parse provider `Retry-After` and rate-limit headers consistently.
- Add source-specific quota profiles for NVD, Shodan, GreyNoise, AbuseIPDB, VirusTotal, URLScan, Censys, OTX, MISP, Pulsedive, and Hybrid Analysis.
- Return quota-protected source status inside MCP structured results so clients know why evidence is partial.
