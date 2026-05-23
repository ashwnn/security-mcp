# Security MCP

Security MCP is a minimal Rust MCP server for security enrichment, passive recon, CVE intelligence, and analyst workflows.

It helps security analysts understand external exposure, attack vectors, vulnerability context, and defensive control gaps by collecting structured evidence from trusted security sources through a local web UI and MCP-compatible remote server.

The goal is simple: reduce manual lookup work, organize evidence, and make security enrichment easier to use from AI clients without exposing a noisy list of raw tools.

## Features

- CVE, EPSS, CVSS, CWE, and CISA KEV enrichment
- Domain, IP, URL, DNS, TLS, ASN, and passive DNS analysis
- Public exposure and attack-surface context gathering
- Package vulnerability checks with OSV and GitHub Advisories
- Threat intelligence lookups for infrastructure and indicators
- Local web UI for manual analyst workflows
- Remote MCP server support for AI clients
- Bearer token and OAuth-compatible authentication
- SQLite caching and local audit logs
- Small single-binary deployment

## Sources

The initial version targets integrations with:

- NVD
- EPSS
- CISA KEV
- MITRE ATT&CK
- Shodan
- GreyNoise
- AbuseIPDB
- VirusTotal
- URLScan
- OSV
- GitHub Advisories
- CIRCL Passive DNS
- MalwareBazaar
- ThreatFox

## Use Cases

Security MCP is intended for workflows such as:

- Enriching CVEs before prioritizing patching or mitigation
- Checking whether vulnerabilities appear in CISA KEV
- Reviewing EPSS, CVSS, CWE, exploit, and attack-technique context
- Mapping externally visible domains, subdomains, services, and infrastructure
- Understanding likely attack vectors against exposed assets
- Gathering evidence to support firewall, WAF, DNS, endpoint, and access-control policies
- Reviewing package and dependency risk across software projects
- Correlating security intelligence into analyst-reviewed findings
- Giving AI clients a safer, smaller set of security investigation tools

## Design

Security MCP is built around a small model-facing MCP interface and a broader internal tool registry.

AI clients should not need to see every low-level source tool. Instead, they can call higher-level investigation tools that route to the right enrichment modules and return structured results.

The local web UI exposes more manual control for analysts who want to inspect sources, review raw evidence, and run specific lookups.

## Deployment

Security MCP is designed to run as a small Rust binary with minimal operational overhead.

Supported deployment targets include:

- Local analyst workstation
- Small VPS
- Internal security tooling server
- Cloudflare-proxied HTTPS endpoint

SQLite is used for local caching and audit logs.

## Authentication

Security MCP supports:

- Static bearer tokens
- API key-style authentication
- OAuth-compatible flows for MCP clients that require OAuth

This allows the same server to work with different MCP clients and connector platforms without requiring every deployment to manage a full external identity provider.

## Scope

Security MCP is not a vulnerability scanner, exploitation framework, ticketing system, or replacement for analyst judgment.

It focuses on enrichment, exposure context, attack-vector analysis, evidence organization, and analyst-reviewed defensive decisions.

## Contributing

Issues, feature requests, and pull requests are welcome.

Good contributions are focused, tested, documented, and aligned with the project goal: useful security enrichment without unnecessary complexity.

## License

[MIT](LICENSE)
