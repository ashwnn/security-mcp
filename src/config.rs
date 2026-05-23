use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Serialize;
use url::Url;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
pub struct Cli {
    #[arg(long, env = "SECURITY_MCP_BIND_ADDR")]
    pub bind_addr: Option<String>,
    #[arg(long, env = "SECURITY_MCP_PUBLIC_BASE_URL")]
    pub public_base_url: Option<String>,
    #[arg(long, env = "SECURITY_MCP_DATABASE_PATH")]
    pub database_path: Option<String>,
    #[arg(long, env = "SECURITY_MCP_PUBLIC_MODE")]
    pub public_mode: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub public_base_url: Url,
    pub oauth_issuer: Url,
    pub database_path: String,
    pub public_mode: bool,
    pub bearer_token: Option<String>,
    pub bearer_scopes: Vec<String>,
    pub api_key: Option<String>,
    pub api_key_scopes: Vec<String>,
    pub api_key_header: String,
    pub api_key_query_enabled: bool,
    pub api_key_query_name: String,
    pub connector_token: Option<String>,
    pub oauth_enabled: bool,
    pub oauth_allowed_scopes: Vec<String>,
    pub oauth_default_scopes: Vec<String>,
    pub oauth_require_resource: bool,
    pub require_registered_oauth_clients: bool,
    pub access_token_ttl_seconds: i64,
    pub auth_code_ttl_seconds: i64,
    pub expert_tool_enabled: bool,
    pub cache_enabled: bool,
    pub default_timeout_seconds: u64,
    pub max_request_body_bytes: usize,
    pub allow_private_targets: bool,
    pub trust_proxy_headers: bool,
    pub enforce_mcp_origin: bool,
    pub auth_rate_limit_per_minute: u32,
    pub lookup_rate_limit_per_minute: u32,
    pub ui_localhost_only: bool,
    pub log_level: String,
    pub nvd_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    pub greynoise_api_key: Option<String>,
    pub abuseipdb_api_key: Option<String>,
    pub virustotal_api_key: Option<String>,
    pub urlscan_api_key: Option<String>,
    pub github_token: Option<String>,
    pub circl_pd_user: Option<String>,
    pub circl_pd_password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RedactedConfig {
    pub bind_addr: String,
    pub public_base_url: String,
    pub oauth_issuer: String,
    pub database_path: String,
    pub public_mode: bool,
    pub bearer_token_configured: bool,
    pub bearer_scopes: Vec<String>,
    pub api_key_configured: bool,
    pub api_key_scopes: Vec<String>,
    pub api_key_header: String,
    pub api_key_query_enabled: bool,
    pub api_key_query_name: String,
    pub connector_token_configured: bool,
    pub oauth_enabled: bool,
    pub oauth_allowed_scopes: Vec<String>,
    pub oauth_default_scopes: Vec<String>,
    pub oauth_require_resource: bool,
    pub require_registered_oauth_clients: bool,
    pub access_token_ttl_seconds: i64,
    pub expert_tool_enabled: bool,
    pub cache_enabled: bool,
    pub default_timeout_seconds: u64,
    pub max_request_body_bytes: usize,
    pub allow_private_targets: bool,
    pub trust_proxy_headers: bool,
    pub enforce_mcp_origin: bool,
    pub auth_rate_limit_per_minute: u32,
    pub lookup_rate_limit_per_minute: u32,
    pub ui_localhost_only: bool,
    pub log_level: String,
}

impl Config {
    pub fn from_sources(cli: Cli) -> Result<Self> {
        let bind_addr = cli
            .bind_addr
            .or_else(|| std::env::var("SECURITY_MCP_BIND_ADDR").ok())
            .unwrap_or_else(|| "127.0.0.1:8080".to_string())
            .parse::<SocketAddr>()
            .context("invalid SECURITY_MCP_BIND_ADDR")?;

        let public_base_url = Url::parse(
            &cli.public_base_url
                .or_else(|| std::env::var("SECURITY_MCP_PUBLIC_BASE_URL").ok())
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
        )
        .context("invalid SECURITY_MCP_PUBLIC_BASE_URL")?;

        let oauth_issuer = Url::parse(
            &std::env::var("SECURITY_MCP_OAUTH_ISSUER")
                .ok()
                .unwrap_or_else(|| public_base_url.to_string()),
        )
        .context("invalid SECURITY_MCP_OAUTH_ISSUER")?;

        let database_path = cli
            .database_path
            .or_else(|| std::env::var("SECURITY_MCP_DATABASE_PATH").ok())
            .unwrap_or_else(|| "./security-mcp.sqlite".to_string());

        let public_mode = cli
            .public_mode
            .or_else(|| {
                std::env::var("SECURITY_MCP_PUBLIC_MODE")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(false);

        let config = Self {
            bind_addr,
            public_base_url,
            oauth_issuer,
            database_path,
            public_mode,
            bearer_token: std::env::var("SECURITY_MCP_BEARER_TOKEN")
                .ok()
                .filter(|v| !v.is_empty()),
            bearer_scopes: parse_scopes("SECURITY_MCP_BEARER_SCOPES", &["mcp:read", "mcp:tools"]),
            api_key: std::env::var("SECURITY_MCP_API_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            api_key_scopes: parse_scopes("SECURITY_MCP_API_KEY_SCOPES", &["mcp:read", "mcp:tools"]),
            api_key_header: std::env::var("SECURITY_MCP_API_KEY_HEADER")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "X-API-Key".to_string()),
            api_key_query_enabled: std::env::var("SECURITY_MCP_API_KEY_QUERY_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            api_key_query_name: std::env::var("SECURITY_MCP_API_KEY_QUERY_NAME")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "api_key".to_string()),
            connector_token: std::env::var("SECURITY_MCP_CONNECTOR_TOKEN")
                .ok()
                .filter(|v| !v.is_empty()),
            oauth_enabled: std::env::var("SECURITY_MCP_OAUTH_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            oauth_allowed_scopes: parse_scopes(
                "SECURITY_MCP_OAUTH_ALLOWED_SCOPES",
                &["mcp:read", "mcp:tools", "mcp:raw", "mcp:admin"],
            ),
            oauth_default_scopes: parse_scopes(
                "SECURITY_MCP_OAUTH_DEFAULT_SCOPES",
                &["mcp:read", "mcp:tools"],
            ),
            oauth_require_resource: std::env::var("SECURITY_MCP_OAUTH_REQUIRE_RESOURCE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            require_registered_oauth_clients: std::env::var(
                "SECURITY_MCP_REQUIRE_REGISTERED_OAUTH_CLIENTS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true),
            access_token_ttl_seconds: std::env::var("SECURITY_MCP_ACCESS_TOKEN_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            auth_code_ttl_seconds: std::env::var("SECURITY_MCP_AUTH_CODE_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            expert_tool_enabled: std::env::var("SECURITY_MCP_EXPERT_TOOL_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            cache_enabled: std::env::var("SECURITY_MCP_CACHE_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            default_timeout_seconds: std::env::var("SECURITY_MCP_DEFAULT_TIMEOUT_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            max_request_body_bytes: std::env::var("SECURITY_MCP_MAX_REQUEST_BODY_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024 * 1024),
            allow_private_targets: std::env::var("SECURITY_MCP_ALLOW_PRIVATE_TARGETS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            trust_proxy_headers: std::env::var("SECURITY_MCP_TRUST_PROXY_HEADERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            enforce_mcp_origin: std::env::var("SECURITY_MCP_ENFORCE_MCP_ORIGIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            auth_rate_limit_per_minute: std::env::var("SECURITY_MCP_AUTH_RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
            lookup_rate_limit_per_minute: std::env::var(
                "SECURITY_MCP_LOOKUP_RATE_LIMIT_PER_MINUTE",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120),
            ui_localhost_only: std::env::var("SECURITY_MCP_UI_LOCALHOST_ONLY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            log_level: std::env::var("SECURITY_MCP_LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            nvd_api_key: std::env::var("NVD_API_KEY").ok().filter(|v| !v.is_empty()),
            shodan_api_key: std::env::var("SHODAN_API_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            greynoise_api_key: std::env::var("GREYNOISE_API_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            abuseipdb_api_key: std::env::var("ABUSEIPDB_API_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            virustotal_api_key: std::env::var("VIRUSTOTAL_API_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            urlscan_api_key: std::env::var("URLSCAN_API_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            github_token: std::env::var("GITHUB_TOKEN").ok().filter(|v| !v.is_empty()),
            circl_pd_user: std::env::var("CIRCL_PD_USER")
                .ok()
                .or_else(|| std::env::var("CIRCL_PASSIVE_DNS_USERNAME").ok())
                .filter(|v| !v.is_empty()),
            circl_pd_password: std::env::var("CIRCL_PD_PASSWORD")
                .ok()
                .or_else(|| std::env::var("CIRCL_PASSIVE_DNS_PASSWORD").ok())
                .filter(|v| !v.is_empty()),
        };

        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.public_mode && self.bind_addr.ip().is_loopback() {
            bail!("public mode enabled but bind address is loopback")
        }
        if self.public_mode
            && self.bearer_token.is_none()
            && self.api_key.is_none()
            && (!self.oauth_enabled || self.connector_token.is_none())
        {
            bail!("public mode requires at least one authentication mode")
        }
        if self.oauth_enabled && self.connector_token.is_none() {
            bail!("SECURITY_MCP_CONNECTOR_TOKEN is required when OAuth is enabled")
        }
        if self.oauth_enabled && self.oauth_issuer.scheme() != "https" && self.public_mode {
            bail!("oauth issuer must be https in public mode")
        }
        if self.public_mode && self.public_base_url.scheme() != "https" {
            bail!("SECURITY_MCP_PUBLIC_BASE_URL must be https in public mode")
        }
        if self.oauth_default_scopes.is_empty() {
            bail!("oauth default scopes cannot be empty")
        }
        if let Some(scope) = self
            .oauth_default_scopes
            .iter()
            .find(|scope| !self.oauth_allowed_scopes.contains(scope))
        {
            bail!("oauth default scope not in allowed scopes: {scope}")
        }
        Ok(())
    }

    pub fn redacted(&self) -> RedactedConfig {
        RedactedConfig {
            bind_addr: self.bind_addr.to_string(),
            public_base_url: self.public_base_url.to_string(),
            oauth_issuer: self.oauth_issuer.to_string(),
            database_path: self.database_path.clone(),
            public_mode: self.public_mode,
            bearer_token_configured: self.bearer_token.is_some(),
            bearer_scopes: self.bearer_scopes.clone(),
            api_key_configured: self.api_key.is_some(),
            api_key_scopes: self.api_key_scopes.clone(),
            api_key_header: self.api_key_header.clone(),
            api_key_query_enabled: self.api_key_query_enabled,
            api_key_query_name: self.api_key_query_name.clone(),
            connector_token_configured: self.connector_token.is_some(),
            oauth_enabled: self.oauth_enabled,
            oauth_allowed_scopes: self.oauth_allowed_scopes.clone(),
            oauth_default_scopes: self.oauth_default_scopes.clone(),
            oauth_require_resource: self.oauth_require_resource,
            require_registered_oauth_clients: self.require_registered_oauth_clients,
            access_token_ttl_seconds: self.access_token_ttl_seconds,
            expert_tool_enabled: self.expert_tool_enabled,
            cache_enabled: self.cache_enabled,
            default_timeout_seconds: self.default_timeout_seconds,
            max_request_body_bytes: self.max_request_body_bytes,
            allow_private_targets: self.allow_private_targets,
            trust_proxy_headers: self.trust_proxy_headers,
            enforce_mcp_origin: self.enforce_mcp_origin,
            auth_rate_limit_per_minute: self.auth_rate_limit_per_minute,
            lookup_rate_limit_per_minute: self.lookup_rate_limit_per_minute,
            ui_localhost_only: self.ui_localhost_only,
            log_level: self.log_level.clone(),
        }
    }

    pub fn source_configured(&self, source: &str) -> bool {
        match source {
            "nvd" => self.nvd_api_key.is_some(),
            "shodan" => self.shodan_api_key.is_some(),
            "greynoise" => self.greynoise_api_key.is_some(),
            "abuseipdb" => self.abuseipdb_api_key.is_some(),
            "virustotal" => self.virustotal_api_key.is_some(),
            "urlscan" => self.urlscan_api_key.is_some(),
            "github" => self.github_token.is_some(),
            "circl_passive_dns" => self.circl_pd_user.is_some() && self.circl_pd_password.is_some(),
            _ => true,
        }
    }
}

fn parse_scopes(env_var: &str, defaults: &[&str]) -> Vec<String> {
    let raw = std::env::var(env_var)
        .ok()
        .unwrap_or_else(|| defaults.join(" "));
    let normalized = raw
        .replace(',', " ")
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    let mut scopes = normalized
        .split_whitespace()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    scopes.sort();
    scopes.dedup();
    scopes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_env() {
        let keys = [
            "SECURITY_MCP_BIND_ADDR",
            "SECURITY_MCP_PUBLIC_BASE_URL",
            "SECURITY_MCP_DATABASE_PATH",
            "SECURITY_MCP_PUBLIC_MODE",
            "SECURITY_MCP_BEARER_TOKEN",
            "SECURITY_MCP_BEARER_SCOPES",
            "SECURITY_MCP_API_KEY",
            "SECURITY_MCP_API_KEY_SCOPES",
            "SECURITY_MCP_CONNECTOR_TOKEN",
            "SECURITY_MCP_OAUTH_ENABLED",
            "SECURITY_MCP_OAUTH_ALLOWED_SCOPES",
            "SECURITY_MCP_OAUTH_DEFAULT_SCOPES",
            "SECURITY_MCP_OAUTH_REQUIRE_RESOURCE",
            "SECURITY_MCP_REQUIRE_REGISTERED_OAUTH_CLIENTS",
            "SECURITY_MCP_ENFORCE_MCP_ORIGIN",
            "SECURITY_MCP_AUTH_RATE_LIMIT_PER_MINUTE",
            "SECURITY_MCP_LOOKUP_RATE_LIMIT_PER_MINUTE",
        ];
        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn parses_defaults() {
        clear_env();
        unsafe {
            std::env::set_var("SECURITY_MCP_OAUTH_ENABLED", "false");
        }
        let config = Config::from_sources(Cli::parse_from(["app"])).expect("config");
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn public_mode_requires_auth() {
        let config = Config {
            bind_addr: "0.0.0.0:8080".parse().expect("addr"),
            public_base_url: Url::parse("https://example.com").expect("url"),
            oauth_issuer: Url::parse("https://example.com").expect("url"),
            database_path: ":memory:".to_string(),
            public_mode: true,
            bearer_token: None,
            bearer_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            api_key: None,
            api_key_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            api_key_header: "X-API-Key".to_string(),
            api_key_query_enabled: false,
            api_key_query_name: "api_key".to_string(),
            connector_token: None,
            oauth_enabled: false,
            oauth_allowed_scopes: vec![
                "mcp:read".to_string(),
                "mcp:tools".to_string(),
                "mcp:raw".to_string(),
                "mcp:admin".to_string(),
            ],
            oauth_default_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            oauth_require_resource: false,
            require_registered_oauth_clients: true,
            access_token_ttl_seconds: 3600,
            auth_code_ttl_seconds: 300,
            expert_tool_enabled: false,
            cache_enabled: true,
            default_timeout_seconds: 15,
            max_request_body_bytes: 1024 * 1024,
            allow_private_targets: false,
            trust_proxy_headers: false,
            enforce_mcp_origin: true,
            auth_rate_limit_per_minute: 120,
            lookup_rate_limit_per_minute: 120,
            ui_localhost_only: true,
            log_level: "info".to_string(),
            nvd_api_key: None,
            shodan_api_key: None,
            greynoise_api_key: None,
            abuseipdb_api_key: None,
            virustotal_api_key: None,
            urlscan_api_key: None,
            github_token: None,
            circl_pd_user: None,
            circl_pd_password: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn redaction_hides_secret_values() {
        clear_env();
        unsafe {
            std::env::set_var("SECURITY_MCP_OAUTH_ENABLED", "false");
            std::env::set_var("SECURITY_MCP_BEARER_TOKEN", "super-secret");
        }
        let config = Config::from_sources(Cli::parse_from(["app"])).expect("config");
        let redacted = serde_json::to_string(&config.redacted()).expect("json");
        assert!(!redacted.contains("super-secret"));
        assert!(redacted.contains("bearer_token_configured"));
    }
}
