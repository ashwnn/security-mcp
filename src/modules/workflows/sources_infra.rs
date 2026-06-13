use std::time::Duration;

use anyhow::{Result, bail};
use reqwest::redirect::Policy;
use serde_json::Value;

use super::common::{ModuleRunResult, missing_key, success};
use crate::validation::validate_public_url;

pub(super) async fn abuseipdb_lookup(
    state: &crate::types::AppState,
    ip: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.abuseipdb_api_key.as_deref() else {
        return Ok(missing_key("abuseipdb", "ABUSEIPDB_API_KEY"));
    };
    let resp = state
        .http_client
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .header("Key", key)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("abuseipdb request failed: {status}")
    }
    Ok(success(
        "abuseipdb",
        "AbuseIPDB reputation",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn greynoise_lookup(
    state: &crate::types::AppState,
    ip: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.greynoise_api_key.as_deref() else {
        return Ok(missing_key("greynoise", "GREYNOISE_API_KEY"));
    };
    let resp = state
        .http_client
        .get(format!("https://api.greynoise.io/v3/community/{}", urlencoding::encode(ip)))
        .header("key", key)
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("greynoise request failed: {status}")
    }
    Ok(success(
        "greynoise",
        "GreyNoise context",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn shodan_lookup(
    state: &crate::types::AppState,
    ip: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.shodan_api_key.as_deref() else {
        return Ok(missing_key("shodan", "SHODAN_API_KEY"));
    };
    let resp = state
        .http_client
        .get(format!("https://api.shodan.io/shodan/host/{}", urlencoding::encode(ip)))
        .query(&[("key", key)])
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("shodan request failed: {status}")
    }
    Ok(success(
        "shodan",
        "Shodan passive host data",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn circl_pdns_lookup(
    state: &crate::types::AppState,
    indicator: &str,
) -> Result<ModuleRunResult> {
    let Some(user) = state.config.circl_pd_user.as_deref() else {
        return Ok(missing_key("circl_passive_dns", "CIRCL_PD_USER"));
    };
    let Some(pass) = state.config.circl_pd_password.as_deref() else {
        return Ok(missing_key("circl_passive_dns", "CIRCL_PD_PASSWORD"));
    };
    let resp = state
        .http_client
        .get(format!("https://www.circl.lu/pdns/query/{}", urlencoding::encode(indicator)))
        .basic_auth(user, Some(pass))
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("circl pdns request failed: {status}")
    }
    Ok(success(
        "circl_passive_dns",
        "Passive DNS records",
        "medium",
        serde_json::json!({"preview": text.lines().take(20).collect::<Vec<_>>() }),
        serde_json::json!({"raw_text": text}),
    ))
}

pub(super) async fn rdap_lookup(
    state: &crate::types::AppState,
    target: &str,
) -> Result<ModuleRunResult> {
    let path = if target.parse::<std::net::IpAddr>().is_ok() {
        format!("https://rdap.org/ip/{target}")
    } else {
        format!("https://rdap.org/domain/{target}")
    };
    let resp = state.http_client.get(path).send().await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("rdap request failed: {status}")
    }
    Ok(success("rdap", "RDAP context", "low", body.clone(), body))
}

pub(super) async fn doh_lookup(
    state: &crate::types::AppState,
    domain: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .get("https://cloudflare-dns.com/dns-query")
        .query(&[("name", domain), ("type", "A")])
        .header("accept", "application/dns-json")
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("dns lookup failed: {status}")
    }
    Ok(success(
        "dns_over_https",
        "DNS records",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn crtsh_lookup(
    state: &crate::types::AppState,
    domain: &str,
) -> Result<ModuleRunResult> {
    let query = if domain.contains('.') {
        format!("%.{domain}")
    } else {
        domain.to_string()
    };
    let resp = state
        .http_client
        .get("https://crt.sh/")
        .query(&[("q", query), ("output", "json".to_string())])
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("crt.sh request failed: {status}")
    }
    let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!([]));
    Ok(success(
        "crtsh",
        "Certificate transparency data",
        "medium",
        parsed.clone(),
        parsed,
    ))
}

pub(super) async fn http_headers_lookup(
    state: &crate::types::AppState,
    target: &str,
) -> Result<ModuleRunResult> {
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{target}")
    };
    validate_public_url(&url, state.config.allow_private_targets)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(state.config.default_timeout_seconds))
        .user_agent("security-mcp/0.1.0")
        .redirect(Policy::none())
        .build()?;

    let resp = client.head(&url).send().await?;
    let status = resp.status().as_u16();
    let mut headers = std::collections::BTreeMap::new();
    for (k, v) in resp.headers() {
        headers.insert(
            k.as_str().to_string(),
            v.to_str().unwrap_or("<non-utf8>").to_string(),
        );
    }
    Ok(success(
        "http",
        "HTTP response headers",
        "low",
        serde_json::json!({"status": status, "headers": headers, "redirect_followed": false, "method": "HEAD"}),
        serde_json::json!({"status": status, "headers": headers, "redirect_followed": false, "method": "HEAD"}),
    ))
}

pub(super) async fn technology_hint(target: &str) -> Result<ModuleRunResult> {
    let hint = if target.contains("github") {
        "github_pages"
    } else {
        "unknown"
    };
    Ok(success(
        "heuristic",
        "Technology fingerprint hint",
        "low",
        serde_json::json!({"hint": hint}),
        serde_json::json!({"hint": hint}),
    ))
}

pub(super) async fn cloud_hint(target: &str) -> Result<ModuleRunResult> {
    let hint = if target.contains("cloudflare") {
        "cloudflare"
    } else {
        "unknown"
    };
    Ok(success(
        "heuristic",
        "Cloud hosting hint",
        "low",
        serde_json::json!({"provider_hint": hint}),
        serde_json::json!({"provider_hint": hint}),
    ))
}
