use anyhow::{Result, bail};
use serde_json::Value;

use super::common::{ModuleRunResult, missing_key, success};
use crate::validation::validate_public_ip;

/// Censys - internet exposure and certificate intelligence
pub(super) async fn censys_lookup(
    state: &crate::types::AppState,
    query: &str,
) -> Result<ModuleRunResult> {
    let Some(api_id) = state.config.censys_api_id.as_deref() else {
        return Ok(missing_key("censys", "CENSYS_API_ID"));
    };
    let Some(api_secret) = state.config.censys_api_secret.as_deref() else {
        return Ok(missing_key("censys", "CENSYS_API_SECRET"));
    };

    // Try IP lookup first
    let is_ip = query.parse::<std::net::IpAddr>().is_ok();
    let path = if is_ip {
        format!("/v2/hosts/{}", urlencoding::encode(query))
    } else {
        format!("/v2/hosts/search?q={}", urlencoding::encode(query))
    };

    let resp = state
        .http_client
        .get(format!("https://search.censys.io{path}"))
        .basic_auth(api_id, Some(api_secret))
        .send()
        .await?;
    let status = resp.status();

    // Update quota tracker based on response
    if status.as_u16() == 429 {
        state.quota_tracker.record_rate_limit_error("censys", None);
        return Ok(super::common::source_error("censys", "rate limit exceeded"));
    }

    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("censys request failed: {status}")
    }

    state.quota_tracker.record_request("censys");
    state.quota_tracker.record_success("censys");

    // Extract summary fields
    let services = body["results"]
        .as_array()
        .and_then(|r| r.first())
        .and_then(|h| h["services"].as_array())
        .map(|s| s.len())
        .unwrap_or(0);

    Ok(success(
        "censys",
        "Censys host data",
        "medium",
        serde_json::json!({"services_count": services}),
        body,
    ))
}

/// AlienVault OTX - threat intelligence
pub(super) async fn otx_lookup(
    state: &crate::types::AppState,
    indicator: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.otx_api_key.as_deref() else {
        return Ok(missing_key("otx", "OTX_API_KEY"));
    };

    // Determine endpoint based on indicator type
    let is_ip = indicator.parse::<std::net::IpAddr>().is_ok();
    let is_hash = indicator.len() == 32 || indicator.len() == 40 || indicator.len() == 64;

    let (type_name, path) = if is_ip {
        ("ip", format!("/api/v1/indicators/IPv4/{}/general", urlencoding::encode(indicator)))
    } else if is_hash {
        ("hash", format!("/api/v1/indicators/file/{}", urlencoding::encode(indicator)))
    } else {
        ("hostname", format!("/api/v1/indicators/hostname/{}/general", urlencoding::encode(indicator)))
    };

    let resp = state
        .http_client
        .get(format!("https://otx.alienvault.com{path}"))
        .header("X-OTX-API-KEY", key)
        .send()
        .await?;
    let status = resp.status();

    if status.as_u16() == 429 {
        state.quota_tracker.record_rate_limit_error("otx", None);
        return Ok(super::common::source_error("otx", "rate limit exceeded"));
    }

    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("otx request failed: {status}")
    }

    state.quota_tracker.record_request("otx");
    state.quota_tracker.record_success("otx");

    let pulse_count = body["pulse_count"].as_i64().unwrap_or(0);
    let validation = body["validation"]
        .as_object()
        .and_then(|v| v.get("content").and_then(|c| c.as_str()));

    let severity = if pulse_count > 0 { "high" } else { "low" };
    Ok(success(
        "otx",
        "AlienVault OTX pulse signal",
        severity,
        serde_json::json!({"pulse_count": pulse_count, "validation": validation}),
        body,
    ))
}

/// MISP - enterprise threat intel
pub(super) async fn misp_lookup(
    state: &crate::types::AppState,
    indicator: &str,
) -> Result<ModuleRunResult> {
    let Some(base_url) = state.config.misp_base_url.as_deref() else {
        return Ok(missing_key("misp", "MISP_BASE_URL"));
    };
    let Some(key) = state.config.misp_api_key.as_deref() else {
        return Ok(missing_key("misp", "MISP_API_KEY"));
    };

    // Validate it's not a private target
    if indicator.parse::<std::net::IpAddr>().is_ok() {
        crate::validation::validate_public_ip(indicator.parse().unwrap())?;
    }

    let resp = state
        .http_client
        .get(format!("{}/rest/search", base_url))
        .query(&[("value", indicator)])
        .header("Authorization", key)
        .send()
        .await?;
    let status = resp.status();

    if status.as_u16() == 429 {
        state.quota_tracker.record_rate_limit_error("misp", None);
        return Ok(super::common::source_error("misp", "rate limit exceeded"));
    }

    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("misp request failed: {status}")
    }

    state.quota_tracker.record_request("misp");
    state.quota_tracker.record_success("misp");

    let response = body.get("response").and_then(|r| r.get("Attribute"));
    let count = response.as_array().map(|a| a.len()).unwrap_or(0);

    let severity = if count > 10 { "high" } else if count > 0 { "medium" } else { "low" };
    Ok(success(
        "misp",
        "MISP attribute lookup",
        severity,
        serde_json::json!({"attribute_count": count}),
        body,
    ))
}

/// Pulsedive - threat intelligence
pub(super) async fn pulsedive_lookup(
    state: &crate::types::AppState,
    indicator: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.pulsedive_api_key.as_deref() else {
        return Ok(missing_key("pulsedive", "PULSEDIVE_API_KEY"));
    };

    let resp = state
        .http_client
        .get("https://pulsedive.com/api/info.php")
        .query(&[("key", key), ("value", indicator)])
        .send()
        .await?;
    let status = resp.status();

    if status.as_u16() == 429 {
        state.quota_tracker.record_rate_limit_error("pulsedive", None);
        return Ok(super::common::source_error("pulsedive", "rate limit exceeded"));
    }

    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("pulsedive request failed: {status}")
    }

    state.quota_tracker.record_request("pulsedive");
    state.quota_tracker.record_success("pulsedive");

    let risk_level = body["risk"].as_str().unwrap_or("unknown");
    let severity = match risk_level {
        "high" | "critical" => "high",
        "medium" => "medium",
        _ => "low",
    };

    Ok(success(
        "pulsedive",
        "Pulsedive threat intel",
        severity,
        serde_json::json!({"risk": risk_level}),
        body,
    ))
}

/// Hybrid Analysis - hash intelligence
pub(super) async fn hybrid_analysis_lookup(
    state: &crate::types::AppState,
    hash: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.hybrid_analysis_api_key.as_deref() else {
        return Ok(missing_key("hybrid_analysis", "HYBRID_ANALYSIS_API_KEY"));
    };

    let resp = state
        .http_client
        .get(format!("https://www.hybrid-analysis.com/api/v2/search/hash/{}", urlencoding::encode(hash)))
        .header("api-key", key)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();

    if status.as_u16() == 429 {
        state.quota_tracker.record_rate_limit_error("hybrid_analysis", None);
        return Ok(super::common::source_error("hybrid_analysis", "rate limit exceeded"));
    }

    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("hybrid_analysis request failed: {status}")
    }

    state.quota_tracker.record_request("hybrid_analysis");
    state.quota_tracker.record_success("hybrid_analysis");

    let verdict = body["verdict"].as_str().unwrap_or("unknown");
    let severity = match verdict {
        "malicious" => "high",
        "suspicious" => "medium",
        _ => "low",
    };

    Ok(success(
        "hybrid_analysis",
        "Hybrid Analysis hash lookup",
        severity,
        serde_json::json!({"verdict": verdict}),
        body,
    ))
}