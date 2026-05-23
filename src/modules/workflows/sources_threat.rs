use anyhow::{Result, bail};
use serde_json::Value;

use super::common::{ModuleRunResult, missing_key, success};
pub(super) async fn virustotal_lookup(
    state: &crate::types::AppState,
    query: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.virustotal_api_key.as_deref() else {
        return Ok(missing_key("virustotal", "VIRUSTOTAL_API_KEY"));
    };
    let resp = state
        .http_client
        .get("https://www.virustotal.com/api/v3/search")
        .query(&[("query", query)])
        .header("x-apikey", key)
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("virustotal request failed: {status}")
    }
    Ok(success(
        "virustotal",
        "VirusTotal lookup",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn urlscan_lookup(
    state: &crate::types::AppState,
    query: &str,
) -> Result<ModuleRunResult> {
    let Some(key) = state.config.urlscan_api_key.as_deref() else {
        return Ok(missing_key("urlscan", "URLSCAN_API_KEY"));
    };
    let resp = state
        .http_client
        .get("https://urlscan.io/api/v1/search/")
        .query(&[("q", query)])
        .header("API-Key", key)
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("urlscan request failed: {status}")
    }
    Ok(success(
        "urlscan",
        "URLScan lookup",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn malwarebazaar_lookup(
    state: &crate::types::AppState,
    hash: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .post("https://mb-api.abuse.ch/api/v1/")
        .form(&[("query", "get_info"), ("hash", hash)])
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({"query_status":"unknown"}));
    if !status.is_success() {
        bail!("malwarebazaar request failed: {status}")
    }
    Ok(success(
        "malwarebazaar",
        "MalwareBazaar lookup",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn threatfox_lookup(
    state: &crate::types::AppState,
    query: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .post("https://threatfox-api.abuse.ch/api/v1/")
        .json(&serde_json::json!({"query":"search_ioc","search_term":query}))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({"query_status":"unknown"}));
    if !status.is_success() {
        bail!("threatfox request failed: {status}")
    }
    Ok(success(
        "threatfox",
        "ThreatFox IOC lookup",
        "medium",
        body.clone(),
        body,
    ))
}

pub(super) async fn ransomwhere_lookup(
    state: &crate::types::AppState,
    query: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .get("https://api.ransomwhe.re/export")
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("ransomwhere request failed: {status}")
    }
    let lc = query.to_ascii_lowercase();
    let count = body["result"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|x| x.to_string().to_ascii_lowercase().contains(&lc))
                .count()
        })
        .unwrap_or(0);
    Ok(success(
        "ransomwhere",
        "Ransomwhere signal",
        if count > 0 { "high" } else { "low" },
        serde_json::json!({"match_count": count}),
        body,
    ))
}
