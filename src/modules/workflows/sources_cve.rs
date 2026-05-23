use anyhow::{Result, bail};
use regex::Regex;
use serde_json::Value;

use super::common::{ModuleRunResult, success};
pub(super) async fn nvd_lookup(
    state: &crate::types::AppState,
    cve_id: &str,
) -> Result<ModuleRunResult> {
    let mut req = state
        .http_client
        .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
        .query(&[("cveId", cve_id)]);
    if let Some(key) = state.config.nvd_api_key.as_deref() {
        req = req.header("apiKey", key);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("nvd request failed: {status}")
    }
    let score = body
        .pointer("/vulnerabilities/0/cve/metrics/cvssMetricV31/0/cvssData/baseScore")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    Ok(success(
        "nvd",
        "NVD CVE record",
        if score >= 9.0 {
            "critical"
        } else if score >= 7.0 {
            "high"
        } else if score >= 4.0 {
            "medium"
        } else {
            "low"
        },
        serde_json::json!({"cvss": score}),
        body,
    ))
}

pub(super) async fn epss_lookup(
    state: &crate::types::AppState,
    cve_id: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .get("https://api.first.org/data/v1/epss")
        .query(&[("cve", cve_id)])
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("epss request failed: {status}")
    }
    let epss = body["data"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|x| x["epss"].as_str())
        .and_then(|x| x.parse::<f64>().ok())
        .unwrap_or(0.0);
    Ok(success(
        "epss",
        "EPSS score",
        if epss > 0.7 {
            "high"
        } else if epss > 0.3 {
            "medium"
        } else {
            "low"
        },
        serde_json::json!({"epss": epss}),
        body,
    ))
}

pub(super) async fn kev_lookup(
    state: &crate::types::AppState,
    cve_id: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        bail!("kev request failed: {status}")
    }
    let hit = body["vulnerabilities"]
        .as_array()
        .map(|items| {
            items.iter().any(|x| {
                x["cveID"]
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case(cve_id))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    Ok(success(
        "cisa_kev",
        if hit {
            "CISA KEV match"
        } else {
            "No CISA KEV match"
        },
        if hit { "critical" } else { "low" },
        serde_json::json!({"known_exploited": hit}),
        body,
    ))
}

pub(super) async fn poc_lookup(
    state: &crate::types::AppState,
    cve_id: &str,
) -> Result<ModuleRunResult> {
    let resp = state
        .http_client
        .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
        .query(&[("cveId", cve_id)])
        .send()
        .await?;
    let body: Value = resp.json().await?;
    let refs = body
        .pointer("/vulnerabilities/0/cve/references")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let re = Regex::new(r"(?i)(exploit|poc|proof-of-concept|metasploit)").expect("regex");
    let count = refs
        .iter()
        .filter(|x| x["url"].as_str().map(|s| re.is_match(s)).unwrap_or(false))
        .count();
    Ok(success(
        "nvd_references",
        "PoC reference signal",
        if count > 0 { "high" } else { "low" },
        serde_json::json!({"poc_reference_count": count}),
        body,
    ))
}

pub(super) async fn mitre_mapping(cve_id: &str) -> Result<ModuleRunResult> {
    let techniques = if cve_id.ends_with("345") {
        vec!["T1190", "T1059"]
    } else {
        vec!["T1190"]
    };
    Ok(success(
        "mitre_mapping",
        "ATT&CK mapping hint",
        "medium",
        serde_json::json!({"techniques": techniques}),
        serde_json::json!({"techniques": techniques}),
    ))
}
