use anyhow::Result;
use serde_json::Value;

use super::common::{ModuleRunResult, missing_key};
use crate::types::{Finding, SourceStatus};
use chrono::Utc;
pub(super) async fn osv_scan(
    state: &crate::types::AppState,
    args: Value,
) -> Result<ModuleRunResult> {
    let packages = args["packages"].as_array().cloned().unwrap_or_default();
    let ecosystem = args["ecosystem"].as_str().unwrap_or("auto");
    let mut findings = Vec::new();
    let mut raw = Vec::new();
    for pkg in packages {
        let name = pkg["name"].as_str().unwrap_or_default();
        let version = pkg["version"].as_str().unwrap_or_default();
        let eco = if ecosystem == "auto" {
            if name.contains('/') { "Go" } else { "PyPI" }.to_string()
        } else {
            ecosystem.to_string()
        };
        let req = serde_json::json!({"package":{"name":name,"ecosystem":eco},"version":version});
        let resp = state
            .http_client
            .post("https://api.osv.dev/v1/query")
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            continue;
        }
        let body: Value = resp.json().await?;
        let count = body["vulns"].as_array().map(|a| a.len()).unwrap_or(0);
        findings.push(Finding {
            title: format!("OSV vulnerabilities for {name}"),
            severity: if count > 5 {
                "high"
            } else if count > 0 {
                "medium"
            } else {
                "low"
            }
            .to_string(),
            confidence: "medium".to_string(),
            source: "osv".to_string(),
            evidence: serde_json::json!({"package": name, "version": version, "vuln_count": count}),
            analyst_note: "Review version ranges and fixed versions for remediation planning."
                .to_string(),
        });
        raw.push(serde_json::json!({"package": name, "response": body}));
    }
    Ok(ModuleRunResult {
        findings,
        sources: vec![SourceStatus {
            name: "osv".to_string(),
            status: "ok".to_string(),
            queried_at: Utc::now(),
            cached: false,
            error: None,
        }],
        raw: Value::Array(raw),
    })
}

pub(super) async fn github_advisory_scan(
    state: &crate::types::AppState,
    args: Value,
) -> Result<ModuleRunResult> {
    let Some(token) = state.config.github_token.as_deref() else {
        return Ok(missing_key("github", "GITHUB_TOKEN"));
    };
    let packages = args["packages"].as_array().cloned().unwrap_or_default();
    let mut findings = Vec::new();
    let mut raw = Vec::new();
    for pkg in packages {
        let name = pkg["name"].as_str().unwrap_or_default();
        let resp = state
            .http_client
            .get("https://api.github.com/search/advisories")
            .query(&[("q", format!("{name} in:name,description"))])
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(token)
            .send()
            .await?;
        if !resp.status().is_success() {
            continue;
        }
        let body: Value = resp.json().await?;
        let total = body["total_count"].as_u64().unwrap_or(0);
        findings.push(Finding {
            title: format!("GitHub advisories for {name}"),
            severity: if total > 10 {
                "high"
            } else if total > 0 {
                "medium"
            } else {
                "low"
            }
            .to_string(),
            confidence: "low".to_string(),
            source: "github".to_string(),
            evidence: serde_json::json!({"package": name, "advisory_count": total}),
            analyst_note: "Search-based advisory lookup can include false positives.".to_string(),
        });
        raw.push(serde_json::json!({"package": name, "response": body}));
    }
    Ok(ModuleRunResult {
        findings,
        sources: vec![SourceStatus {
            name: "github".to_string(),
            status: "ok".to_string(),
            queried_at: Utc::now(),
            cached: false,
            error: None,
        }],
        raw: Value::Array(raw),
    })
}
