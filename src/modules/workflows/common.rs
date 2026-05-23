use anyhow::{Result, bail};
use chrono::Utc;
use serde_json::Value;

use crate::auth::AuthIdentity;
use crate::db::AuditEvent;
use crate::types::{Finding, InvestigationResult, OutputMode, RiskInfo, SourceStatus};

#[derive(Debug)]
pub(super) struct ModuleRunResult {
    pub findings: Vec<Finding>,
    pub sources: Vec<SourceStatus>,
    pub raw: Value,
}

pub(super) fn success(
    source: &str,
    title: &str,
    severity: &str,
    evidence: Value,
    raw: Value,
) -> ModuleRunResult {
    ModuleRunResult {
        findings: vec![Finding {
            title: title.to_string(),
            severity: severity.to_string(),
            confidence: "medium".to_string(),
            source: source.to_string(),
            evidence,
            analyst_note: "Source evidence should be validated against asset context.".to_string(),
        }],
        sources: vec![SourceStatus {
            name: source.to_string(),
            status: "ok".to_string(),
            queried_at: Utc::now(),
            cached: false,
            error: None,
        }],
        raw,
    }
}

pub(super) fn missing_key(source: &str, env_key: &str) -> ModuleRunResult {
    ModuleRunResult {
        findings: vec![Finding {
            title: format!("Source {source} not configured"),
            severity: "low".to_string(),
            confidence: "high".to_string(),
            source: source.to_string(),
            evidence: serde_json::json!({"configured": false, "required_env": env_key}),
            analyst_note: format!("Set {env_key} to enable this source."),
        }],
        sources: vec![SourceStatus {
            name: source.to_string(),
            status: "not_configured".to_string(),
            queried_at: Utc::now(),
            cached: false,
            error: Some("missing_api_key".to_string()),
        }],
        raw: serde_json::json!({"configured": false}),
    }
}

pub(super) fn source_error(source: &str, error: &str) -> ModuleRunResult {
    ModuleRunResult {
        findings: vec![Finding {
            title: format!("Source {source} query failed"),
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            source: source.to_string(),
            evidence: serde_json::json!({
                "error_class": "source_request_error",
                "message": error,
            }),
            analyst_note: "Treat this source as unavailable and confirm with alternate sources."
                .to_string(),
        }],
        sources: vec![SourceStatus {
            name: source.to_string(),
            status: "error".to_string(),
            queried_at: Utc::now(),
            cached: false,
            error: Some("source_request_error".to_string()),
        }],
        raw: serde_json::json!({
            "error": "source_request_error"
        }),
    }
}

pub(super) fn calculate_risk_from_findings(findings: &[Finding]) -> RiskInfo {
    let mut score = 0_u8;
    for finding in findings {
        score = score.saturating_add(match finding.severity.as_str() {
            "critical" => 25,
            "high" => 18,
            "medium" => 10,
            "low" => 4,
            _ => 2,
        });
    }
    let severity = if score >= 80 {
        "critical"
    } else if score >= 60 {
        "high"
    } else if score >= 30 {
        "medium"
    } else {
        "low"
    };
    RiskInfo {
        score,
        severity: severity.to_string(),
        confidence: if findings.len() >= 6 {
            "high"
        } else if findings.len() >= 3 {
            "medium"
        } else {
            "low"
        }
        .to_string(),
        reasoning: vec![
            format!("{} findings contributed to score", findings.len()),
            "Severity-weighted scoring with source confidence".to_string(),
        ],
    }
}

pub(super) fn mask_output_mode(
    mut result: InvestigationResult,
    output_mode: OutputMode,
    auth: &AuthIdentity,
) -> Result<InvestigationResult> {
    match output_mode {
        OutputMode::Summary => {
            result.raw = serde_json::json!({});
            Ok(result)
        }
        OutputMode::Evidence => Ok(result),
        OutputMode::Raw => {
            if auth
                .scopes
                .iter()
                .any(|s| s == "mcp:raw" || s == "mcp:admin")
            {
                Ok(result)
            } else {
                bail!("raw output requires mcp:raw or mcp:admin scope")
            }
        }
    }
}

pub(super) async fn audit(
    state: &crate::types::AppState,
    target: &str,
    target_type: &str,
    tool: &str,
    sources: &[SourceStatus],
    duration_ms: i64,
    auth_method: &str,
) -> Result<()> {
    state
        .db
        .audit_insert(AuditEvent {
            request_id: uuid::Uuid::new_v4().to_string(),
            tool: tool.to_string(),
            target: target.to_string(),
            target_type: target_type.to_string(),
            sources_requested: vec![],
            sources_used: sources.iter().map(|s| s.name.clone()).collect(),
            cache_hit: false,
            duration_ms,
            status: "ok".to_string(),
            error_class: None,
            auth_method: auth_method.to_string(),
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_score_orders_severity() {
        let findings = vec![
            Finding {
                title: "a".to_string(),
                severity: "high".to_string(),
                confidence: "high".to_string(),
                source: "x".to_string(),
                evidence: serde_json::json!({}),
                analyst_note: "n".to_string(),
            },
            Finding {
                title: "b".to_string(),
                severity: "low".to_string(),
                confidence: "high".to_string(),
                source: "x".to_string(),
                evidence: serde_json::json!({}),
                analyst_note: "n".to_string(),
            },
        ];
        let risk = calculate_risk_from_findings(&findings);
        assert!(risk.score >= 20);
    }
}
