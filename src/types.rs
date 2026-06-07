use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    db::Database,
    modules::Registry,
    oauth::SimpleRateLimiter,
    rate_limit::{QuotaTracker, RateLimitSummary},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub registry: Registry,
    pub http_client: reqwest::Client,
    pub auth_rate_limiter: Arc<SimpleRateLimiter>,
    pub lookup_rate_limiter: Arc<SimpleRateLimiter>,
    pub quota_tracker: Arc<QuotaTracker>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RiskInfo {
    pub score: u8,
    pub severity: String,
    pub confidence: String,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub source: String,
    pub evidence: serde_json::Value,
    pub analyst_note: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceStatus {
    pub name: String,
    pub status: String,
    pub queried_at: DateTime<Utc>,
    pub cached: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InvestigationResult {
    pub target: String,
    pub target_type: String,
    pub mode: String,
    pub risk: RiskInfo,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub sources: Vec<SourceStatus>,
    pub raw: serde_json::Value,
    pub unknowns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_summary: Option<RateLimitSummary>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InvestigationInput {
    pub target: String,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub depth: Option<String>,
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CveInvestigationInput {
    pub cve_id: String,
    #[serde(default = "default_true")]
    pub include_epss: bool,
    #[serde(default = "default_true")]
    pub include_kev: bool,
    #[serde(default = "default_true")]
    pub include_poc: bool,
    #[serde(default = "default_true")]
    pub include_mitre: bool,
    #[serde(default = "default_true")]
    pub include_vendor_advisories: bool,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IndicatorInvestigationInput {
    pub indicator: String,
    #[serde(default)]
    pub indicator_type: Option<String>,
    #[serde(default = "default_true")]
    pub include_reputation: bool,
    #[serde(default = "default_true")]
    pub include_passive_dns: bool,
    #[serde(default = "default_true")]
    pub include_malware: bool,
    #[serde(default = "default_true")]
    pub include_url_safety: bool,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PackageRef {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DependencyScanInput {
    #[serde(default)]
    pub ecosystem: Option<String>,
    #[serde(default)]
    pub packages: Vec<PackageRef>,
    #[serde(default)]
    pub file_type: Option<String>,
    #[serde(default)]
    pub file_content: Option<String>,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompareInput {
    pub items: Vec<String>,
    #[serde(default)]
    pub comparison_type: Option<String>,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ToolCatalogInput {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub configured_only: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RunToolInput {
    pub tool_id: String,
    pub args: serde_json::Value,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputMode {
    Summary,
    Evidence,
    Raw,
}

impl OutputMode {
    pub fn from_str(value: Option<&str>) -> Self {
        match value.unwrap_or("summary") {
            "evidence" => Self::Evidence,
            "raw" => Self::Raw,
            _ => Self::Summary,
        }
    }
}

pub fn default_true() -> bool {
    true
}
