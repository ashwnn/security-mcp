use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Rate-limit window types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitWindow {
    PerMinute,
    PerHour,
    PerDay,
    PerMonth,
    Concurrent,
    Unknown,
}

impl RateLimitWindow {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PerMinute => "per_minute",
            Self::PerHour => "per_hour",
            Self::PerDay => "per_day",
            Self::PerMonth => "per_month",
            Self::Concurrent => "concurrent",
            Self::Unknown => "unknown",
        }
    }
}

/// Known rate-limit plans
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitPlan {
    Free,
    Paid,
    Enterprise,
    Unlimited,
}

impl RateLimitPlan {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Paid => "paid",
            Self::Enterprise => "enterprise",
            Self::Unlimited => "unlimited",
        }
    }
}

/// Source of truth for quota data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuotaSourceOfTruth {
    ResponseHeaders,
    ProviderDocs,
    ConfigOverride,
    LocalCounter,
    Unknown,
}

impl QuotaSourceOfTruth {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ResponseHeaders => "response_headers",
            Self::ProviderDocs => "provider_docs",
            Self::ConfigOverride => "config_override",
            Self::LocalCounter => "local_counter",
            Self::Unknown => "unknown",
        }
    }
}

/// Source quota status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuotaStatus {
    Configured,
    NotConfigured,
    Disabled,
    Ok,
    Cached,
    Partial,
    Error,
    Timeout,
    RateLimited,
    NearLimit,
    QuotaProtected,
    SoftBlocked,
    UnknownLimit,
}

impl QuotaStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::NotConfigured => "not_configured",
            Self::Disabled => "disabled",
            Self::Ok => "ok",
            Self::Cached => "cached",
            Self::Partial => "partial",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::NearLimit => "near_limit",
            Self::QuotaProtected => "quota_protected",
            Self::SoftBlocked => "soft_blocked",
            Self::UnknownLimit => "unknown_limit",
        }
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::QuotaProtected | Self::SoftBlocked)
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, Self::NearLimit | Self::RateLimited)
    }
}

/// Per-source quota tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceQuota {
    pub source: String,
    pub category: String,
    pub plan: RateLimitPlan,
    pub limit_window: RateLimitWindow,
    pub cap: Option<u64>,
    pub used: u64,
    pub remaining: Option<u64>,
    pub remaining_percent: Option<f64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub last_request: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub last_rate_limit_error: Option<DateTime<Utc>>,
    pub source_of_truth: QuotaSourceOfTruth,
    pub status: QuotaStatus,
}

impl SourceQuota {
    pub fn new(source: &str, category: &str) -> Self {
        Self {
            source: source.to_string(),
            category: category.to_string(),
            plan: RateLimitPlan::Free,
            limit_window: RateLimitWindow::Unknown,
            cap: None,
            used: 0,
            remaining: None,
            remaining_percent: None,
            reset_at: None,
            last_request: None,
            last_success: None,
            last_rate_limit_error: None,
            source_of_truth: QuotaSourceOfTruth::Unknown,
            status: QuotaStatus::UnknownLimit,
        }
    }

    /// Check if source should be skipped due to quota protection
    pub fn should_skip(&self, warn_threshold: f64, block_threshold: f64, soft_block_enabled: bool) -> bool {
        // If not configured, skip
        if self.status == QuotaStatus::NotConfigured || self.status == QuotaStatus::Disabled {
            return true;
        }

        // If rate limited by provider, skip
        if self.status == QuotaStatus::RateLimited {
            return true;
        }

        // Check remaining percentage
        if let Some(pct) = self.remaining_percent {
            // Block at 5% if soft block enabled
            if soft_block_enabled && pct <= block_threshold {
                return true;
            }
        }

        false
    }

    /// Check if source is near warning threshold
    pub fn is_near_limit(&self, warn_threshold: f64) -> bool {
        if let Some(pct) = self.remaining_percent {
            return pct <= warn_threshold && pct > 0.0;
        }
        false
    }

    /// Update from rate-limit headers if present
    pub fn update_from_headers(&mut self, remaining: Option<u64>, reset: Option<i64>) {
        if remaining.is_some() || reset.is_some() {
            self.source_of_truth = QuotaSourceOfTruth::ResponseHeaders;
        }
        if let Some(r) = remaining {
            self.remaining = Some(r);
            if let Some(cap) = self.cap {
                if cap > 0 {
                    self.remaining_percent = Some((r as f64 / cap as f64) * 100.0);
                    self.status = if self.is_near_limit(20.0) {
                        QuotaStatus::NearLimit
                    } else {
                        QuotaStatus::Ok
                    };
                }
            }
        }
        if let Some(reset_ts) = reset {
            self.reset_at = DateTime::from_timestamp(reset_ts, 0);
        }
    }
}

/// Global rate-limit policy
#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    pub default_plan: RateLimitPlan,
    pub warn_remaining_percent: f64,
    pub block_remaining_percent: f64,
    pub soft_block_enabled: bool,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            default_plan: RateLimitPlan::Free,
            warn_remaining_percent: 20.0,
            block_remaining_percent: 5.0,
            soft_block_enabled: true,
        }
    }
}

/// In-memory quota tracker
#[derive(Debug, Clone)]
pub struct QuotaTracker {
    policy: RateLimitPolicy,
    quotas: RwLock<HashMap<String, SourceQuota>>,
}

impl QuotaTracker {
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            quotas: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_quota(&self, source: &str) -> Option<SourceQuota> {
        self.quotas.read().ok().and_then(|q| q.get(source).cloned())
    }

    pub fn set_quota(&self, quota: SourceQuota) {
        if let Ok(mut q) = self.quotas.write() {
            q.insert(quota.source.clone(), quota);
        }
    }

    pub fn record_request(&self, source: &str) {
        if let Ok(mut q) = self.quotas.write() {
            if let Some(quota) = q.get_mut(source) {
                quota.used += 1;
                quota.last_request = Some(Utc::now());

                // Update remaining if we have a cap
                if let Some(cap) = quota.cap {
                    if cap > 0 {
                        quota.remaining = Some(cap.saturating_sub(quota.used));
                        quota.remaining_percent = Some((quota.remaining.unwrap_or(0) as f64 / cap as f64) * 100.0);

                        // Update status
                        if let Some(pct) = quota.remaining_percent {
                            quota.status = if pct <= self.policy.block_remaining_percent {
                                QuotaStatus::QuotaProtected
                            } else if pct <= self.policy.warn_remaining_percent {
                                QuotaStatus::NearLimit
                            } else {
                                QuotaStatus::Ok
                            };
                        }
                    }
                }
            }
        }
    }

    pub fn record_success(&self, source: &str) {
        if let Ok(mut q) = self.quotas.write() {
            if let Some(quota) = q.get_mut(source) {
                quota.last_success = Some(Utc::now());
                // Clear rate-limited status on success
                if quota.status == QuotaStatus::RateLimited {
                    quota.status = QuotaStatus::Ok;
                }
            }
        }
    }

    pub fn record_rate_limit_error(&self, source: &str, retry_after: Option<i64>) {
        if let Ok(mut q) = self.quotas.write() {
            if let Some(quota) = q.get_mut(source) {
                quota.last_rate_limit_error = Some(Utc::now());
                quota.status = QuotaStatus::RateLimited;

                if let Some(after) = retry_after {
                    let reset = Utc::now() + chrono::Duration::seconds(after);
                    quota.reset_at = Some(reset);
                }
            }
        }
    }

    pub fn record_timeout(&self, source: &str) {
        if let Ok(mut q) = self.quotas.write() {
            if let Some(quota) = q.get_mut(source) {
                quota.status = QuotaStatus::Timeout;
            }
        }
    }

    pub fn record_error(&self, source: &str) {
        if let Ok(mut q) = self.quotas.write() {
            if let Some(quota) = q.get_mut(source) {
                quota.status = QuotaStatus::Error;
            }
        }
    }

    /// Get all quotas as a list
    pub fn all_quotas(&self) -> Vec<SourceQuota> {
        self.quotas.read().ok()
            .map(|q| q.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get sources that should be skipped
    pub fn sources_to_skip(&self) -> Vec<(String, String)> {
        let mut skipped = Vec::new();
        if let Ok(q) = self.quotas.read() {
            for (source, quota) in q.iter() {
                if quota.should_skip(self.policy.warn_remaining_percent, self.policy.block_remaining_percent, self.policy.soft_block_enabled) {
                    let reason = if quota.status == QuotaStatus::QuotaProtected {
                        "quota_protected"
                    } else if quota.status == QuotaStatus::RateLimited {
                        "provider_rate_limited"
                    } else {
                        "quota_exhausted"
                    };
                    skipped.push((source.clone(), reason.to_string()));
                }
            }
        }
        skipped
    }

    /// Get sources that are near their limit
    pub fn sources_near_limit(&self) -> Vec<String> {
        let mut near = Vec::new();
        if let Ok(q) = self.quotas.read() {
            for (source, quota) in q.iter() {
                if quota.is_near_limit(self.policy.warn_remaining_percent) {
                    near.push(source.clone());
                }
            }
        }
        near
    }
}

/// Rate-limit summary for MCP responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSummary {
    pub policy: RateLimitPolicyInfo,
    pub sources: Vec<SourceQuotaSummary>,
    pub skipped: Vec<SkippedSource>,
    pub cache: CacheStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicyInfo {
    pub plan: String,
    pub warn_remaining_percent: f64,
    pub block_remaining_percent: f64,
    pub soft_block_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceQuotaSummary {
    pub source: String,
    pub status: String,
    pub limit_window: String,
    pub cap: Option<u64>,
    pub used: u64,
    pub remaining: Option<u64>,
    pub remaining_percent: Option<f64>,
    pub reset_at: Option<String>,
    pub source_of_truth: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedSource {
    pub source: String,
    pub reason: String,
    pub remaining_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

impl RateLimitSummary {
    pub fn new(policy: &RateLimitPolicy, cache_hits: u64, cache_misses: u64) -> Self {
        Self {
            policy: RateLimitPolicyInfo {
                plan: policy.default_plan.as_str().to_string(),
                warn_remaining_percent: policy.warn_remaining_percent,
                block_remaining_percent: policy.block_remaining_percent,
                soft_block_enabled: policy.soft_block_enabled,
            },
            sources: Vec::new(),
            skipped: Vec::new(),
            cache: CacheStats {
                hits: cache_hits,
                misses: cache_misses,
            },
        }
    }

    pub fn add_source(&mut self, quota: &SourceQuota) {
        self.sources.push(SourceQuotaSummary {
            source: quota.source.clone(),
            status: quota.status.as_str().to_string(),
            limit_window: quota.limit_window.as_str().to_string(),
            cap: quota.cap,
            used: quota.used,
            remaining: quota.remaining,
            remaining_percent: quota.remaining_percent,
            reset_at: quota.reset_at.map(|dt| dt.to_rfc3339()),
            source_of_truth: quota.source_of_truth.as_str().to_string(),
        });
    }

    pub fn add_skipped(&mut self, source: &str, reason: &str, remaining_pct: Option<f64>) {
        self.skipped.push(SkippedSource {
            source: source.to_string(),
            reason: reason.to_string(),
            remaining_percent: remaining_pct,
        });
    }
}

/// Parse Retry-After header value
pub fn parse_retry_after(value: &str) -> Option<i64> {
    // Try HTTP-date format first
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(value) {
        let now = Utc::now();
        let diff = (dt.with_timezone(&Utc) - now).num_seconds();
        return Some(diff.max(0));
    }

    // Try seconds format
    value.trim().parse().ok()
}

/// Parse X-RateLimit-* headers if present
pub fn parse_rate_limit_headers(headers: &http::HeaderMap) -> Option<(Option<u64>, Option<i64>)> {
    // Different providers use different header names
    let limit = headers.get("X-RateLimit-Limit")
        .or_else(|| headers.get("X-Rate-Lem"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let remaining = headers.get("X-RateLimit-Remaining")
        .or_else(|| headers.get("X-Rate-Remaining"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let reset = headers.get("X-RateLimit-Reset")
        .or_else(|| headers.get("X-Rate-Reset"))
        .or_else(|| headers.get("X-Quota-Reset"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    Some((remaining.or(limit), reset))
}

/// Default quota configuration for known sources
pub fn default_source_quotas() -> Vec<(&'static str, &'static str, RateLimitPlan, RateLimitWindow, Option<u64>)> {
    vec![
        // Source, Category, Plan, Window, Cap
        ("nvd", "cve", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(50)),
        ("epss", "cve", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(60)),
        ("cisa_kev", "cve", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(100)),
        ("abuseipdb", "network", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(1000)),
        ("greynoise", "network", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(250)),
        ("shodan", "network", RateLimitPlan::Free, RateLimitWindow::PerMonth, Some(100)),
        ("virustotal", "threat", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(500)),
        ("urlscan", "threat", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(100)),
        ("circl_passive_dns", "network", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(500)),
        ("rdap", "domain", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(60)),
        ("dns_over_https", "domain", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(120)),
        ("crtsh", "domain", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(30)),
        ("malwarebazaar", "threat", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(500)),
        ("threatfox", "threat", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(500)),
        ("ransomwhere", "threat", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(200)),
        ("osv", "devsecops", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(60)),
        ("github", "devsecops", RateLimitPlan::Free, RateLimitWindow::PerHour, Some(5000)),
        // New sources
        ("censys", "network", RateLimitPlan::Free, RateLimitWindow::PerMonth, Some(250)),
        ("securitytrails", "domain", RateLimitPlan::Free, RateLimitWindow::PerMonth, Some(100)),
        ("otx", "threat", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(50)),
        ("misp", "threat", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(60)),
        ("google_safe_browsing", "threat", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(10000)),
        ("pulsedive", "threat", RateLimitPlan::Free, RateLimitWindow::PerDay, Some(500)),
        ("hybrid_analysis", "threat", RateLimitPlan::Free, RateLimitWindow::PerMinute, Some(10)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_status_checks() {
        let mut quota = SourceQuota::new("test", "threat");
        quota.cap = Some(100);
        quota.used = 5;
        quota.remaining = Some(95);
        quota.remaining_percent = Some(95.0);

        assert!(!quota.is_near_limit(20.0));

        quota.used = 85;
        quota.remaining = Some(15);
        quota.remaining_percent = Some(15.0);

        assert!(quota.is_near_limit(20.0));
        assert!(!quota.should_skip(20.0, 5.0, true)); // 15% > 5%, so not blocked

        quota.used = 96;
        quota.remaining = Some(4);
        quota.remaining_percent = Some(4.0);

        assert!(quota.should_skip(20.0, 5.0, true)); // 4% <= 5%, blocked
    }

    #[test]
    fn skip_not_configured() {
        let mut quota = SourceQuota::new("test", "threat");
        quota.status = QuotaStatus::NotConfigured;

        assert!(quota.should_skip(20.0, 5.0, true));
    }

    #[test]
    fn parse_retry_after_seconds() {
        assert_eq!(parse_retry_after("120"), Some(120));
        assert_eq!(parse_retry_after("3600"), Some(3600));
    }

    #[test]
    fn quota_tracker_records() {
        let tracker = QuotaTracker::new(RateLimitPolicy::default());

        let mut quota = SourceQuota::new("test_source", "threat");
        quota.cap = Some(100);
        tracker.set_quota(quota);

        tracker.record_request("test_source");
        tracker.record_success("test_source");

        let quota = tracker.get_quota("test_source").unwrap();
        assert_eq!(quota.used, 1);
        assert!(quota.last_success.is_some());
    }

    #[test]
    fn rate_limit_summary_builder() {
        let policy = RateLimitPolicy::default();
        let mut summary = RateLimitSummary::new(&policy, 5, 3);

        let mut quota = SourceQuota::new("test", "threat");
        quota.cap = Some(100);
        quota.used = 20;
        quota.remaining = Some(80);
        quota.remaining_percent = Some(80.0);

        summary.add_source(&quota);
        summary.add_skipped("blocked_source", "quota_protected", Some(3.0));

        assert_eq!(summary.sources.len(), 1);
        assert_eq!(summary.skipped.len(), 1);
        assert_eq!(summary.cache.hits, 5);
    }
}