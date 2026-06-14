use std::collections::BTreeSet;

use anyhow::{Result, bail};
use chrono::Utc;
use serde_json::Value;

use super::common::{
    ModuleRunResult, audit, calculate_risk_from_findings, mask_output_mode, source_error,
};
use super::local::{HashClassification, IocExtraction, classify_hash, extract_iocs};
use super::sources_cve::{epss_lookup, kev_lookup, mitre_mapping, nvd_lookup, poc_lookup};
use super::sources_deps::{github_advisory_scan, osv_scan};
use super::sources_infra::{
    abuseipdb_lookup, circl_pdns_lookup, cloud_hint, crtsh_lookup, doh_lookup, greynoise_lookup,
    http_headers_lookup, rdap_lookup, shodan_lookup, technology_hint,
};
use super::sources_new::{
    censys_lookup, hybrid_analysis_lookup, misp_lookup, otx_lookup, pulsedive_lookup,
};
use super::sources_threat::{
    malwarebazaar_lookup, ransomwhere_lookup, threatfox_lookup, urlscan_lookup, virustotal_lookup,
};
use crate::auth::AuthIdentity;
use crate::cache::CacheStore;
use crate::modules::parsers::parse_dependency_file;
use crate::modules::registry::Registry;
use crate::types::{
    CompareInput, CveInvestigationInput, DependencyScanInput, IndicatorInvestigationInput,
    InvestigationInput, InvestigationResult, OutputMode, SourceStatus, ToolCatalogInput,
};
use crate::validation::{
    TargetKind, detect_target_kind, validate_cve_id, validate_public_ip, validate_public_url,
};

#[derive(Debug, Clone)]
struct WorkflowOptions {
    mode: String,
    depth: String,
    sources: Vec<String>,
}

pub async fn security_investigate(
    state: &crate::types::AppState,
    input: InvestigationInput,
    auth: &AuthIdentity,
) -> Result<InvestigationResult> {
    let InvestigationInput {
        target,
        target_type,
        mode,
        depth,
        sources,
        output_mode,
    } = input;
    let opts = workflow_options(mode, depth, sources)?;

    let target_type = target_type.unwrap_or_else(|| match detect_target_kind(&target) {
        TargetKind::Cve => "cve".to_string(),
        TargetKind::Ip => "ip".to_string(),
        TargetKind::Domain => "domain".to_string(),
        TargetKind::Url => "url".to_string(),
        TargetKind::Hash => "hash".to_string(),
        TargetKind::Package => "package".to_string(),
        TargetKind::Unknown => "unknown".to_string(),
    });

    match target_type.as_str() {
        "cve" => {
            security_investigate_cve(
                state,
                CveInvestigationInput {
                    cve_id: target,
                    include_epss: true,
                    include_kev: true,
                    include_poc: true,
                    include_mitre: true,
                    include_vendor_advisories: true,
                    mode: Some(opts.mode),
                    depth: Some(opts.depth),
                    sources: Some(opts.sources),
                    output_mode,
                },
                auth,
            )
            .await
        }
        "ip" | "domain" | "url" | "hash" => {
            security_investigate_indicator(
                state,
                IndicatorInvestigationInput {
                    indicator: target,
                    indicator_type: Some(target_type),
                    include_reputation: true,
                    include_passive_dns: true,
                    include_malware: true,
                    include_url_safety: true,
                    mode: Some(opts.mode),
                    depth: Some(opts.depth),
                    sources: Some(opts.sources),
                    output_mode,
                },
                auth,
            )
            .await
        }
        _ => bail!("unsupported target type"),
    }
}

pub async fn security_investigate_cve(
    state: &crate::types::AppState,
    input: CveInvestigationInput,
    auth: &AuthIdentity,
) -> Result<InvestigationResult> {
    let start = std::time::Instant::now();
    validate_cve_id(&input.cve_id)?;
    let opts = workflow_options(input.mode.clone(), input.depth.clone(), input.sources.clone())?;

    let mut findings = Vec::new();
    let mut sources = Vec::new();
    let mut raw = serde_json::Map::new();
    let (modules, unknowns) = cve_modules(&input, &opts);

    for module in modules {
        let run = run_module(
            state,
            module,
            &input.cve_id,
            serde_json::json!({ "cve_id": input.cve_id }),
            auth,
        )
        .await?;
        findings.extend(run.findings);
        sources.extend(run.sources);
        raw.insert(module.to_string(), run.raw);
    }

    let risk = calculate_risk_from_findings(&findings);
    let output_mode = OutputMode::from_str(input.output_mode.as_deref());
    let result = InvestigationResult {
        target: input.cve_id.clone(),
        target_type: "cve".to_string(),
        mode: format!("cve_investigation:{}:{}", opts.mode, opts.depth),
        risk,
        summary: format!("{} findings for {}", findings.len(), input.cve_id),
        findings,
        sources,
        raw: Value::Object(raw),
        unknowns,
        rate_limit_summary: None,
    };

    audit(
        state,
        &input.cve_id,
        "cve",
        "security_investigate_cve",
        &result.sources,
        start.elapsed().as_millis() as i64,
        &auth.method,
    )
    .await?;

    mask_output_mode(result, output_mode, auth)
}

pub async fn security_investigate_indicator(
    state: &crate::types::AppState,
    input: IndicatorInvestigationInput,
    auth: &AuthIdentity,
) -> Result<InvestigationResult> {
    let opts = workflow_options(input.mode.clone(), input.depth.clone(), input.sources.clone())?;
    let indicator_type = input.indicator_type.clone().unwrap_or_else(|| {
        match detect_target_kind(&input.indicator) {
            TargetKind::Ip => "ip".to_string(),
            TargetKind::Domain => "domain".to_string(),
            TargetKind::Url => "url".to_string(),
            TargetKind::Hash => "hash".to_string(),
            _ => "unknown".to_string(),
        }
    });

    if indicator_type == "ip" {
        validate_public_ip(input.indicator.parse()?)?;
    }
    if indicator_type == "url" {
        validate_public_url(&input.indicator, state.config.allow_private_targets).await?;
    }

    let start = std::time::Instant::now();
    let mut findings = Vec::new();
    let mut sources = Vec::new();
    let mut raw = serde_json::Map::new();
    let (modules, unknowns) = indicator_modules(&input, &indicator_type, &opts)?;

    for module in modules {
        let run = run_module(
            state,
            module,
            &input.indicator,
            serde_json::json!({"indicator": input.indicator}),
            auth,
        )
        .await?;
        findings.extend(run.findings);
        sources.extend(run.sources);
        raw.insert(module.to_string(), run.raw);
    }

    let risk = calculate_risk_from_findings(&findings);
    let output_mode = OutputMode::from_str(input.output_mode.as_deref());
    let result = InvestigationResult {
        target: input.indicator.clone(),
        target_type: indicator_type.clone(),
        mode: format!("indicator_investigation:{}:{}", opts.mode, opts.depth),
        risk,
        summary: format!(
            "{indicator_type} investigation produced {} findings",
            findings.len()
        ),
        findings,
        sources,
        raw: Value::Object(raw),
        unknowns,
        rate_limit_summary: None,
    };

    audit(
        state,
        &input.indicator,
        &indicator_type,
        "security_investigate_indicator",
        &result.sources,
        start.elapsed().as_millis() as i64,
        &auth.method,
    )
    .await?;

    mask_output_mode(result, output_mode, auth)
}

pub async fn security_scan_dependencies(
    state: &crate::types::AppState,
    input: DependencyScanInput,
    auth: &AuthIdentity,
) -> Result<InvestigationResult> {
    let start = std::time::Instant::now();
    let mut packages = input.packages.clone();
    if let (Some(file_type), Some(file_content)) =
        (input.file_type.clone(), input.file_content.clone())
    {
        packages.extend(parse_dependency_file(&file_type, &file_content)?);
    }
    if packages.is_empty() {
        bail!("no packages provided")
    }

    let osv = run_module(
        state,
        "scan_dependencies",
        "dependency-set",
        serde_json::json!({"ecosystem": input.ecosystem, "packages": packages}),
        auth,
    )
    .await?;
    let ghsa = run_module(
        state,
        "scan_github_advisories",
        "dependency-set",
        serde_json::json!({"packages": packages}),
        auth,
    )
    .await?;

    let mut findings = osv.findings;
    findings.extend(ghsa.findings);
    let mut sources = osv.sources;
    sources.extend(ghsa.sources);
    let risk = calculate_risk_from_findings(&findings);

    let output_mode = OutputMode::from_str(input.output_mode.as_deref());
    let result = InvestigationResult {
        target: "dependency-set".to_string(),
        target_type: "package".to_string(),
        mode: "dependency_scan".to_string(),
        risk,
        summary: format!("{} dependency findings", findings.len()),
        findings,
        sources,
        raw: serde_json::json!({"osv": osv.raw, "github": ghsa.raw}),
        unknowns: vec![],
        rate_limit_summary: None,
    };

    audit(
        state,
        "dependency-set",
        "package",
        "security_scan_dependencies",
        &result.sources,
        start.elapsed().as_millis() as i64,
        &auth.method,
    )
    .await?;

    mask_output_mode(result, output_mode, auth)
}

pub async fn security_compare(
    _state: &crate::types::AppState,
    input: CompareInput,
    _auth: &AuthIdentity,
) -> Result<Value> {
    let _output_mode = input.output_mode.clone();
    let mut rows = input
        .items
        .into_iter()
        .map(|item| {
            let score = if item.to_ascii_uppercase().starts_with("CVE-") {
                75
            } else {
                40
            };
            serde_json::json!({"item": item, "score": score})
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b["score"].as_i64().cmp(&a["score"].as_i64()));
    Ok(serde_json::json!({
        "comparison_type": input.comparison_type.unwrap_or_else(|| "risk".to_string()),
        "results": rows
    }))
}

pub fn security_tool_catalog(
    registry: &Registry,
    config: &crate::config::Config,
    input: ToolCatalogInput,
) -> Value {
    let category = input.category.unwrap_or_else(|| "all".to_string());
    let configured_only = input.configured_only.unwrap_or(false);
    let mut modules = Vec::new();

    for m in registry.list() {
        if category != "all" && m.category != category {
            continue;
        }
        let configured = m
            .required_source
            .as_ref()
            .map(|s| config.source_configured(s))
            .unwrap_or(true);
        if configured_only && !configured {
            continue;
        }
        modules.push(serde_json::json!({
            "id": m.id,
            "name": m.name,
            "category": m.category,
            "description": m.description,
            "required_source": m.required_source,
            "configured": configured,
            "cache_ttl_seconds": m.cache_ttl_seconds,
        }));
    }

    serde_json::json!({
        "high_level_tools": registry.high_level_tools(),
        "internal_module_count": registry.list().len(),
        "modules": modules,
    })
}

pub async fn security_run_tool(
    state: &crate::types::AppState,
    tool_id: &str,
    args: Value,
    auth: &AuthIdentity,
) -> Result<Value> {
    if !state.config.expert_tool_enabled {
        bail!("expert tool dispatcher disabled")
    }
    if !auth
        .scopes
        .iter()
        .any(|s| s == "mcp:admin" || s == "mcp:raw")
    {
        bail!("insufficient scope")
    }
    if state.registry.module(tool_id).is_none() {
        bail!("unknown tool id")
    }
    let target = args
        .get("target")
        .or_else(|| args.get("cve_id"))
        .or_else(|| args.get("indicator"))
        .and_then(Value::as_str)
        .unwrap_or("input")
        .to_string();
    let run = run_module(state, tool_id, &target, args, auth).await?;
    Ok(serde_json::json!({
        "target": target,
        "findings": run.findings,
        "sources": run.sources,
        "raw": run.raw,
    }))
}

pub async fn security_extract_iocs(text: &str) -> Result<IocExtraction> {
    Ok(extract_iocs(text))
}

pub async fn security_classify_hash(hash: &str) -> Result<HashClassification> {
    Ok(classify_hash(hash))
}

async fn run_module(
    state: &crate::types::AppState,
    module_id: &str,
    target: &str,
    args: Value,
    _auth: &AuthIdentity,
) -> Result<ModuleRunResult> {
    let cache = CacheStore::new(state.db.clone(), state.config.cache_enabled);
    if let Some(hit) = cache.get(module_id, target, &args).await? {
        let findings = serde_json::from_value(hit["findings"].clone()).unwrap_or_default();
        let mut sources: Vec<SourceStatus> =
            serde_json::from_value(hit["sources"].clone()).unwrap_or_default();
        for s in &mut sources {
            s.cached = true;
        }
        return Ok(ModuleRunResult {
            findings,
            sources,
            raw: hit["raw"].clone(),
        });
    }

    let window = Utc::now().to_rfc3339();
    let run = match execute_module(state, module_id, target, args.clone()).await {
        Ok(run) => {
            let _ = state.db.source_mark_success(module_id).await;
            let _ = state
                .db
                .source_usage_record(module_id, &window, 1, 1, 0, 0, 0)
                .await;
            run
        }
        Err(err) => {
            let err_text = err.to_string();
            let timeout_count = i64::from(err_text.to_ascii_lowercase().contains("timeout"));
            let rate_limit_count = i64::from(err_text.to_ascii_lowercase().contains("rate limit"));
            let _ = state.db.source_mark_error(module_id, &err_text).await;
            let _ = state
                .db
                .source_usage_record(module_id, &window, 1, 0, 1, timeout_count, rate_limit_count)
                .await;
            source_error(module_id, &err_text)
        }
    };
    let ttl = state
        .registry
        .module(module_id)
        .map(|m| m.cache_ttl_seconds)
        .unwrap_or(3600);
    cache
        .set(
            module_id,
            target,
            &args,
            serde_json::json!({"findings": run.findings, "sources": run.sources, "raw": run.raw}),
            ttl,
        )
        .await?;
    Ok(run)
}

async fn execute_module(
    state: &crate::types::AppState,
    module_id: &str,
    target: &str,
    args: Value,
) -> Result<ModuleRunResult> {
    let rate_key = format!("{}:{}", module_id, target.to_ascii_lowercase());
    if !state.lookup_rate_limiter.check(&rate_key) {
        bail!("rate limit exceeded")
    }

    match module_id {
        "lookup_cve" | "get_cvss_details" | "get_cwe_info" | "get_cve_references" => {
            nvd_lookup(state, target).await
        }
        "get_epss_score" => epss_lookup(state, target).await,
        "check_kev_status" => kev_lookup(state, target).await,
        "check_poc_availability" => poc_lookup(state, target).await,
        "get_mitre_techniques" => mitre_mapping(target).await,
        "lookup_ip_reputation" => abuseipdb_lookup(state, target).await,
        "check_ip_noise" => greynoise_lookup(state, target).await,
        "shodan_host_lookup" => shodan_lookup(state, target).await,
        "passive_dns_lookup" => circl_pdns_lookup(state, target).await,
        "asn_lookup" | "rdap_lookup" => rdap_lookup(state, target).await,
        "dns_records_lookup" => doh_lookup(state, target).await,
        "domain_subdomain_enum" | "tls_certificate_lookup" => crtsh_lookup(state, target).await,
        "http_headers_lookup" => http_headers_lookup(state, target).await,
        "technology_fingerprint" => technology_hint(target).await,
        "cloud_hosting_hint" => cloud_hint(target).await,
        "virustotal_lookup" => virustotal_lookup(state, target).await,
        "urlscan_check" => urlscan_lookup(state, target).await,
        "search_malware" => malwarebazaar_lookup(state, target).await,
        "search_iocs" => threatfox_lookup(state, target).await,
        "check_ransomware" => ransomwhere_lookup(state, target).await,
        "scan_dependencies" => osv_scan(state, args).await,
        "scan_github_advisories" => github_advisory_scan(state, args).await,
        "censys_lookup" => censys_lookup(state, target).await,
        "otx_lookup" => otx_lookup(state, target).await,
        "misp_lookup" => misp_lookup(state, target).await,
        "pulsedive_lookup" => pulsedive_lookup(state, target).await,
        "hybrid_analysis_lookup" => hybrid_analysis_lookup(state, target).await,
        _ => bail!("unsupported module"),
    }
}

fn workflow_options(
    mode: Option<String>,
    depth: Option<String>,
    sources: Option<Vec<String>>,
) -> Result<WorkflowOptions> {
    let mode = mode.unwrap_or_else(|| "auto".to_string()).to_ascii_lowercase();
    if !matches!(
        mode.as_str(),
        "auto" | "passive_only" | "active_http_headers" | "threat_intel"
    ) {
        bail!("unsupported mode: {mode}")
    }

    let depth = depth
        .unwrap_or_else(|| "standard".to_string())
        .to_ascii_lowercase();
    if !matches!(depth.as_str(), "quick" | "standard" | "deep") {
        bail!("unsupported depth: {depth}")
    }

    let mut sources = sources.unwrap_or_default();
    sources = sources
        .into_iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();

    Ok(WorkflowOptions {
        mode,
        depth,
        sources,
    })
}

fn cve_modules(input: &CveInvestigationInput, opts: &WorkflowOptions) -> (Vec<&'static str>, Vec<String>) {
    let mut modules = vec!["lookup_cve", "get_cvss_details", "get_cwe_info"];
    if input.include_vendor_advisories && opts.depth != "quick" {
        modules.push("get_cve_references");
    }
    if input.include_epss {
        modules.push("get_epss_score");
    }
    if input.include_kev {
        modules.push("check_kev_status");
    }
    if input.include_poc && opts.depth != "quick" {
        modules.push("check_poc_availability");
    }
    if input.include_mitre && opts.depth == "deep" {
        modules.push("get_mitre_techniques");
    }
    filter_modules(modules, &opts.sources)
}

fn indicator_modules(
    input: &IndicatorInvestigationInput,
    indicator_type: &str,
    opts: &WorkflowOptions,
) -> Result<(Vec<&'static str>, Vec<String>)> {
    let mut modules = match indicator_type {
        "ip" => {
            let mut m = vec!["check_ip_noise", "shodan_host_lookup", "asn_lookup"];
            if input.include_reputation {
                m.insert(0, "lookup_ip_reputation");
            }
            if input.include_passive_dns {
                m.push("passive_dns_lookup");
            }
            if input.include_malware {
                m.push("search_iocs");
                m.push("check_ransomware");
            }
            m
        }
        "domain" => {
            let mut m = vec![
                "dns_records_lookup",
                "rdap_lookup",
                "domain_subdomain_enum",
                "tls_certificate_lookup",
                "technology_fingerprint",
                "cloud_hosting_hint",
            ];
            if input.include_passive_dns {
                m.push("passive_dns_lookup");
            }
            if input.include_malware {
                m.push("search_iocs");
                m.push("check_ransomware");
            }
            m
        }
        "url" => {
            let mut m = vec![
                "http_headers_lookup",
                "technology_fingerprint",
                "cloud_hosting_hint",
            ];
            if input.include_url_safety {
                m.push("urlscan_check");
            }
            m
        }
        "hash" => {
            let mut m = vec!["virustotal_lookup"];
            if input.include_malware {
                m.push("search_malware");
            }
            m
        }
        _ => bail!("unsupported indicator type"),
    };

    match opts.mode.as_str() {
        "passive_only" => modules.retain(|m| *m != "http_headers_lookup"),
        "active_http_headers" => {
            modules = match indicator_type {
                "domain" | "url" => vec![
                    "http_headers_lookup",
                    "technology_fingerprint",
                    "cloud_hosting_hint",
                ],
                _ => bail!("active_http_headers mode only supports domain or url indicators"),
            }
        }
        "threat_intel" => modules.retain(|m| {
            matches!(
                *m,
                "lookup_ip_reputation"
                    | "check_ip_noise"
                    | "shodan_host_lookup"
                    | "virustotal_lookup"
                    | "urlscan_check"
                    | "search_malware"
                    | "search_iocs"
                    | "check_ransomware"
            )
        }),
        "auto" => {}
        _ => unreachable!(),
    }

    if opts.depth == "quick" && opts.sources.is_empty() && modules.len() > 3 {
        modules.truncate(3);
    }
    if opts.depth == "deep" {
        match indicator_type {
            "ip" | "domain" | "url" | "hash" => {
                modules.extend([
                    "otx_lookup",
                    "misp_lookup",
                    "pulsedive_lookup",
                    "hybrid_analysis_lookup",
                ]);
            }
            _ => {}
        }
        if indicator_type == "ip" {
            modules.push("censys_lookup");
        }
    }

    modules.sort_unstable();
    modules.dedup();
    Ok(filter_modules(modules, &opts.sources))
}

fn filter_modules(modules: Vec<&'static str>, requested: &[String]) -> (Vec<&'static str>, Vec<String>) {
    if requested.is_empty() {
        return (modules, vec![]);
    }

    let requested_set = requested.iter().cloned().collect::<BTreeSet<_>>();
    let mut matched = BTreeSet::new();
    let filtered = modules
        .into_iter()
        .filter(|module| {
            let names = module_match_names(module);
            let is_match = names.iter().any(|name| requested_set.contains(*name));
            if is_match {
                for name in names {
                    if requested_set.contains(name) {
                        matched.insert(name.to_string());
                    }
                }
            }
            is_match
        })
        .collect::<Vec<_>>();

    let unknowns = requested_set
        .difference(&matched)
        .map(|s| format!("requested source or module not used: {s}"))
        .collect::<Vec<_>>();
    (filtered, unknowns)
}

fn module_match_names(module: &str) -> Vec<&'static str> {
    match module {
        "lookup_cve" | "get_cvss_details" | "get_cwe_info" | "get_cve_references" => {
            vec![module, "nvd"]
        }
        "get_epss_score" => vec![module, "epss"],
        "check_kev_status" => vec![module, "kev", "cisa_kev"],
        "check_poc_availability" => vec![module, "poc"],
        "get_mitre_techniques" => vec![module, "mitre"],
        "lookup_ip_reputation" => vec![module, "abuseipdb", "reputation"],
        "check_ip_noise" => vec![module, "greynoise"],
        "shodan_host_lookup" => vec![module, "shodan"],
        "passive_dns_lookup" => vec![module, "circl_passive_dns", "passive_dns"],
        "asn_lookup" | "rdap_lookup" => vec![module, "rdap"],
        "dns_records_lookup" => vec![module, "dns", "dns_over_https"],
        "domain_subdomain_enum" | "tls_certificate_lookup" => vec![module, "crtsh", "certificate_transparency"],
        "http_headers_lookup" => vec![module, "http", "headers"],
        "technology_fingerprint" | "cloud_hosting_hint" => vec![module, "heuristic"],
        "virustotal_lookup" => vec![module, "virustotal"],
        "urlscan_check" => vec![module, "urlscan"],
        "search_malware" => vec![module, "malwarebazaar"],
        "search_iocs" => vec![module, "threatfox"],
        "check_ransomware" => vec![module, "ransomwhere"],
        "censys_lookup" => vec![module, "censys"],
        "otx_lookup" => vec![module, "otx"],
        "misp_lookup" => vec![module, "misp"],
        "pulsedive_lookup" => vec![module, "pulsedive"],
        "hybrid_analysis_lookup" => vec![module, "hybrid_analysis"],
        _ => vec!["unknown"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_filter_accepts_source_aliases() {
        let (modules, unknowns) = filter_modules(
            vec!["lookup_cve", "get_epss_score", "check_kev_status"],
            &["epss".to_string()],
        );
        assert_eq!(modules, vec!["get_epss_score"]);
        assert!(unknowns.is_empty());
    }

    #[test]
    fn unsupported_mode_rejected() {
        assert!(workflow_options(Some("exploit".to_string()), None, None).is_err());
    }
}
