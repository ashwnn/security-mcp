use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ModuleDefinition {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub required_source: Option<String>,
    pub available_without_credentials: bool,
    pub mcp_exposed_default: bool,
    pub ui_visible: bool,
    pub cache_ttl_seconds: i64,
    pub timeout_seconds: u64,
}

#[derive(Clone)]
pub struct Registry {
    modules: HashMap<String, ModuleDefinition>,
    expert_tool_enabled: bool,
}

impl Registry {
    pub fn new(expert_tool_enabled: bool) -> Self {
        let modules = module_definitions()
            .into_iter()
            .map(|m| (m.id.clone(), m))
            .collect();
        Self {
            modules,
            expert_tool_enabled,
        }
    }

    pub fn list(&self) -> Vec<ModuleDefinition> {
        let mut list = self.modules.values().cloned().collect::<Vec<_>>();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    pub fn module(&self, id: &str) -> Option<ModuleDefinition> {
        self.modules.get(id).cloned()
    }

    pub fn high_level_tools(&self) -> Vec<&'static str> {
        let mut tools = vec![
            "security_investigate",
            "security_investigate_cve",
            "security_investigate_indicator",
            "security_scan_dependencies",
            "security_compare",
            "security_tool_catalog",
        ];
        if self.expert_tool_enabled {
            tools.push("security_run_tool");
        }
        tools
    }
}

fn module_definitions() -> Vec<ModuleDefinition> {
    vec![
        m("lookup_cve", "Lookup CVE", "cve", Some("nvd"), true, 3600),
        m("search_cves", "Search CVEs", "cve", Some("nvd"), true, 3600),
        m(
            "bulk_cve_lookup",
            "Bulk CVE lookup",
            "cve",
            Some("nvd"),
            true,
            3600,
        ),
        m(
            "get_cve_references",
            "Get CVE references",
            "cve",
            Some("nvd"),
            true,
            3600,
        ),
        m(
            "get_epss_score",
            "Get EPSS score",
            "cve",
            Some("epss"),
            true,
            21600,
        ),
        m(
            "check_kev_status",
            "Check KEV status",
            "cve",
            Some("cisa_kev"),
            true,
            3600,
        ),
        m(
            "get_cvss_details",
            "Get CVSS details",
            "cve",
            Some("nvd"),
            true,
            3600,
        ),
        m(
            "get_cwe_info",
            "Get CWE info",
            "cve",
            Some("nvd"),
            true,
            86400,
        ),
        m(
            "get_attack_patterns",
            "Get CAPEC patterns",
            "cve",
            None,
            true,
            86400,
        ),
        m(
            "search_exploits",
            "Search exploit references",
            "exploit",
            Some("github"),
            false,
            3600,
        ),
        m(
            "check_poc_availability",
            "Check PoC availability",
            "exploit",
            Some("nvd"),
            true,
            3600,
        ),
        m(
            "get_mitre_techniques",
            "Get MITRE techniques",
            "exploit",
            None,
            true,
            86400,
        ),
        m(
            "calculate_risk_score",
            "Calculate risk score",
            "risk",
            None,
            true,
            3600,
        ),
        m(
            "prioritize_cves",
            "Prioritize CVEs",
            "risk",
            None,
            true,
            3600,
        ),
        m(
            "generate_risk_summary",
            "Generate risk summary",
            "risk",
            None,
            true,
            3600,
        ),
        m(
            "lookup_ip_reputation",
            "IP reputation",
            "network",
            Some("abuseipdb"),
            false,
            3600,
        ),
        m(
            "check_ip_noise",
            "IP noise",
            "network",
            Some("greynoise"),
            false,
            3600,
        ),
        m(
            "shodan_host_lookup",
            "Shodan host",
            "network",
            Some("shodan"),
            false,
            3600,
        ),
        m(
            "passive_dns_lookup",
            "Passive DNS",
            "network",
            Some("circl_passive_dns"),
            false,
            3600,
        ),
        m(
            "asn_lookup",
            "ASN lookup",
            "network",
            Some("rdap"),
            true,
            3600,
        ),
        m(
            "dns_records_lookup",
            "DNS lookup",
            "domain",
            Some("dns_over_https"),
            true,
            3600,
        ),
        m(
            "rdap_lookup",
            "RDAP lookup",
            "domain",
            Some("rdap"),
            true,
            3600,
        ),
        m(
            "domain_subdomain_enum",
            "Subdomain enumeration",
            "domain",
            Some("crtsh"),
            true,
            3600,
        ),
        m(
            "tls_certificate_lookup",
            "TLS certificate lookup",
            "domain",
            Some("crtsh"),
            true,
            3600,
        ),
        m(
            "http_headers_lookup",
            "HTTP headers lookup",
            "domain",
            Some("http"),
            true,
            3600,
        ),
        m(
            "technology_fingerprint",
            "Technology fingerprint",
            "domain",
            None,
            true,
            3600,
        ),
        m(
            "cloud_hosting_hint",
            "Cloud hosting hint",
            "domain",
            None,
            true,
            3600,
        ),
        m(
            "virustotal_lookup",
            "VirusTotal lookup",
            "threat",
            Some("virustotal"),
            false,
            3600,
        ),
        m(
            "urlscan_check",
            "URLScan check",
            "threat",
            Some("urlscan"),
            false,
            3600,
        ),
        m(
            "search_malware",
            "Malware search",
            "threat",
            Some("malwarebazaar"),
            true,
            86400,
        ),
        m(
            "search_iocs",
            "IOC search",
            "threat",
            Some("threatfox"),
            true,
            86400,
        ),
        m(
            "check_ransomware",
            "Ransomware check",
            "threat",
            Some("ransomwhere"),
            true,
            86400,
        ),
        m(
            "scan_dependencies",
            "Scan dependencies",
            "devsecops",
            Some("osv"),
            true,
            21600,
        ),
        m(
            "scan_github_advisories",
            "GitHub advisories",
            "devsecops",
            Some("github"),
            false,
            21600,
        ),
        m(
            "parse_requirements_txt",
            "Parse requirements",
            "devsecops",
            None,
            true,
            21600,
        ),
        m(
            "parse_package_json",
            "Parse package.json",
            "devsecops",
            None,
            true,
            21600,
        ),
        m(
            "parse_poetry_lock",
            "Parse poetry.lock",
            "devsecops",
            None,
            true,
            21600,
        ),
        m(
            "parse_go_mod",
            "Parse go.mod",
            "devsecops",
            None,
            true,
            21600,
        ),
        m(
            "parse_cargo_toml",
            "Parse Cargo.toml",
            "devsecops",
            None,
            true,
            21600,
        ),
        m("extract_iocs", "IOC extraction", "utility", None, true, 0),
        m("classify_hash", "Hash classification", "utility", None, true, 0),
        m("censys_lookup", "Censys lookup", "network", Some("censys"), false, 3600),
        m("otx_lookup", "OTX lookup", "threat", Some("otx"), false, 3600),
        m("misp_lookup", "MISP lookup", "threat", Some("misp"), false, 3600),
        m("pulsedive_lookup", "Pulsedive lookup", "threat", Some("pulsedive"), false, 3600),
        m("hybrid_analysis_lookup", "Hybrid Analysis lookup", "threat", Some("hybrid_analysis"), false, 86400),
    ]
}

fn m(
    id: &str,
    name: &str,
    category: &str,
    required_source: Option<&str>,
    available_without_credentials: bool,
    ttl: i64,
) -> ModuleDefinition {
    ModuleDefinition {
        id: id.to_string(),
        name: name.to_string(),
        category: category.to_string(),
        description: format!("{name} module"),
        required_source: required_source.map(ToString::to_string),
        available_without_credentials,
        mcp_exposed_default: false,
        ui_visible: true,
        cache_ttl_seconds: ttl,
        timeout_seconds: 15,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tools() {
        let registry = Registry::new(false);
        assert_eq!(registry.high_level_tools().len(), 6);
    }
}
