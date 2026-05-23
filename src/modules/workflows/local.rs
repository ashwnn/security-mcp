use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// IOC extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocExtraction {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub hashes: Vec<String>,
    pub cves: Vec<String>,
    pub emails: Vec<String>,
    pub count: usize,
}

/// Hash classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashClassification {
    pub hash: String,
    pub hash_type: Option<String>,
    pub is_valid_format: bool,
    pub normalized: Option<String>,
    pub confidence: String,
    pub explanation: String,
}

/// Extract IOCs from text
pub fn extract_iocs(text: &str) -> IocExtraction {
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let mut urls = Vec::new();
    let mut hashes = Vec::new();
    let mut cves = Vec::new();
    let mut emails = Vec::new();

    // IP regex (including defanged)
    let ip_re = Regex::new(r"(?i)(?:[\d]{1,3}\.){3}[\d]{1,3}").unwrap();
    // Domain regex
    let domain_re = Regex::new(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}").unwrap();
    // URL regex
    let url_re = Regex::new(r#"(?i)https?://[^\s<>"']+"#).unwrap();
    // Hash regex (MD5, SHA1, SHA256, SHA512)
    let hash_re = Regex::new(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b").unwrap();
    // CVE regex
    let cve_re = Regex::new(r"(?i)CVE-\d{4}-\d{4,}").unwrap();
    // Email regex
    let email_re = Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap();

    for cap in ip_re.find_iter(text) {
        let ip = defang_refang(&cap.as_str());
        if is_likely_ip(&ip) {
            ips.push(ip);
        }
    }

    for cap in domain_re.find_iter(text) {
        let domain = defang_refang(&cap.as_str());
        if is_likely_domain(&domain) {
            domains.push(domain);
        }
    }

    for cap in url_re.find_iter(text) {
        let url = defang_refang(&cap.as_str());
        urls.push(url);
    }

    for cap in hash_re.find_iter(text) {
        let hash = cap.as_str().to_lowercase();
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }

    for cap in cve_re.find_iter(text) {
        let cve = cap.as_str().to_uppercase();
        if !cves.contains(&cve) {
            cves.push(cve);
        }
    }

    for cap in email_re.find_iter(text) {
        let email = cap.as_str().to_lowercase();
        if !emails.contains(&email) {
            emails.push(email);
        }
    }

    // Deduplicate
    ips.sort();
    ips.dedup();
    domains.sort();
    domains.dedup();
    hashes.sort();
    hashes.dedup();
    cves.sort();
    cves.dedup();
    emails.sort();
    emails.dedup();

    let count = ips.len() + domains.len() + urls.len() + hashes.len() + cves.len() + emails.len();

    IocExtraction {
        ips,
        domains,
        urls,
        hashes,
        cves,
        emails,
        count,
    }
}

/// Classify a hash
pub fn classify_hash(hash: &str) -> HashClassification {
    let hash = hash.trim().to_lowercase();
    let len = hash.len();
    let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());

    if !is_hex {
        return HashClassification {
            hash: hash.to_string(),
            hash_type: None,
            is_valid_format: false,
            normalized: None,
            confidence: "low".to_string(),
            explanation: "Hash contains non-hexadecimal characters".to_string(),
        };
    }

    let (hash_type, confidence, explanation) = match len {
        32 => ("MD5".to_string(), "high".to_string(), "128-bit hash, commonly used for file integrity".to_string()),
        40 => ("SHA1".to_string(), "high".to_string(), "160-bit hash, deprecated for security purposes".to_string()),
        64 => ("SHA256".to_string(), "high".to_string(), "256-bit hash, current standard for cryptographic hashing".to_string()),
        128 => ("SHA512".to_string(), "medium".to_string(), "512-bit hash, could also be bcrypt (60 chars) or other formats".to_string()),
        _ => {
            return HashClassification {
                hash: hash.to_string(),
                hash_type: None,
                is_valid_format: false,
                normalized: None,
                confidence: "low".to_string(),
                explanation: format!("Unrecognized hash length: {} characters. Expected MD5 (32), SHA1 (40), SHA256 (64), or SHA512 (128)", len),
            }
        }
    };

    HashClassification {
        hash: hash.to_string(),
        hash_type: Some(hash_type),
        is_valid_format: true,
        normalized: Some(hash),
        confidence,
        explanation,
    }
}

/// Check if string looks like a valid IP
fn is_likely_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        if let Ok(n) = part.parse::<u8>() {
            if n.to_string() != part {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

/// Check if string looks like a valid domain
fn is_likely_domain(s: &str) -> bool {
    if s.len() < 4 || s.len() > 253 {
        return false;
    }
    // Must have at least one dot (not TLD-only)
    if !s.contains('.') {
        return false;
    }
    // Reasonable TLD
    let tlds = ["com", "net", "org", "io", "co", "uk", "de", "fr", "ru", "cn", "jp", "br", "in", "au", "gov", "edu", "mil", "biz", "info", "me", "tv", "cc", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "site", "online", "tech"];
    let tld = s.rsplit('.').next().unwrap_or("");
    tlds.contains(&tld) || tld.len() >= 2
}

/// Defang/refang indicator
fn defang_refang(s: &str) -> String {
    let mut result = s.to_string();
    // Defanged patterns
    result = result.replace("[.]", ".");
    result = result.replace(".", "[.]");
    result = result.replace("[:]", ":");
    result = result.replace("[@]", "@");
    result = result.replace("[/]", "/");
    result = result.replace("hxxp", "http");
    result = result.replace("hxxps", "https");
    result = result.replace("XX", "..");
    result = result.replace("x[.]", ".");
    // Clean up double dots
    while result.contains("..") {
        result = result.replace("..", ".");
    }
    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_iocs_from_soc_note() {
        let text = r#"
Investigation notes:
Target IP: 185.220.101.34 (Tor exit node)
Associated domains: malicious-site[.]com, evil-domain.net
URL observed: hxxps://phishing-example.com/payload/download
Hashes identified: d41d8cd98f00b204e9800998ecf8427e (MD5)
CVE referenced: CVE-2024-3094
Contact: analyst@company.com
"#;

        let result = extract_iocs(text);
        assert!(!result.ips.is_empty());
        assert!(result.ips.contains(&"185.220.101.34".to_string()));
        assert!(result.cves.contains(&"CVE-2024-3094".to_string()));
        assert!(!result.emails.is_empty());
        assert!(result.hashes.len() >= 1);
    }

    #[test]
    fn classify_hash_types() {
        let cases = vec![
            ("d41d8cd98f00b204e9800998ecf8427e", "MD5", true),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1", true),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256", true),
        ];

        for (hash, expected_type, expected_valid) in cases {
            let result = classify_hash(hash);
            assert_eq!(result.hash_type.as_deref(), Some(expected_type));
            assert_eq!(result.is_valid_format, expected_valid);
        }
    }

    #[test]
    fn classify_invalid_hash() {
        let result = classify_hash("not-a-hash-at-all");
        assert!(!result.is_valid_format);
        assert!(result.hash_type.is_none());
    }
}