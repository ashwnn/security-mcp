use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use anyhow::{Result, bail};
use regex::Regex;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetKind {
    Cve,
    Ip,
    Domain,
    Url,
    Hash,
    Package,
    Unknown,
}

pub fn validate_cve_id(input: &str) -> Result<()> {
    let re = Regex::new(r"^CVE-\d{4}-\d{4,}$").expect("regex");
    if re.is_match(input) {
        Ok(())
    } else {
        bail!("invalid CVE ID")
    }
}

pub fn detect_target_kind(input: &str) -> TargetKind {
    if validate_cve_id(input).is_ok() {
        return TargetKind::Cve;
    }
    if input.parse::<IpAddr>().is_ok() {
        return TargetKind::Ip;
    }
    if Url::parse(input).is_ok() {
        return TargetKind::Url;
    }
    let domain_re =
        Regex::new(r"^(?i)[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]\.[a-z]{2,}$").expect("regex");
    if domain_re.is_match(input) {
        return TargetKind::Domain;
    }
    let hash_re = Regex::new(r"(?i)^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$").expect("regex");
    if hash_re.is_match(input) {
        return TargetKind::Hash;
    }
    if input.contains('@') || input.contains('/') {
        return TargetKind::Package;
    }
    TargetKind::Unknown
}

pub fn validate_public_ip(ip: IpAddr) -> Result<()> {
    if is_blocked_ip(ip) {
        bail!("private or reserved IP lookups are blocked")
    }
    Ok(())
}

pub fn validate_public_url(url: &str, allow_private: bool) -> Result<Url> {
    let parsed = Url::parse(url)?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        bail!("unsupported URL scheme")
    }

    let port = parsed.port_or_known_default().unwrap_or(80);
    if !allow_private && !matches!(port, 80 | 443) {
        bail!("non-standard target ports are blocked")
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host"))?;
    if !allow_private {
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
            bail!("localhost and local domains are blocked")
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            validate_public_ip(ip)?;
        } else {
            let addrs = (host, port)
                .to_socket_addrs()
                .map_err(|_| anyhow::anyhow!("failed to resolve host"))?;
            for addr in addrs {
                validate_public_ip(addr.ip())?;
            }
        }
    }

    Ok(parsed)
}

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 224
        || ip.octets()[0] == 127
        || ip.octets() == [169, 254, 169, 254]
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 2)
        || (ip.octets()[0] == 198 && ip.octets()[1] == 51 && ip.octets()[2] == 100)
        || (ip.octets()[0] == 203 && ip.octets()[1] == 0 && ip.octets()[2] == 113)
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped().or_else(|| ip.to_ipv4()) {
        return is_blocked_ipv4(v4);
    }
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.segments()[0] & 0xffc0 == 0xfe80
        || ip.segments()[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_validation() {
        assert!(validate_cve_id("CVE-2025-12345").is_ok());
        assert!(validate_cve_id("CVE-202-1").is_err());
    }

    #[test]
    fn detection_works() {
        assert_eq!(detect_target_kind("CVE-2025-12345"), TargetKind::Cve);
        assert_eq!(detect_target_kind("1.1.1.1"), TargetKind::Ip);
        assert_eq!(detect_target_kind("https://example.com"), TargetKind::Url);
        assert_eq!(detect_target_kind("example.com"), TargetKind::Domain);
    }

    #[test]
    fn private_ip_blocked() {
        assert!(validate_public_ip("127.0.0.1".parse().expect("ip")).is_err());
        assert!(validate_public_ip("169.254.169.254".parse().expect("ip")).is_err());
        assert!(validate_public_ip("8.8.8.8".parse().expect("ip")).is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_is_blocked() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().expect("ip")));
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().expect("ip")));
    }

    #[test]
    fn non_standard_ports_are_blocked() {
        assert!(validate_public_url("https://example.com:8443", false).is_err());
    }
}
