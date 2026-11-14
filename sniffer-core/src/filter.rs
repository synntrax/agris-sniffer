//! Validation of the `--ips` capture filter. Entries end up inside a libpcap
//! filter expression, so anything but a literal IP or CIDR range is rejected.
use std::net::IpAddr;

/// Parse a comma-separated list of IPs / CIDR ranges (`1.2.3.4, 10.0.0.0/8, ::1`).
/// Returns the normalised entries, or an error naming the first bad one.
pub fn parse_ip_filter(list: &str) -> Result<Vec<String>, String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let (ip, prefix) = match entry.split_once('/') {
                Some((ip, p)) => (ip, Some(p)),
                None => (entry, None),
            };
            let ip: IpAddr = ip.parse().map_err(|_| format!("not an IP address: {entry}"))?;
            match prefix {
                None => Ok(ip.to_string()),
                Some(p) => {
                    let max = if ip.is_ipv4() { 32 } else { 128 };
                    match p.parse::<u8>() {
                        Ok(n) if n <= max => Ok(format!("{ip}/{n}")),
                        _ => Err(format!("bad network prefix: {entry}")),
                    }
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ips_and_ranges() {
        assert_eq!(parse_ip_filter(" 1.2.3.4, 10.0.0.0/8 ,::1,").unwrap(), ["1.2.3.4", "10.0.0.0/8", "::1"]);
        assert!(parse_ip_filter("").unwrap().is_empty());
    }

    #[test]
    fn rejects_filter_injection() {
        assert!(parse_ip_filter("1.2.3.4) or (port 22").is_err());
        assert!(parse_ip_filter("host 1.2.3.4").is_err());
        assert!(parse_ip_filter("1.2.3.4/33").is_err());
        assert!(parse_ip_filter("1.2.3.4/8 or port 22").is_err());
    }
}
