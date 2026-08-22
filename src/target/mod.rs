use crate::model::Target;
use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use std::{collections::BTreeMap, net::Ipv4Addr, str::FromStr};

const MAX_EXPANDED_TARGETS: usize = 1_000_000;

pub fn parse_targets(text: &str) -> Result<Vec<Target>> {
    let mut found: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.contains('/') {
            let net = Ipv4Net::from_str(line)
                .with_context(|| format!("invalid IPv4 CIDR on line {}: {line}", index + 1))?;
            for ip in net.hosts() {
                found.entry(ip).or_default();
                if found.len() > MAX_EXPANDED_TARGETS {
                    bail!("target expansion exceeds {MAX_EXPANDED_TARGETS}");
                }
            }
            if net.prefix_len() >= 31 {
                found.entry(net.network()).or_default();
                found.entry(net.broadcast()).or_default();
            }
        } else {
            let (ip_text, port) = parse_ip_port(line)
                .with_context(|| format!("invalid target on line {}: {line}", index + 1))?;
            let ports = found.entry(ip_text).or_default();
            if let Some(port) = port {
                ports.push(port);
            }
        }
    }
    for ports in found.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }
    Ok(found
        .into_iter()
        .map(|(ip, known_c2_ports)| Target { ip, known_c2_ports })
        .collect())
}

fn parse_ip_port(value: &str) -> Result<(Ipv4Addr, Option<u16>)> {
    if let Some((ip, port)) = value.rsplit_once(':') {
        return Ok((ip.parse()?, Some(port.parse()?)));
    }
    if let Some((ip, port)) = value.split_once(',') {
        return Ok((ip.trim().parse()?, Some(port.trim().parse()?)));
    }
    Ok((value.parse()?, None))
}

pub fn parse_ports(value: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .parse()
                .with_context(|| format!("invalid port: {start}"))?;
            let end: u16 = end
                .parse()
                .with_context(|| format!("invalid port: {end}"))?;
            if start == 0 || start > end {
                bail!("invalid port range: {part}");
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .with_context(|| format!("invalid port: {part}"))?;
            if port == 0 {
                bail!("port 0 is not supported");
            }
            ports.push(port);
        }
    }
    if ports.is_empty() {
        bail!("port selection is empty");
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ports_are_expanded_and_deduplicated() {
        assert_eq!(
            parse_ports("80,443,8000-8002,80").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
        assert!(parse_ports("0").is_err());
    }
    #[test]
    fn targets_support_ip_cidr_and_known_port() {
        let got = parse_targets("192.0.2.1\n192.0.2.1:443\n198.51.100.0/30\n").unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].known_c2_ports, vec![443]);
    }
}
