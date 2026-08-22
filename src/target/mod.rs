use crate::model::Target;
use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use std::{collections::BTreeMap, net::Ipv4Addr, str::FromStr};

const MAX_EXPANDED_TARGETS: usize = 1_000_000;

/// Column layout discovered from a CSV header line.
#[derive(Debug, Clone, Copy)]
struct CsvLayout {
    ip: usize,
    known_port: Option<usize>,
}

/// Parse targets from free-form text: bare IPv4, `IP:port`, `IP,port`, CIDR, or
/// a CSV whose known-C2-port column is named by `known_service_field`.
///
/// Every address inside a CIDR is kept, including the network and broadcast
/// addresses: a scanner must not assume the block is a routed LAN.
pub fn parse_targets(text: &str, known_service_field: Option<&str>) -> Result<Vec<Target>> {
    let mut found: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
    let mut layout: Option<CsvLayout> = None;
    for (index, raw) in text.lines().enumerate() {
        let raw = raw.trim();
        if raw.starts_with('#') {
            continue;
        }
        // Preserve `#` inside quoted/free-form CSV fields. Inline comments are
        // supported for the simple IP/CIDR forms only.
        let line = if raw.contains(',') {
            raw
        } else {
            raw.split('#').next().unwrap_or("").trim()
        };
        if line.is_empty() {
            continue;
        }
        if let Some(found_layout) = detect_header(line, known_service_field)? {
            layout = Some(found_layout);
            continue;
        }
        if line.contains('/') {
            let net = Ipv4Net::from_str(line)
                .with_context(|| format!("invalid IPv4 CIDR on line {}: {line}", index + 1))?;
            let mut address = net.network();
            let last = net.broadcast();
            loop {
                found.entry(address).or_default();
                if found.len() > MAX_EXPANDED_TARGETS {
                    bail!("target expansion exceeds {MAX_EXPANDED_TARGETS} addresses");
                }
                if address == last {
                    break;
                }
                address = Ipv4Addr::from(u32::from(address) + 1);
            }
        } else {
            let (ip, port) = parse_row(line, layout)
                .with_context(|| format!("invalid target on line {}: {line}", index + 1))?;
            let ports = found.entry(ip).or_default();
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

/// Recognise a CSV header line and locate its address and known-port columns.
///
/// Header rows are skipped even without `--known-service-field` so that an
/// analyst-exported CSV is not a fatal input.
fn detect_header(line: &str, known_service_field: Option<&str>) -> Result<Option<CsvLayout>> {
    if !line.contains(',') {
        return Ok(None);
    }
    let columns: Vec<String> = csv_fields(line)?
        .into_iter()
        .map(|column| column.trim().to_ascii_lowercase())
        .collect();
    // A header never starts with a literal address.
    if columns[0].parse::<Ipv4Addr>().is_ok() {
        return Ok(None);
    }
    let Some(ip) = columns
        .iter()
        .position(|c| matches!(c.as_str(), "ip" | "ipv4" | "host" | "address" | "target"))
    else {
        // Not a recognised header: let normal row parsing report the invalid
        // IPv4 value instead of silently discarding a malformed data row.
        return Ok(None);
    };
    let known_port = if let Some(field) = known_service_field {
        let field = field.to_ascii_lowercase();
        Some(
            columns
                .iter()
                .position(|column| *column == field)
                .ok_or_else(|| {
                    anyhow::anyhow!("known service field '{field}' is absent from CSV header")
                })?,
        )
    } else {
        columns.iter().position(|c| {
            // No explicit flag: fall back to the conventional column names so a
            // headered CSV keeps the same meaning as the bare `IP,port` form.
            matches!(
                c.as_str(),
                "port" | "c2_port" | "known_c2_port" | "service_port"
            )
        })
    };
    Ok(Some(CsvLayout { ip, known_port }))
}

/// Parse one data row, honouring a previously detected CSV layout.
fn parse_row(line: &str, layout: Option<CsvLayout>) -> Result<(Ipv4Addr, Option<u16>)> {
    if let Some(layout) = layout {
        let columns = csv_fields(line)?;
        let ip = columns
            .get(layout.ip)
            .ok_or_else(|| anyhow::anyhow!("missing address column"))?
            .trim()
            .parse()?;
        let port = layout
            .known_port
            .and_then(|index| columns.get(index))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<u16>())
            .transpose()?;
        if port == Some(0) {
            bail!("port 0 is not supported");
        }
        return Ok((ip, port));
    }
    parse_ip_port(line)
}

fn parse_ip_port(value: &str) -> Result<(Ipv4Addr, Option<u16>)> {
    if let Some((ip, port)) = value.rsplit_once(':') {
        let port: u16 = port.parse()?;
        if port == 0 {
            bail!("port 0 is not supported");
        }
        return Ok((ip.parse()?, Some(port)));
    }
    if value.contains(',') {
        let columns = csv_fields(value)?;
        if columns.len() != 2 {
            bail!("headerless CSV target rows must contain exactly IP and port");
        }
        let ip = columns[0].trim();
        let port = columns[1].trim();
        if port.is_empty() {
            return Ok((ip.parse()?, None));
        }
        let port: u16 = port.parse()?;
        if port == 0 {
            bail!("port 0 is not supported");
        }
        return Ok((ip.parse()?, Some(port)));
    }
    Ok((value.parse()?, None))
}

fn csv_fields(line: &str) -> Result<Vec<String>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(line.as_bytes());
    let record = reader
        .records()
        .next()
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("empty CSV row"))?;
    Ok(record.iter().map(str::to_string).collect())
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
        let got = parse_targets("192.0.2.1\n192.0.2.1:443\n198.51.100.0/30\n", None).unwrap();
        // /30 keeps all four addresses, including network and broadcast.
        assert_eq!(got.len(), 5);
        assert_eq!(got[0].known_c2_ports, vec![443]);
        let expect = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        assert!(got.iter().any(|t| t.ip == expect("198.51.100.0")));
        assert!(got.iter().any(|t| t.ip == expect("198.51.100.3")));
    }
    #[test]
    fn single_address_cidr_expands_to_one_target() {
        let got = parse_targets("203.0.113.7/32", None).unwrap();
        assert_eq!(got.len(), 1);
    }
    #[test]
    fn csv_header_selects_the_known_service_column() {
        let text =
            "ip,first_seen,c2_port\n203.0.113.10,2026-01-01,443\n203.0.113.11,2026-01-02,1618\n";
        let got = parse_targets(text, Some("c2_port")).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].known_c2_ports, vec![443]);
        assert_eq!(got[1].known_c2_ports, vec![1618]);
    }
    #[test]
    fn csv_header_is_skipped_without_the_field_flag() {
        let got = parse_targets("ip,c2_port\n203.0.113.10,443\n", None).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].known_c2_ports, vec![443]);
    }
    #[test]
    fn malformed_rows_and_zero_ports_are_not_silently_accepted() {
        assert!(parse_targets("not-an-ip,443\n", None).is_err());
        assert!(parse_targets("192.0.2.1:0\n", None).is_err());
        assert!(parse_targets("ip,other\n192.0.2.1,443\n", Some("c2_port")).is_err());
    }

    #[test]
    fn quoted_csv_fields_do_not_shift_the_known_port_column() {
        let got = parse_targets(
            "ip,note,c2_port\n\"203.0.113.10\",\"first, observed\",443\n",
            Some("c2_port"),
        )
        .unwrap();
        assert_eq!(got[0].known_c2_ports, vec![443]);
    }

    #[test]
    fn hashes_inside_csv_fields_are_not_treated_as_comments() {
        let got = parse_targets(
            "ip,note,c2_port\n\"203.0.113.10\",\"case #42\",443\n",
            Some("c2_port"),
        )
        .unwrap();
        assert_eq!(got[0].known_c2_ports, vec![443]);
    }
}
