use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Connect,
    Syn,
}

#[derive(Debug, Parser)]
#[command(
    name = "surface-scan",
    version,
    about = "Fast IPv4 operator-surface discovery"
)]
pub struct Cli {
    /// Target file, or '-' for standard input.
    #[arg(short = 'i', long = "input")]
    pub input: Option<PathBuf>,
    /// A single IPv4, IPv4:known-c2-port, or CIDR. May be repeated.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,
    /// Ports such as '80,443,8000-9000' (default: 1-65535).
    #[arg(short = 'p', long = "ports")]
    pub ports: Option<String>,
    /// TCP discovery backend.
    #[arg(long = "scan-mode", value_enum)]
    pub scan_mode: Option<ScanMode>,
    /// Connection attempts/sec (connect) or packets/sec (syn).
    #[arg(long)]
    pub rate: Option<u64>,
    /// Token bucket burst capacity.
    #[arg(long)]
    pub burst: Option<u64>,
    /// Maximum connect sockets in flight.
    #[arg(long)]
    pub concurrency: Option<usize>,
    /// Maximum application probes in flight.
    #[arg(long = "probe-concurrency")]
    pub probe_concurrency: Option<usize>,
    /// TCP timeout, e.g. 700ms or 1s.
    #[arg(long="tcp-timeout", value_parser=parse_duration)]
    pub tcp_timeout: Option<std::time::Duration>,
    /// Retries after the initial TCP attempt.
    #[arg(long = "tcp-retries")]
    pub tcp_retries: Option<u32>,
    /// HTTP write/read inactivity timeout.
    #[arg(long="http-timeout", value_parser=parse_duration)]
    pub http_timeout: Option<std::time::Duration>,
    /// TLS connect/handshake timeout.
    #[arg(long="tls-timeout", value_parser=parse_duration)]
    pub tls_timeout: Option<std::time::Duration>,
    /// Maximum response body bytes retained for hashing.
    #[arg(long = "max-body")]
    pub max_body: Option<usize>,
    /// Host-centric JSONL output.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
    /// Service-level CSV output.
    #[arg(long)]
    pub csv: Option<PathBuf>,
    /// Service-level JSONL output.
    #[arg(long = "flat-output")]
    pub flat_output: Option<PathBuf>,
    /// Detected web targets as IP:port.
    #[arg(long = "export-nmap")]
    pub export_nmap: Option<PathBuf>,
    /// Detected web targets as URLs.
    #[arg(long = "export-urls")]
    pub export_urls: Option<PathBuf>,
    /// Machine-readable scan metrics JSON.
    #[arg(long = "metrics-json")]
    pub metrics_json: Option<PathBuf>,
    /// Save host-level resume state here.
    #[arg(long)]
    pub checkpoint: Option<PathBuf>,
    /// Resume and append outputs using this state.
    #[arg(long)]
    pub resume: Option<PathBuf>,
    /// TOML configuration file (CLI values take precedence).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// tracing filter, e.g. info or surface_scan=debug.
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

fn parse_duration(value: &str) -> Result<std::time::Duration, String> {
    let value = value.trim();
    let (number, multiplier) = if let Some(v) = value.strip_suffix("ms") {
        (v, 1)
    } else if let Some(v) = value.strip_suffix('s') {
        (v, 1000)
    } else {
        (value, 1)
    };
    let amount: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration: {value}"))?;
    Ok(std::time::Duration::from_millis(
        amount.saturating_mul(multiplier),
    ))
}
