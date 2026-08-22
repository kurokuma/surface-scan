use crate::{
    cli::{Cli, ScanMode},
    target::parse_ports,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Clone)]
pub struct Settings {
    pub scan_mode: ScanMode,
    pub ports: Vec<u16>,
    pub ports_spec: String,
    pub rate: u64,
    pub burst: u64,
    pub concurrency: usize,
    pub probe_concurrency: usize,
    pub tcp_timeout: Duration,
    pub tcp_retries: u32,
    pub http_timeout: Duration,
    pub tls_timeout: Duration,
    pub max_body: usize,
    pub output: PathBuf,
    pub csv: Option<PathBuf>,
    pub flat_output: Option<PathBuf>,
    pub export_nmap: Option<PathBuf>,
    pub export_urls: Option<PathBuf>,
    pub metrics_json: Option<PathBuf>,
    pub checkpoint: Option<PathBuf>,
    pub resume: Option<PathBuf>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub protocol: ProtocolConfig,
    #[serde(default)]
    pub output: OutputConfig,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanConfig {
    pub mode: Option<ScanMode>,
    pub ports: Option<String>,
    pub rate: Option<u64>,
    pub burst: Option<u64>,
    pub concurrency: Option<usize>,
    pub tcp_timeout_ms: Option<u64>,
    pub tcp_retries: Option<u32>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub http_timeout_ms: Option<u64>,
    pub tls_timeout_ms: Option<u64>,
    pub max_body_bytes: Option<usize>,
    pub probe_concurrency: Option<usize>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OutputConfig {
    pub jsonl: Option<PathBuf>,
    pub csv: Option<PathBuf>,
    pub flat_jsonl: Option<PathBuf>,
    pub export_nmap: Option<PathBuf>,
    pub export_urls: Option<PathBuf>,
    pub metrics_json: Option<PathBuf>,
}

impl Settings {
    pub fn load(cli: &Cli) -> Result<Self> {
        let file: FileConfig = if let Some(path) = &cli.config {
            toml::from_str(
                &std::fs::read_to_string(path)
                    .with_context(|| format!("read config {}", path.display()))?,
            )
            .with_context(|| format!("parse config {}", path.display()))?
        } else {
            FileConfig::default()
        };
        let ports_spec = cli
            .ports
            .clone()
            .or(file.scan.ports)
            .unwrap_or_else(|| "1-65535".into());
        let settings = Self {
            scan_mode: cli
                .scan_mode
                .or(file.scan.mode)
                .unwrap_or(ScanMode::Connect),
            ports: parse_ports(&ports_spec)?,
            ports_spec,
            rate: cli.rate.or(file.scan.rate).unwrap_or(10_000),
            burst: cli.burst.or(file.scan.burst).unwrap_or(1_000),
            concurrency: cli.concurrency.or(file.scan.concurrency).unwrap_or(1_024),
            probe_concurrency: cli
                .probe_concurrency
                .or(file.protocol.probe_concurrency)
                .unwrap_or(128),
            tcp_timeout: cli
                .tcp_timeout
                .or(file.scan.tcp_timeout_ms.map(Duration::from_millis))
                .unwrap_or(Duration::from_millis(700)),
            tcp_retries: cli.tcp_retries.or(file.scan.tcp_retries).unwrap_or(1),
            http_timeout: cli
                .http_timeout
                .or(file.protocol.http_timeout_ms.map(Duration::from_millis))
                .unwrap_or(Duration::from_secs(1)),
            tls_timeout: cli
                .tls_timeout
                .or(file.protocol.tls_timeout_ms.map(Duration::from_millis))
                .unwrap_or(Duration::from_secs(1)),
            max_body: cli
                .max_body
                .or(file.protocol.max_body_bytes)
                .unwrap_or(262_144),
            output: cli
                .output
                .clone()
                .or(file.output.jsonl)
                .unwrap_or_else(|| "result.jsonl".into()),
            csv: cli.csv.clone().or(file.output.csv),
            flat_output: cli.flat_output.clone().or(file.output.flat_jsonl),
            export_nmap: cli.export_nmap.clone().or(file.output.export_nmap),
            export_urls: cli.export_urls.clone().or(file.output.export_urls),
            metrics_json: cli.metrics_json.clone().or(file.output.metrics_json),
            checkpoint: cli.checkpoint.clone(),
            resume: cli.resume.clone(),
        };
        if settings.rate == 0 || settings.burst == 0 {
            bail!("rate and burst must be greater than zero");
        }
        if settings.concurrency == 0 || settings.probe_concurrency == 0 {
            bail!("concurrency must be greater than zero");
        }
        if settings.max_body == 0 {
            bail!("max-body must be greater than zero");
        }
        Ok(settings)
    }
}
