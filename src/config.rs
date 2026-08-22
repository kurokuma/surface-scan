use crate::{
    cli::{Cli, ScanMode},
    target::parse_ports,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

/// Weights for the triage-only suspicion score described in spec section 20.
///
/// A score never states maliciousness; it only orders analyst attention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SuspicionWeights {
    pub high_port: u32,
    pub high_port_threshold: u16,
    pub uncommon_server: u32,
    pub absent_server: u32,
    pub directory_listing: u32,
    pub hfs: u32,
    pub login_panel: u32,
    pub admin_panel: u32,
    pub self_signed_certificate: u32,
    pub expired_certificate: u32,
    pub downloadable_artifacts: u32,
    pub unknown_fingerprint: u32,
}
impl Default for SuspicionWeights {
    fn default() -> Self {
        Self {
            high_port: 2,
            high_port_threshold: 10_000,
            uncommon_server: 2,
            absent_server: 1,
            directory_listing: 3,
            hfs: 3,
            login_panel: 2,
            admin_panel: 2,
            self_signed_certificate: 1,
            expired_certificate: 1,
            downloadable_artifacts: 2,
            unknown_fingerprint: 2,
        }
    }
}

/// Per-rule fingerprint switches from the `[fingerprint]` config table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FingerprintToggles {
    pub hfs: bool,
    pub directory_listing: bool,
    pub login_panel: bool,
    pub admin_panel: bool,
    pub apache: bool,
    pub nginx: bool,
    pub iis: bool,
    pub python_simplehttpserver: bool,
    pub tomcat: bool,
    pub jetty: bool,
    pub nodejs: bool,
    pub go_http: bool,
}
impl Default for FingerprintToggles {
    fn default() -> Self {
        Self {
            hfs: true,
            directory_listing: true,
            login_panel: true,
            admin_panel: true,
            apache: true,
            nginx: true,
            iis: true,
            python_simplehttpserver: true,
            tomcat: true,
            jetty: true,
            nodejs: true,
            go_http: true,
        }
    }
}
impl FingerprintToggles {
    pub fn rule_enabled(&self, name: &str) -> bool {
        match name {
            "hfs" => self.hfs,
            "apache" => self.apache,
            "nginx" => self.nginx,
            "iis" => self.iis,
            "python-simplehttpserver" => self.python_simplehttpserver,
            "tomcat" => self.tomcat,
            "jetty" => self.jetty,
            "nodejs" => self.nodejs,
            "go-http" => self.go_http,
            _ => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub scan_mode: ScanMode,
    pub ports: Vec<u16>,
    pub ports_spec: String,
    pub known_service_field: Option<String>,
    pub rate: u64,
    pub burst: u64,
    pub concurrency: usize,
    pub probe_concurrency: usize,
    pub fingerprint_concurrency: usize,
    pub host_concurrency: usize,
    pub queue_depth: usize,
    pub tcp_timeout: Duration,
    pub tcp_retries: u32,
    pub http_timeout: Duration,
    pub http_body_timeout: Duration,
    pub tls_timeout: Duration,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub max_body: usize,
    pub output: PathBuf,
    pub csv: Option<PathBuf>,
    pub flat_output: Option<PathBuf>,
    pub export_nmap: Option<PathBuf>,
    pub export_urls: Option<PathBuf>,
    pub metrics_json: Option<PathBuf>,
    pub checkpoint: Option<PathBuf>,
    pub resume: Option<PathBuf>,
    pub scan_label: Option<String>,
    pub fingerprints: FingerprintToggles,
    pub suspicion: SuspicionWeights,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub protocol: ProtocolConfig,
    #[serde(default)]
    pub fingerprint: FingerprintToggles,
    #[serde(default)]
    pub suspicion: SuspicionWeights,
    #[serde(default)]
    pub output: OutputConfig,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub mode: Option<ScanMode>,
    pub ports: Option<String>,
    pub known_service_field: Option<String>,
    pub rate: Option<u64>,
    pub burst: Option<u64>,
    pub concurrency: Option<usize>,
    pub host_concurrency: Option<usize>,
    pub queue_depth: Option<usize>,
    pub tcp_timeout_ms: Option<u64>,
    pub tcp_retries: Option<u32>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtocolConfig {
    pub http: Option<bool>,
    pub https: Option<bool>,
    pub http_timeout_ms: Option<u64>,
    pub http_body_timeout_ms: Option<u64>,
    pub tls_timeout_ms: Option<u64>,
    pub max_body_bytes: Option<usize>,
    pub probe_concurrency: Option<usize>,
    pub fingerprint_concurrency: Option<usize>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    pub jsonl: Option<PathBuf>,
    pub csv: Option<PathBuf>,
    pub flat_jsonl: Option<PathBuf>,
    pub export_nmap: Option<PathBuf>,
    pub export_urls: Option<PathBuf>,
    pub metrics_json: Option<PathBuf>,
    pub scan_label: Option<String>,
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
        let scan_mode = cli
            .scan_mode
            .or(file.scan.mode)
            .unwrap_or(ScanMode::Connect);
        // One raw sender already saturates the configured packet rate, so parallel
        // hosts only buy anything for the connect backend.
        let default_host_concurrency = match scan_mode {
            ScanMode::Connect => 8,
            ScanMode::Syn => 1,
        };
        let settings = Self {
            scan_mode,
            ports: parse_ports(&ports_spec)?,
            ports_spec,
            known_service_field: cli
                .known_service_field
                .clone()
                .or(file.scan.known_service_field),
            rate: cli.rate.or(file.scan.rate).unwrap_or(10_000),
            burst: cli.burst.or(file.scan.burst).unwrap_or(1_000),
            concurrency: cli.concurrency.or(file.scan.concurrency).unwrap_or(1_024),
            probe_concurrency: cli
                .probe_concurrency
                .or(file.protocol.probe_concurrency)
                .unwrap_or(128),
            fingerprint_concurrency: cli
                .fingerprint_concurrency
                .or(file.protocol.fingerprint_concurrency)
                .unwrap_or(32),
            host_concurrency: cli
                .host_concurrency
                .or(file.scan.host_concurrency)
                .unwrap_or(default_host_concurrency),
            queue_depth: cli.queue_depth.or(file.scan.queue_depth).unwrap_or(64),
            tcp_timeout: cli
                .tcp_timeout
                .or(file.scan.tcp_timeout_ms.map(Duration::from_millis))
                .unwrap_or(Duration::from_millis(700)),
            tcp_retries: cli.tcp_retries.or(file.scan.tcp_retries).unwrap_or(1),
            http_timeout: cli
                .http_timeout
                .or(file.protocol.http_timeout_ms.map(Duration::from_millis))
                .unwrap_or(Duration::from_secs(1)),
            http_body_timeout: cli
                .http_body_timeout
                .or(file
                    .protocol
                    .http_body_timeout_ms
                    .map(Duration::from_millis))
                .unwrap_or(Duration::from_millis(1_500)),
            tls_timeout: cli
                .tls_timeout
                .or(file.protocol.tls_timeout_ms.map(Duration::from_millis))
                .unwrap_or(Duration::from_secs(1)),
            http_enabled: file.protocol.http.unwrap_or(true),
            https_enabled: file.protocol.https.unwrap_or(true),
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
            scan_label: cli.scan_label.clone().or(file.output.scan_label),
            fingerprints: file.fingerprint,
            suspicion: file.suspicion,
        };
        if settings.rate == 0 || settings.burst == 0 {
            bail!("rate and burst must be greater than zero");
        }
        if settings.concurrency == 0
            || settings.probe_concurrency == 0
            || settings.fingerprint_concurrency == 0
        {
            bail!("concurrency values must be greater than zero");
        }
        if settings.host_concurrency == 0 || settings.queue_depth == 0 {
            bail!("host-concurrency and queue-depth must be greater than zero");
        }
        if settings.max_body == 0 {
            bail!("max-body must be greater than zero");
        }
        if settings.tcp_timeout.is_zero()
            || settings.tls_timeout.is_zero()
            || settings.http_timeout.is_zero()
            || settings.http_body_timeout.is_zero()
        {
            bail!("all timeout values must be greater than zero");
        }
        if !settings.http_enabled && !settings.https_enabled {
            bail!("at least one of protocol.http or protocol.https must be enabled");
        }
        if settings.http_body_timeout < settings.http_timeout {
            tracing::warn!(
                "http-body-timeout is shorter than http-timeout; the body deadline wins"
            );
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn config_typos_are_rejected_instead_of_silently_ignored() {
        let parsed = toml::from_str::<FileConfig>("[scan]\ntcp_timout_ms = 10\n");
        assert!(parsed.is_err());
    }

    #[test]
    fn protocol_switches_are_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.toml");
        std::fs::write(&path, "[protocol]\nhttp = false\nhttps = true\n").unwrap();
        let cli = Cli::parse_from([
            "surface-scan",
            "--config",
            path.to_str().unwrap(),
            "127.0.0.1",
        ]);
        let settings = Settings::load(&cli).unwrap();
        assert!(!settings.http_enabled);
        assert!(settings.https_enabled);
    }

    #[test]
    fn disabling_every_web_probe_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.toml");
        std::fs::write(&path, "[protocol]\nhttp = false\nhttps = false\n").unwrap();
        let cli = Cli::parse_from([
            "surface-scan",
            "--config",
            path.to_str().unwrap(),
            "127.0.0.1",
        ]);
        assert!(Settings::load(&cli).is_err());
    }
}
