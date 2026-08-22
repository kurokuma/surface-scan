use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::Ipv4Addr};

/// Output schema version. Bump when a field changes meaning, so that an S3 or
/// Athena reader can tell records apart.
pub const SCHEMA_VERSION: &str = "2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub known_c2_ports: Vec<u16>,
}

/// Run-level provenance stamped into every emitted record.
///
/// Results are archived and queried long after the run, so each line has to
/// carry the parameters that produced it rather than relying on the operator
/// remembering the command line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub tool: String,
    pub tool_version: String,
    pub schema_version: String,
    pub scan_id: String,
    pub scan_label: Option<String>,
    pub scan_started_at: String,
    pub scan_mode: String,
    pub port_spec: String,
    pub port_count: usize,
    pub target_count: usize,
    pub target_set_hash: String,
    pub rate: u64,
    pub burst: u64,
    pub concurrency: usize,
    pub probe_concurrency: usize,
    pub fingerprint_concurrency: usize,
    pub host_concurrency: usize,
    pub queue_depth: usize,
    pub tcp_timeout_ms: u64,
    pub tcp_retries: u32,
    pub tls_timeout_ms: u64,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub http_timeout_ms: u64,
    pub http_body_timeout_ms: u64,
    pub max_body_bytes: usize,
    /// TLS certificate chains are deliberately not verified; see `tls.validity`
    /// and `tls.self_signed` for the observed certificate state.
    pub tls_verification: String,
    pub resumed: bool,
    pub host_os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FingerprintMatch {
    pub name: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsMetadata {
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub certificate_sha256: Option<String>,
    pub public_key_sha256: Option<String>,
    pub san: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub self_signed: Option<bool>,
    pub validity: Option<String>,
    pub hostname_match: Option<bool>,
    /// Always true: chains are accepted so that scanning never stops on an
    /// invalid certificate. The observed state is reported, not enforced.
    pub verification_skipped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResult {
    pub port: u16,
    pub transport: String,
    pub protocol: String,
    pub state: String,
    pub known_c2_port: bool,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub location: Option<String>,
    pub www_authenticate: Option<String>,
    pub cookie_names: Vec<String>,
    pub response_headers: BTreeMap<String, String>,
    pub body_length: Option<usize>,
    pub body_sha256: Option<String>,
    pub favicon_hash: Option<String>,
    pub favicon_mmh3: Option<i32>,
    pub redirect_destination: Option<String>,
    pub response_latency_ms: Option<u64>,
    pub fingerprint_latency_ms: Option<u64>,
    pub tls: Option<TlsMetadata>,
    pub fingerprints: Vec<FingerprintMatch>,
    pub known_product: Option<String>,
    pub classification: Option<String>,
    pub is_unknown_web: bool,
    pub suspicion_score: u32,
    pub suspicion_reasons: Vec<String>,
    /// Bounded, in-memory evidence passed from protocol detection to the
    /// fingerprint stage. It is deliberately never serialized.
    #[serde(skip)]
    pub fingerprint_body: Option<String>,
    /// Internal stage timing; exported through the host scan summary only.
    #[serde(skip)]
    pub protocol_probe_latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ServiceResult {
    pub fn unknown_tcp(port: u16, known_c2_port: bool) -> Self {
        Self {
            port,
            transport: "tcp".into(),
            protocol: "unknown".into(),
            state: "open".into(),
            known_c2_port,
            status: None,
            title: None,
            server: None,
            content_type: None,
            content_length: None,
            location: None,
            www_authenticate: None,
            cookie_names: vec![],
            response_headers: BTreeMap::new(),
            body_length: None,
            body_sha256: None,
            favicon_hash: None,
            favicon_mmh3: None,
            redirect_destination: None,
            response_latency_ms: None,
            fingerprint_latency_ms: None,
            tls: None,
            fingerprints: vec![],
            known_product: None,
            classification: None,
            is_unknown_web: false,
            suspicion_score: 0,
            suspicion_reasons: vec![],
            fingerprint_body: None,
            protocol_probe_latency_ms: None,
            error: None,
        }
    }

    pub fn is_web(&self) -> bool {
        matches!(self.protocol.as_str(), "http" | "https")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub ports_scanned: usize,
    pub ports_attempted: usize,
    pub tcp_probes_sent: u64,
    pub open_ports: usize,
    pub tcp_discovery_ms: u64,
    pub protocol_detection_ms: u64,
    pub fingerprint_ms: u64,
    /// False when Ctrl+C landed mid-host; such a host is never checkpointed as
    /// completed and is rescanned on resume.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub schema_version: String,
    pub meta: ScanMetadata,
    pub ip: Ipv4Addr,
    pub started_at: String,
    pub completed_at: String,
    pub scan: ScanSummary,
    pub services: Vec<ServiceResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metrics {
    pub targets: usize,
    pub ports_per_target: usize,
    pub hosts_completed: usize,
    pub hosts_interrupted: usize,
    pub tcp_probes: u64,
    pub open_ports: u64,
    pub http_services: u64,
    pub https_services: u64,
    pub tls_non_http_services: u64,
    pub unknown_tcp_services: u64,
    pub hfs: u64,
    pub directory_listings: u64,
    pub login_admin_panels: u64,
    pub unknown_web_surfaces: u64,
    pub elapsed_ms: u64,
    /// Wall-clock duration of the overlapping discovery stage.
    pub tcp_discovery_wall_ms: u64,
    pub tcp_discovery_ms: u64,
    pub protocol_detection_ms: u64,
    pub fingerprint_ms: u64,
    pub tcp_probe_rate_avg: f64,
    pub interrupted: bool,
}

/// Metrics document written by `--metrics-json`, carrying the same provenance
/// block as the host records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsDocument {
    pub schema_version: String,
    pub meta: ScanMetadata,
    pub completed_at: String,
    pub metrics: Metrics,
}
