use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::Ipv4Addr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub known_c2_ports: Vec<u16>,
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
    pub san: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub self_signed: Option<bool>,
    pub validity: Option<String>,
    pub hostname_match: Option<bool>,
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
    pub redirect_destination: Option<String>,
    pub response_latency_ms: Option<u64>,
    pub fingerprint_latency_ms: Option<u64>,
    pub tls: Option<TlsMetadata>,
    pub fingerprints: Vec<FingerprintMatch>,
    pub known_product: Option<String>,
    pub classification: Option<String>,
    pub is_unknown_web: bool,
    pub suspicion_score: u32,
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
            redirect_destination: None,
            response_latency_ms: None,
            fingerprint_latency_ms: None,
            tls: None,
            fingerprints: vec![],
            known_product: None,
            classification: None,
            is_unknown_web: false,
            suspicion_score: 0,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub tcp_discovery_ms: u64,
    pub protocol_detection_ms: u64,
    pub fingerprint_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub schema_version: String,
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
    pub tcp_probes: u64,
    pub open_ports: u64,
    pub http_services: u64,
    pub https_services: u64,
    pub hfs: u64,
    pub directory_listings: u64,
    pub login_admin_panels: u64,
    pub unknown_web_surfaces: u64,
    pub elapsed_ms: u64,
    pub tcp_discovery_ms: u64,
    pub protocol_detection_ms: u64,
    pub fingerprint_ms: u64,
    pub tcp_probe_rate_avg: f64,
}
