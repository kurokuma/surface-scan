use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use operator_surface_scanner::{
    cli::Cli,
    config::Settings,
    fingerprint::FingerprintEngine,
    model::{SCHEMA_VERSION, ScanMetadata, ServiceResult, Target},
    output::OutputWriters,
    protocol::{ProbeContext, ProtocolProbe},
    runtime::{Checkpoint, pipeline::Pipeline},
    scanner::{DiscoveryOutcome, ScannerBackend},
    util::now_rfc3339,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

struct ManyOpenPorts;
#[async_trait]
impl ScannerBackend for ManyOpenPorts {
    fn name(&self) -> &'static str {
        "test-many-open"
    }
    async fn discover(
        &self,
        _ip: Ipv4Addr,
        ports: &[u16],
        _cancel: &CancellationToken,
    ) -> Result<DiscoveryOutcome> {
        Ok(DiscoveryOutcome {
            open: ports.to_vec(),
            attempted: ports.len(),
            probes_sent: ports.len() as u64,
            complete: true,
        })
    }
}

struct CountingProbe {
    active: AtomicUsize,
    maximum: AtomicUsize,
}
#[async_trait]
impl ProtocolProbe for CountingProbe {
    fn name(&self) -> &'static str {
        "counting"
    }
    async fn probe(&self, target: SocketAddr, known: bool, _: &ProbeContext) -> ServiceResult {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(3)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        ServiceResult::unknown_tcp(target.port(), known)
    }
}

#[tokio::test]
async fn open_port_work_is_bounded_by_probe_concurrency() {
    let cli = Cli::parse_from(["surface-scan", "-p", "1-100", "127.0.0.1"]);
    let mut settings = Settings::load(&cli).unwrap();
    settings.probe_concurrency = 3;
    settings.fingerprint_concurrency = 2;
    settings.host_concurrency = 1;
    settings.queue_depth = 2;
    let meta = ScanMetadata {
        tool: "operator-surface-scanner".into(),
        tool_version: "test".into(),
        schema_version: SCHEMA_VERSION.into(),
        scan_id: "bounded".into(),
        scan_label: None,
        scan_started_at: now_rfc3339(),
        scan_mode: "test".into(),
        port_spec: settings.ports_spec.clone(),
        port_count: settings.ports.len(),
        target_count: 1,
        target_set_hash: "hash".into(),
        rate: settings.rate,
        burst: settings.burst,
        concurrency: settings.concurrency,
        probe_concurrency: settings.probe_concurrency,
        fingerprint_concurrency: settings.fingerprint_concurrency,
        host_concurrency: settings.host_concurrency,
        queue_depth: settings.queue_depth,
        tcp_timeout_ms: 1,
        tcp_retries: 0,
        tls_timeout_ms: 1,
        http_enabled: true,
        https_enabled: true,
        http_timeout_ms: 1,
        http_body_timeout_ms: 1,
        max_body_bytes: settings.max_body,
        tls_verification: "skipped".into(),
        resumed: false,
        host_os: std::env::consts::OS.into(),
    };
    let probe = Arc::new(CountingProbe {
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
    });
    let dir = tempdir().unwrap();
    let output = dir.path().join("hosts.jsonl");
    let writers = OutputWriters::open(&output, None, None, None, None, false).unwrap();
    let pipeline = Pipeline {
        probe_ctx: ProbeContext::from_settings(&settings),
        probe: probe.clone(),
        fingerprint: Arc::new(FingerprintEngine::new(&settings.fingerprints)),
        backend: Arc::new(ManyOpenPorts),
        meta,
        cancel: CancellationToken::new(),
        checkpoint_path: None,
        settings: settings.clone(),
    };
    let metrics = pipeline
        .run(
            vec![Target {
                ip: "127.0.0.1".parse().unwrap(),
                known_c2_ports: vec![],
            }],
            Checkpoint::fresh("hash".into(), settings.ports_spec),
            writers,
        )
        .await
        .unwrap();
    assert_eq!(metrics.open_ports, 100);
    assert!(probe.maximum.load(Ordering::SeqCst) <= 3);
    let host: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(output).unwrap().trim()).unwrap();
    assert_eq!(host["services"].as_array().unwrap().len(), 100);
}
