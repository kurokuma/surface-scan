//! Review 2.2: a host cut short by shutdown must not be recorded as completed,
//! or a resume silently skips its unscanned ports.

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use operator_surface_scanner::{
    cli::{Cli, ScanMode},
    config::Settings,
    fingerprint::FingerprintEngine,
    model::{SCHEMA_VERSION, ScanMetadata, Target},
    output::OutputWriters,
    protocol::{ProbeContext, WebProbe},
    runtime::{Checkpoint, pipeline::Pipeline},
    scanner::{DiscoveryOutcome, ScannerBackend},
    util::now_rfc3339,
};
use std::{net::Ipv4Addr, sync::Arc};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

/// Backend that reports a sweep cut short, as the real backends do on Ctrl+C.
struct InterruptedBackend;

#[async_trait]
impl ScannerBackend for InterruptedBackend {
    fn name(&self) -> &'static str {
        "test-interrupted"
    }
    async fn discover(
        &self,
        _ip: Ipv4Addr,
        _ports: &[u16],
        cancel: &CancellationToken,
    ) -> Result<DiscoveryOutcome> {
        cancel.cancel();
        Ok(DiscoveryOutcome {
            open: vec![],
            attempted: 1,
            probes_sent: 1,
            complete: false,
        })
    }
}

fn settings() -> Settings {
    let cli = Cli::parse_from(["surface-scan", "-p", "1-16", "192.0.2.1"]);
    let mut settings = Settings::load(&cli).unwrap();
    settings.scan_mode = ScanMode::Connect;
    settings
}

fn metadata(settings: &Settings) -> ScanMetadata {
    ScanMetadata {
        tool: "operator-surface-scanner".into(),
        tool_version: "test".into(),
        schema_version: SCHEMA_VERSION.into(),
        scan_id: "test-scan".into(),
        scan_label: None,
        scan_started_at: now_rfc3339(),
        scan_mode: "test-interrupted".into(),
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
        worker_threads: settings.worker_threads,
        processes: settings.processes,
        tcp_timeout_ms: 200,
        tcp_retries: 0,
        tls_timeout_ms: 200,
        http_enabled: true,
        https_enabled: true,
        http_timeout_ms: 200,
        http_body_timeout_ms: 500,
        max_body_bytes: settings.max_body,
        tls_verification: "skipped".into(),
        resumed: false,
        host_os: std::env::consts::OS.into(),
    }
}

#[tokio::test]
async fn an_interrupted_host_is_not_checkpointed_as_completed() {
    let dir = tempdir().unwrap();
    let jsonl = dir.path().join("hosts.jsonl");
    let state = dir.path().join("scan.state");
    let settings = settings();
    let writers = OutputWriters::open(&jsonl, None, None, None, None, false).unwrap();
    let pipeline = Pipeline {
        probe_ctx: ProbeContext::from_settings(&settings),
        probe: Arc::new(WebProbe::default()),
        fingerprint: Arc::new(FingerprintEngine::new(&settings.fingerprints)),
        backend: Arc::new(InterruptedBackend),
        meta: metadata(&settings),
        cancel: CancellationToken::new(),
        checkpoint_path: Some(state.clone()),
        settings: settings.clone(),
    };
    let target = Target {
        ip: "192.0.2.1".parse().unwrap(),
        known_c2_ports: vec![],
    };
    let checkpoint = Checkpoint::fresh("hash".into(), settings.ports_spec.clone());
    let metrics = pipeline
        .run(vec![target], checkpoint, writers)
        .await
        .unwrap();

    assert_eq!(metrics.hosts_interrupted, 1);
    assert_eq!(metrics.hosts_completed, 0);
    assert!(metrics.interrupted);

    let saved: Checkpoint = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert!(
        saved.completed_hosts.is_empty(),
        "interrupted host must be rescanned on resume, got {:?}",
        saved.completed_hosts
    );
    assert_eq!(
        saved.output_position, 0,
        "resume must roll back the partial host record"
    );

    // The partial result is still written, so nothing observed is thrown away.
    let written = std::fs::read_to_string(&jsonl).unwrap();
    let host: serde_json::Value = serde_json::from_str(written.trim()).unwrap();
    assert_eq!(host["ip"], "192.0.2.1");
    assert_eq!(host["scan"]["complete"], false);

    let mut resumed = OutputWriters::open_at(
        &jsonl,
        None,
        None,
        None,
        None,
        true,
        Some(saved.output_position),
    )
    .unwrap();
    resumed.flush().unwrap();
    drop(resumed);
    assert!(std::fs::read(&jsonl).unwrap().is_empty());
}
