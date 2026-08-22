#![cfg(target_os = "linux")]

use operator_surface_scanner::{cli::ScanMode, config::Settings, scanner};
use std::{path::PathBuf, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires Linux root or CAP_NET_RAW"]
async fn raw_syn_detects_a_loopback_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let settings = Settings {
        scan_mode: ScanMode::Syn,
        ports: vec![port],
        ports_spec: port.to_string(),
        rate: 1_000,
        burst: 10,
        concurrency: 16,
        probe_concurrency: 4,
        tcp_timeout: Duration::from_millis(300),
        tcp_retries: 1,
        http_timeout: Duration::from_secs(1),
        tls_timeout: Duration::from_secs(1),
        max_body: 65_536,
        output: PathBuf::from("unused.jsonl"),
        csv: None,
        flat_output: None,
        export_nmap: None,
        export_urls: None,
        metrics_json: None,
        checkpoint: None,
        resume: None,
    };
    let backend = scanner::backend(&settings).await.unwrap();
    let open = backend
        .discover(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(open, vec![port]);
    drop(listener);
}
