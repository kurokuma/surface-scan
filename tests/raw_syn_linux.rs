#![cfg(target_os = "linux")]

use clap::Parser;
use operator_surface_scanner::{
    cli::{Cli, ScanMode},
    config::Settings,
    scanner,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn settings(port: u16) -> Settings {
    let port_text = port.to_string();
    let cli = Cli::parse_from([
        "surface-scan",
        "--scan-mode",
        "syn",
        "-p",
        &port_text,
        "--rate",
        "1000",
        "--burst",
        "10",
        "--tcp-timeout",
        "300ms",
        "--tcp-retries",
        "1",
        "127.0.0.1",
    ]);
    let settings = Settings::load(&cli).unwrap();
    assert_eq!(settings.scan_mode, ScanMode::Syn);
    settings
}

#[tokio::test]
#[ignore = "requires Linux root or CAP_NET_RAW"]
async fn raw_syn_detects_a_loopback_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let settings = settings(port);
    let backend = scanner::backend(&settings).await.unwrap();
    let outcome = backend
        .discover(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(outcome.open, vec![port]);
    assert!(outcome.complete);
    assert!(outcome.probes_sent >= 1);
    drop(listener);
}

/// A closed port must be reported as such without exhausting the retry budget,
/// and must never appear in the open list.
#[tokio::test]
#[ignore = "requires Linux root or CAP_NET_RAW"]
async fn raw_syn_reports_a_closed_port_as_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let settings = settings(port);
    let backend = scanner::backend(&settings).await.unwrap();
    let outcome = backend
        .discover(
            "127.0.0.1".parse().unwrap(),
            &[port],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(outcome.open.is_empty(), "{outcome:?}");
    assert!(outcome.complete);
}

/// Cancellation must surface as an incomplete sweep so the host is rescanned.
#[tokio::test]
#[ignore = "requires Linux root or CAP_NET_RAW"]
async fn raw_syn_reports_cancellation_as_incomplete() {
    let settings = settings(80);
    let backend = scanner::backend(&settings).await.unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let outcome = backend
        .discover("127.0.0.1".parse().unwrap(), &[80, 443], &cancel)
        .await
        .unwrap();
    assert!(!outcome.complete);
}
