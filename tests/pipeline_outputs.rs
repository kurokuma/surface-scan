use serde_json::Value;
use std::{net::Ipv4Addr, path::Path};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};

/// Serve a fixed HTML page on an ephemeral port until the test finishes.
async fn serve_html(body: &'static [u8]) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let header = format!(
                    "HTTP/1.0 200 OK\r\nServer: test\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(body).await;
            });
        }
    });
    port
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[tokio::test]
async fn input_and_output_path_alias_is_rejected_without_truncating_input() {
    let dir = tempdir().unwrap();
    let targets = dir.path().join("targets.txt");
    std::fs::write(&targets, "127.0.0.1\n").unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args(["-i", path(&targets), "-o", path(&targets), "-p", "1"])
        .status()
        .await
        .unwrap();
    assert!(!status.success());
    assert_eq!(std::fs::read_to_string(targets).unwrap(), "127.0.0.1\n");
}

#[tokio::test]
async fn cli_scans_open_only_and_writes_all_output_shapes() {
    let port = serve_html(b"<html><title>Admin Panel</title></html>").await;
    let dir = tempdir().unwrap();
    let jsonl = dir.path().join("hosts.jsonl");
    let flat = dir.path().join("flat.jsonl");
    let csv = dir.path().join("services.csv");
    let urls = dir.path().join("urls.txt");
    let nmap = dir.path().join("nmap.txt");
    let metrics = dir.path().join("metrics.json");
    let checkpoint = dir.path().join("scan.state");
    let port_text = port.to_string();
    let status = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args([
            "--scan-mode",
            "connect",
            "--rate",
            "10000",
            "--burst",
            "100",
            "--tcp-timeout",
            "200ms",
            "--tls-timeout",
            "200ms",
            "--http-timeout",
            "1s",
            "--scan-label",
            "regression-suite",
            "-p",
            &port_text,
            "-o",
            path(&jsonl),
            "--flat-output",
            path(&flat),
            "--csv",
            path(&csv),
            "--export-urls",
            path(&urls),
            "--export-nmap",
            path(&nmap),
            "--metrics-json",
            path(&metrics),
            "--checkpoint",
            path(&checkpoint),
            "127.0.0.1",
        ])
        .status()
        .await
        .unwrap();
    assert!(status.success());

    let host: Value =
        serde_json::from_str(std::fs::read_to_string(&jsonl).unwrap().trim()).unwrap();
    assert_eq!(host["ip"], "127.0.0.1");
    assert_eq!(host["services"][0]["port"], port);
    assert_eq!(host["services"][0]["protocol"], "http");
    assert!(host["services"][0].get("fingerprint_body").is_none());
    assert!(
        host["services"][0]
            .get("protocol_probe_latency_ms")
            .is_none()
    );
    assert_eq!(host["scan"]["complete"], true);

    // Provenance travels with the record, so an archived line stays readable.
    let meta = &host["meta"];
    assert_eq!(meta["tool"], "operator-surface-scanner");
    assert_eq!(meta["scan_label"], "regression-suite");
    assert_eq!(meta["scan_mode"], "connect");
    assert_eq!(meta["tls_verification"], "skipped");
    assert_eq!(meta["port_spec"], port_text);
    assert!(meta["scan_id"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(meta["tool_version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(meta["http_body_timeout_ms"].as_u64().unwrap() > 0);

    // Flat service records carry the same provenance block.
    let flat_line: Value =
        serde_json::from_str(std::fs::read_to_string(&flat).unwrap().trim()).unwrap();
    assert_eq!(flat_line["meta"]["scan_id"], meta["scan_id"]);
    assert_eq!(flat_line["service"]["port"], port);

    // Metrics are wrapped in the same envelope.
    let metrics_doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&metrics).unwrap()).unwrap();
    assert_eq!(metrics_doc["meta"]["scan_id"], meta["scan_id"]);
    assert_eq!(metrics_doc["metrics"]["hosts_completed"], 1);
    assert_eq!(metrics_doc["metrics"]["interrupted"], false);

    for output in [&flat, &csv, &urls, &nmap] {
        assert!(
            output.metadata().unwrap().len() > 0,
            "{} is empty",
            output.display()
        );
    }

    // Simulate a crash after derived outputs were flushed but before the
    // checkpoint moved forward. Resume must regenerate these files from the
    // authoritative host JSONL instead of preserving duplicate tails.
    for output in [&flat, &csv, &urls, &nmap] {
        let original = std::fs::read(output).unwrap();
        let mut duplicated = original.clone();
        duplicated.extend_from_slice(&original);
        std::fs::write(output, duplicated).unwrap();
    }

    let resumed = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args([
            "--scan-mode",
            "connect",
            "-p",
            &port_text,
            "-o",
            path(&jsonl),
            "--flat-output",
            path(&flat),
            "--csv",
            path(&csv),
            "--export-urls",
            path(&urls),
            "--export-nmap",
            path(&nmap),
            "--resume",
            path(&checkpoint),
            "127.0.0.1",
        ])
        .status()
        .await
        .unwrap();
    assert!(resumed.success());
    assert_eq!(
        std::fs::read_to_string(&jsonl).unwrap().lines().count(),
        1,
        "resume duplicated a completed host"
    );
    // Appending must not add a second header row.
    let csv_text = std::fs::read_to_string(&csv).unwrap();
    assert_eq!(
        csv_text
            .lines()
            .filter(|l| l.starts_with("scan_id,"))
            .count(),
        1,
        "resume wrote a duplicate CSV header:\n{csv_text}"
    );
    assert_eq!(
        csv_text.lines().count(),
        2,
        "resume kept duplicate CSV rows"
    );
    assert_eq!(std::fs::read_to_string(&flat).unwrap().lines().count(), 1);
    assert_eq!(std::fs::read_to_string(&urls).unwrap().lines().count(), 1);
    assert_eq!(std::fs::read_to_string(&nmap).unwrap().lines().count(), 1);
}

/// Review 2.4: a fresh run truncates the CSV, so it must rewrite the header.
#[tokio::test]
async fn rerunning_over_an_existing_csv_keeps_a_header() {
    let port = serve_html(b"<html><title>Panel</title></html>").await;
    let dir = tempdir().unwrap();
    let jsonl = dir.path().join("hosts.jsonl");
    let csv = dir.path().join("services.csv");
    let port_text = port.to_string();
    for run in 0..2 {
        let status = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
            .args([
                "--scan-mode",
                "connect",
                "--tcp-timeout",
                "200ms",
                "--tls-timeout",
                "200ms",
                "-p",
                &port_text,
                "-o",
                path(&jsonl),
                "--csv",
                path(&csv),
                "127.0.0.1",
            ])
            .status()
            .await
            .unwrap();
        assert!(status.success(), "run {run} failed");
        let text = std::fs::read_to_string(&csv).unwrap();
        assert!(
            text.starts_with("scan_id,scan_started_at,ip,port,protocol,"),
            "run {run} produced a headerless CSV:\n{text}"
        );
        assert_eq!(text.lines().count(), 2, "run {run}:\n{text}");
    }
}

/// Review 2.5: a known C2 port supplied with the target is always swept, even
/// when it falls outside `--ports` (spec section 22).
#[tokio::test]
async fn a_known_c2_port_outside_the_range_is_still_scanned() {
    let port = serve_html(b"<html><title>C2 Panel</title></html>").await;
    let dir = tempdir().unwrap();
    let jsonl = dir.path().join("hosts.jsonl");
    // Deliberately scan a different, almost certainly closed port.
    let status = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args([
            "--scan-mode",
            "connect",
            "--tcp-timeout",
            "200ms",
            "--tcp-retries",
            "0",
            "--tls-timeout",
            "200ms",
            "-p",
            "1",
            "-o",
            path(&jsonl),
            &format!("127.0.0.1:{port}"),
        ])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    let host: Value =
        serde_json::from_str(std::fs::read_to_string(&jsonl).unwrap().trim()).unwrap();
    let services = host["services"].as_array().unwrap();
    let found = services
        .iter()
        .find(|s| s["port"] == port)
        .unwrap_or_else(|| panic!("known C2 port {port} was not scanned: {host:#}"));
    assert_eq!(found["known_c2_port"], true);
    assert_eq!(found["protocol"], "http");
    assert_eq!(host["scan"]["ports_scanned"], 2);
}

/// Unknown web surfaces are the point of the tool and must be preserved with
/// their metadata rather than collapsed into "no match" (spec section 18).
#[tokio::test]
async fn an_unknown_web_surface_is_preserved() {
    let port = serve_html(b"<html><title>Totally Bespoke Operator UI</title></html>").await;
    let dir = tempdir().unwrap();
    let jsonl = dir.path().join("hosts.jsonl");
    let status = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args([
            "--scan-mode",
            "connect",
            "--tcp-timeout",
            "200ms",
            "--tls-timeout",
            "200ms",
            "-p",
            &port.to_string(),
            "-o",
            path(&jsonl),
            "127.0.0.1",
        ])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    let host: Value =
        serde_json::from_str(std::fs::read_to_string(&jsonl).unwrap().trim()).unwrap();
    let service = &host["services"][0];
    assert_eq!(service["is_unknown_web"], true);
    assert_eq!(service["known_product"], Value::Null);
    assert_eq!(service["fingerprints"].as_array().unwrap().len(), 0);
    assert_eq!(service["classification"], "unknown_web");
    assert_eq!(service["title"], "Totally Bespoke Operator UI");
    assert!(service["body_sha256"].as_str().is_some());
    // Triage reasons are exported so a score can be audited, not just trusted.
    assert!(!service["suspicion_reasons"].as_array().unwrap().is_empty());
}
