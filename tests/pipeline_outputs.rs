use serde_json::Value;
use std::{net::Ipv4Addr, path::Path};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};

#[tokio::test]
async fn cli_scans_open_only_and_writes_all_output_shapes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let body = b"<html><title>Admin Panel</title></html>";
            let header = format!(
                "HTTP/1.0 200 OK\r\nServer: test\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(body).await;
        }
    });
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
    for output in [&flat, &csv, &urls, &nmap, &metrics] {
        assert!(
            output.metadata().unwrap().len() > 0,
            "{} is empty",
            output.display()
        );
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
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
