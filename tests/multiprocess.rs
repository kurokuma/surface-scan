use serde_json::Value;
use std::{net::Ipv4Addr, path::Path};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

async fn serve_on_every_loopback_address() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let n = socket.read(&mut request).await.unwrap_or(0);
                if request[..n].starts_with(b"GET ") {
                    let body = b"<html><title>Parallel Panel</title></html>";
                    let header = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(body).await;
                }
            });
        }
    });
    port
}

fn common_args<'a>(
    port: &'a str,
    output: &'a Path,
    csv: &'a Path,
    metrics: &'a Path,
) -> Vec<&'a str> {
    vec![
        "--scan-mode",
        "connect",
        "--processes",
        "2",
        "--worker-threads",
        "2",
        "--rate",
        "1000",
        "--burst",
        "10",
        "--concurrency",
        "16",
        "--probe-concurrency",
        "4",
        "--fingerprint-concurrency",
        "2",
        "--host-concurrency",
        "2",
        "--tcp-timeout",
        "200ms",
        "--tcp-retries",
        "0",
        "--tls-timeout",
        "200ms",
        "-p",
        port,
        "-o",
        path(output),
        "--csv",
        path(csv),
        "--metrics-json",
        path(metrics),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_processes_merge_outputs_and_resume_without_duplicates() {
    let port = serve_on_every_loopback_address().await;
    let port = port.to_string();
    let dir = tempdir().unwrap();
    let output = dir.path().join("hosts.jsonl");
    let csv = dir.path().join("services.csv");
    let metrics = dir.path().join("metrics.json");
    let checkpoint = dir.path().join("multi.state");

    let mut args = common_args(&port, &output, &csv, &metrics);
    args.extend(["--checkpoint", path(&checkpoint), "127.0.0.1", "127.0.0.2"]);
    let status = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args(&args)
        .status()
        .await
        .unwrap();
    assert!(status.success());

    let lines: Vec<_> = std::fs::read_to_string(&output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["ip"], "127.0.0.1");
    assert_eq!(lines[1]["ip"], "127.0.0.2");
    assert!(lines.iter().all(|host| host["meta"]["processes"] == 2));
    assert!(lines.iter().all(|host| host["meta"]["worker_threads"] == 2));
    assert_eq!(std::fs::read_to_string(&csv).unwrap().lines().count(), 3);
    let first_metrics: Value = serde_json::from_slice(&std::fs::read(&metrics).unwrap()).unwrap();
    assert_eq!(first_metrics["metrics"]["hosts_completed"], 2);

    let mut resume_args = common_args(&port, &output, &csv, &metrics);
    resume_args.extend(["--resume", path(&checkpoint), "127.0.0.1", "127.0.0.2"]);
    let resumed = Command::new(env!("CARGO_BIN_EXE_surface-scan"))
        .args(&resume_args)
        .status()
        .await
        .unwrap();
    assert!(resumed.success());
    assert_eq!(std::fs::read_to_string(&output).unwrap().lines().count(), 2);
    assert_eq!(std::fs::read_to_string(&csv).unwrap().lines().count(), 3);
    let resumed_metrics: Value = serde_json::from_slice(&std::fs::read(&metrics).unwrap()).unwrap();
    assert_eq!(resumed_metrics["metrics"]["hosts_completed"], 2);
}
