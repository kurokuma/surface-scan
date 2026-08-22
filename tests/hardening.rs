//! Regression tests for the defects found in the spec conformance review
//! (`docs/REVIEW.md`).

use operator_surface_scanner::{
    config::SuspicionWeights,
    protocol::{ProbeContext, ProtocolProbe, WebProbe},
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

fn context() -> ProbeContext {
    ProbeContext {
        http_timeout: Duration::from_secs(1),
        http_body_timeout: Duration::from_millis(1_500),
        tls_timeout: Duration::from_millis(500),
        http_enabled: true,
        https_enabled: true,
        max_body: 262_144,
        suspicion: SuspicionWeights::default(),
    }
}

/// Review 2.1: a peer that trickles one byte at a time, always inside the
/// per-read timeout, used to hold a probe open indefinitely.
#[tokio::test]
async fn a_slow_drip_server_cannot_outlast_the_body_deadline() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                if socket
                    .write_all(b"HTTP/1.0 200 OK\r\nServer: slow\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                // One byte every 200ms, forever: never idle long enough to trip
                // the per-read timeout on its own.
                loop {
                    if socket.write_all(b"A").await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            });
        }
    });

    let ctx = context();
    let started = Instant::now();
    let result = WebProbe::default().probe(addr, false, &ctx).await;
    let elapsed = started.elapsed();

    assert_eq!(result.protocol, "http");
    assert_eq!(result.server.as_deref(), Some("slow"));
    // Two requests (index plus favicon), each bounded by the body deadline.
    assert!(
        elapsed < ctx.probe_budget(),
        "probe took {elapsed:?}, budget is {:?}",
        ctx.probe_budget()
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "body deadline did not bound the probe: {elapsed:?}"
    );
}

/// Review 2.3: TLS terminated but not HTTP. The certificate is the highest
/// value pivot in this workflow and must survive.
#[tokio::test]
async fn tls_without_http_keeps_the_certificate_metadata() {
    let generated = generate_simple_self_signed(vec!["operator-panel.invalid".into()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    let mut request = [0u8; 1024];
                    let _ = tls.read(&mut request).await;
                    // Speaks TLS, but is emphatically not an HTTP server.
                    let _ = tls.write_all(b"\x17\x03\x03BINARY-C2-FRAME").await;
                }
            });
        }
    });

    let result = WebProbe::default().probe(addr, false, &context()).await;
    assert_eq!(result.protocol, "tls", "{result:#?}");
    let tls = result.tls.as_ref().expect("TLS metadata must be retained");
    assert!(tls.subject.is_some(), "{tls:#?}");
    assert!(tls.certificate_sha256.is_some(), "{tls:#?}");
    assert!(tls.public_key_sha256.is_some(), "{tls:#?}");
    assert_eq!(tls.self_signed, Some(true));
    assert!(tls.verification_skipped, "cert errors must be ignored");
    assert_eq!(result.classification.as_deref(), Some("unknown_tls"));
    // Not HTTP, so it must not be counted as a web surface.
    assert!(!result.is_web());
}

/// Certificate validation failures must never abort a probe (spec section 16).
#[tokio::test]
async fn an_untrusted_certificate_never_stops_the_probe() {
    let generated = generate_simple_self_signed(vec!["somewhere-else.invalid".into()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    let mut request = [0u8; 1024];
                    let _ = tls.read(&mut request).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"panel\"\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                }
            });
        }
    });

    let result = WebProbe::default().probe(addr, false, &context()).await;
    // Self-signed, wrong hostname, untrusted issuer: all recorded, none fatal.
    assert_eq!(result.protocol, "https", "{result:#?}");
    assert_eq!(result.status, Some(401));
    let tls = result.tls.as_ref().expect("TLS metadata");
    assert_eq!(tls.self_signed, Some(true));
    assert_eq!(tls.hostname_match, Some(false));
    assert!(tls.verification_skipped);
    assert_eq!(
        result.www_authenticate.as_deref(),
        Some("Basic realm=\"panel\"")
    );
}

/// A server that accepts the connection then says nothing must still terminate
/// quickly and be reported as unknown TCP rather than as a web service.
#[tokio::test]
async fn a_silent_listener_is_bounded_and_not_called_http() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let ctx = context();
    let started = Instant::now();
    let result = WebProbe::default().probe(addr, false, &ctx).await;
    assert_eq!(result.protocol, "unknown");
    assert!(!result.is_unknown_web);
    assert!(result.error.is_some());
    assert!(started.elapsed() < ctx.probe_budget());
}

#[tokio::test]
async fn protocol_switches_change_which_probes_are_sent() {
    // HTTP-only mode must not waste a TLS connection first.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let observed = accepts.clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            observed.fetch_add(1, Ordering::Relaxed);
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let _ = socket
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let mut http_only = context();
    http_only.https_enabled = false;
    let result = WebProbe::default().probe(address, false, &http_only).await;
    assert_eq!(result.protocol, "http", "{result:#?}");
    assert_eq!(accepts.load(Ordering::Relaxed), 2, "index and favicon only");

    // HTTPS-only mode must not fall back to a second plain connection.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let observed = accepts.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            observed.fetch_add(1, Ordering::Relaxed);
            let _ = socket
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let mut https_only = context();
    https_only.http_enabled = false;
    let result = WebProbe::default().probe(address, false, &https_only).await;
    assert_eq!(result.protocol, "unknown", "{result:#?}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "plain fallback was sent"
    );
}
