use operator_surface_scanner::protocol::{ProbeContext, ProtocolProbe, WebProbe};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

fn context() -> ProbeContext {
    ProbeContext {
        http_timeout: Duration::from_secs(2),
        tls_timeout: Duration::from_secs(2),
        max_body: 262_144,
    }
}

async fn bind_preferred(port: u16) -> TcpListener {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => listener,
        Err(_) => TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
    }
}

#[tokio::test]
async fn detects_http_on_high_port_and_hashes_favicon() {
    let listener = bind_preferred(31337).await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let n = socket.read(&mut req).await.unwrap();
            let favicon = String::from_utf8_lossy(&req[..n]).contains("/favicon.ico");
            let body = if favicon {
                b"ICON".as_slice()
            } else {
                b"<html><title>Index of /</title></html>".as_slice()
            };
            let response = format!(
                "HTTP/1.0 200 OK\r\nServer: nginx\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        }
    });
    let result = WebProbe::default().probe(addr, false, &context()).await;
    assert_eq!(result.protocol, "http");
    assert_eq!(result.classification.as_deref(), Some("directory_listing"));
    assert!(result.favicon_hash.is_some());
}

#[tokio::test]
async fn detects_https_on_high_port_with_self_signed_metadata() {
    let generated = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = bind_preferred(49152).await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let mut req = [0u8; 1024];
            let _ = tls.read(&mut req).await.unwrap();
            tls.write_all(
                b"HTTP/1.0 200 OK\r\nContent-Length: 31\r\n\r\n<form><input type='password'>",
            )
            .await
            .unwrap();
        }
    });
    let result = WebProbe::default().probe(addr, false, &context()).await;
    assert_eq!(result.protocol, "https", "{result:#?}");
    assert!(
        result
            .tls
            .as_ref()
            .and_then(|t| t.subject.as_ref())
            .is_some()
    );
    assert_eq!(result.classification.as_deref(), Some("login_panel"));
}

#[tokio::test]
async fn does_not_misclassify_non_http_tcp() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"SSH-2.0-test\r\n").await;
            }
        }
    });
    let result = WebProbe::default().probe(addr, false, &context()).await;
    assert_eq!(result.protocol, "unknown");
    assert!(!result.is_unknown_web);
}
