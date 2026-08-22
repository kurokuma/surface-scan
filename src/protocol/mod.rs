use crate::{
    fingerprint::{FingerprintEngine, WebEvidence, suspicion_score},
    model::{ServiceResult, TlsMetadata},
    util::sha256_hex,
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use scraper::{Html, Selector};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub http_timeout: std::time::Duration,
    pub tls_timeout: std::time::Duration,
    pub max_body: usize,
}
#[async_trait]
pub trait ProtocolProbe: Send + Sync {
    fn name(&self) -> &'static str;
    async fn probe(
        &self,
        target: SocketAddr,
        known_c2_port: bool,
        context: &ProbeContext,
    ) -> ServiceResult;
}

#[derive(Debug)]
struct NoCertificateVerification(Arc<rustls::crypto::CryptoProvider>);
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub struct WebProbe {
    fingerprints: FingerprintEngine,
    tls: TlsConnector,
}
impl Default for WebProbe {
    fn default() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        Self {
            fingerprints: FingerprintEngine::default(),
            tls: TlsConnector::from(Arc::new(config)),
        }
    }
}

#[async_trait]
impl ProtocolProbe for WebProbe {
    fn name(&self) -> &'static str {
        "web"
    }
    async fn probe(&self, target: SocketAddr, known: bool, ctx: &ProbeContext) -> ServiceResult {
        match self.probe_tls(target, known, ctx).await {
            Ok(service) => service,
            Err(tls_error) => match self.probe_plain(target, known, ctx).await {
                Ok(service) => service,
                Err(_) => {
                    let mut s = ServiceResult::unknown_tcp(target.port(), known);
                    s.error = Some(short_error(&tls_error));
                    s
                }
            },
        }
    }
}

impl WebProbe {
    async fn probe_tls(
        &self,
        target: SocketAddr,
        known: bool,
        ctx: &ProbeContext,
    ) -> Result<ServiceResult> {
        let tcp = timeout(ctx.tls_timeout, TcpStream::connect(target)).await??;
        let name = ServerName::IpAddress(
            IpAddr::V4(match target.ip() {
                IpAddr::V4(ip) => ip,
                _ => return Err(anyhow!("IPv6 unsupported")),
            })
            .into(),
        );
        let started = Instant::now();
        let mut stream = timeout(ctx.tls_timeout, self.tls.connect(name, tcp)).await??;
        let tls_meta = tls_metadata(stream.get_ref().1, target.ip());
        let alpn_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        if alpn_h2 {
            let mut s = ServiceResult::unknown_tcp(target.port(), known);
            s.protocol = "https".into();
            s.tls = Some(tls_meta);
            s.response_latency_ms = Some(started.elapsed().as_millis() as u64);
            s.fingerprint_latency_ms = Some(0);
            s.is_unknown_web = true;
            s.known_product = None;
            s.classification = Some("unknown_web".into());
            return Ok(s);
        }
        let response = request_http(
            &mut stream,
            target.ip(),
            ctx.max_body,
            ctx.http_timeout,
            "/",
        )
        .await?;
        let favicon_hash = self.fetch_tls_favicon(target, ctx).await;
        let mut service = self.to_service(
            target.port(),
            known,
            "https",
            response,
            Some(tls_meta),
            started.elapsed(),
        );
        service.favicon_hash = favicon_hash;
        Ok(service)
    }

    async fn probe_plain(
        &self,
        target: SocketAddr,
        known: bool,
        ctx: &ProbeContext,
    ) -> Result<ServiceResult> {
        let mut stream = timeout(ctx.http_timeout, TcpStream::connect(target)).await??;
        let started = Instant::now();
        let response = request_http(
            &mut stream,
            target.ip(),
            ctx.max_body,
            ctx.http_timeout,
            "/",
        )
        .await?;
        let favicon_hash = self.fetch_plain_favicon(target, ctx).await;
        let mut service = self.to_service(
            target.port(),
            known,
            "http",
            response,
            None,
            started.elapsed(),
        );
        service.favicon_hash = favicon_hash;
        Ok(service)
    }

    async fn fetch_plain_favicon(&self, target: SocketAddr, ctx: &ProbeContext) -> Option<String> {
        let mut stream = timeout(ctx.http_timeout, TcpStream::connect(target))
            .await
            .ok()?
            .ok()?;
        let response = request_http(
            &mut stream,
            target.ip(),
            ctx.max_body.min(65_536),
            ctx.http_timeout,
            "/favicon.ico",
        )
        .await
        .ok()?;
        (response.status < 400 && !response.body.is_empty()).then(|| sha256_hex(response.body))
    }

    async fn fetch_tls_favicon(&self, target: SocketAddr, ctx: &ProbeContext) -> Option<String> {
        let tcp = timeout(ctx.tls_timeout, TcpStream::connect(target))
            .await
            .ok()?
            .ok()?;
        let name = ServerName::IpAddress(target.ip().into());
        let mut stream = timeout(ctx.tls_timeout, self.tls.connect(name, tcp))
            .await
            .ok()?
            .ok()?;
        if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
            return None;
        }
        let response = request_http(
            &mut stream,
            target.ip(),
            ctx.max_body.min(65_536),
            ctx.http_timeout,
            "/favicon.ico",
        )
        .await
        .ok()?;
        (response.status < 400 && !response.body.is_empty()).then(|| sha256_hex(response.body))
    }

    fn to_service(
        &self,
        port: u16,
        known: bool,
        protocol: &str,
        r: ParsedResponse,
        tls: Option<TlsMetadata>,
        latency: std::time::Duration,
    ) -> ServiceResult {
        let body_text = String::from_utf8_lossy(&r.body);
        let fingerprint_started = Instant::now();
        let title = extract_title(&body_text);
        let server = r.headers.get("server").cloned();
        let evidence = WebEvidence {
            title: title.as_deref(),
            server: server.as_deref(),
            headers: &r.headers,
            body: &body_text,
        };
        let (fingerprints, classification) = self.fingerprints.analyze(&evidence);
        let self_signed = tls.as_ref().and_then(|t| t.self_signed).unwrap_or(false);
        let expired = tls
            .as_ref()
            .and_then(|t| t.validity.as_deref())
            .is_some_and(|v| v == "expired");
        let score = suspicion_score(
            port,
            server.as_deref(),
            &classification,
            &fingerprints,
            self_signed,
            expired,
            &body_text,
        );
        let unknown = fingerprints.is_empty();
        let known_product = fingerprints
            .iter()
            .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            .map(|fingerprint| fingerprint.name.clone());
        let fingerprint_latency_ms = fingerprint_started.elapsed().as_millis() as u64;
        ServiceResult {
            port,
            transport: "tcp".into(),
            protocol: protocol.into(),
            state: "open".into(),
            known_c2_port: known,
            status: Some(r.status),
            title,
            server,
            content_type: r.headers.get("content-type").cloned(),
            content_length: r.headers.get("content-length").and_then(|v| v.parse().ok()),
            location: r.headers.get("location").cloned(),
            www_authenticate: r.headers.get("www-authenticate").cloned(),
            cookie_names: r.cookie_names,
            response_headers: r.headers,
            body_length: Some(r.body.len()),
            body_sha256: Some(sha256_hex(&r.body)),
            favicon_hash: None,
            redirect_destination: r.redirect,
            response_latency_ms: Some(latency.as_millis() as u64),
            fingerprint_latency_ms: Some(fingerprint_latency_ms),
            tls,
            fingerprints,
            known_product,
            classification: Some(if unknown && classification == "generic_web" {
                "unknown_web".into()
            } else {
                classification
            }),
            is_unknown_web: unknown,
            suspicion_score: score,
            error: None,
        }
    }
}

struct ParsedResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    cookie_names: Vec<String>,
    body: Vec<u8>,
    redirect: Option<String>,
}
async fn request_http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ip: IpAddr,
    max_body: usize,
    duration: std::time::Duration,
    path: &str,
) -> Result<ParsedResponse> {
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: surface-scan/0.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    timeout(duration, stream.write_all(req.as_bytes())).await??;
    let mut data = Vec::with_capacity(8192);
    let max_total = max_body.saturating_add(64 * 1024);
    let mut buf = [0u8; 8192];
    loop {
        match timeout(duration, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let take = n.min(max_total.saturating_sub(data.len()));
                data.extend_from_slice(&buf[..take]);
                if data.len() >= max_total {
                    break;
                }
            }
            Ok(Err(e)) if !data.is_empty() => {
                tracing::debug!(error=%e, "response stream ended after partial data");
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        }
    }
    parse_http(&data, max_body)
}

fn parse_http(data: &[u8], max_body: usize) -> Result<ParsedResponse> {
    let (split, body_offset) = if let Some(split) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        (split, split + 4)
    } else if let Some(split) = data.windows(2).position(|w| w == b"\n\n") {
        (split, split + 2)
    } else {
        return Err(anyhow!("not an HTTP response"));
    };
    let head = std::str::from_utf8(&data[..split]).context("non-UTF8 HTTP headers")?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .map(str::trim)
        .ok_or_else(|| anyhow!("missing status line"))?;
    if !(status_line.starts_with("HTTP/1.0 ") || status_line.starts_with("HTTP/1.1 ")) {
        return Err(anyhow!("not HTTP"));
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("missing status"))?
        .parse()?;
    let mut headers = BTreeMap::new();
    let mut cookies = vec![];
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "set-cookie" {
                if let Some(name) = val.split('=').next() {
                    let name = name.trim();
                    if !name.is_empty() {
                        cookies.push(name.to_string());
                    }
                }
                continue;
            }
            headers
                .entry(key)
                .and_modify(|old: &mut String| {
                    old.push_str(", ");
                    old.push_str(&val)
                })
                .or_insert(val);
        }
    }
    let body = data.get(body_offset..).unwrap_or_default();
    let body = body[..body.len().min(max_body)].to_vec();
    let redirect = headers.get("location").cloned();
    Ok(ParsedResponse {
        status,
        headers,
        cookie_names: cookies,
        body,
        redirect,
    })
}
fn extract_title(body: &str) -> Option<String> {
    let doc = Html::parse_document(body);
    let selector = Selector::parse("title").ok()?;
    doc.select(&selector)
        .next()
        .map(|n| {
            n.text()
                .collect::<String>()
                .trim()
                .chars()
                .take(512)
                .collect()
        })
        .filter(|s: &String| !s.is_empty())
}
fn short_error(e: &anyhow::Error) -> String {
    let s = e.to_string();
    s.chars().take(200).collect()
}

fn tls_metadata(conn: &rustls::ClientConnection, target_ip: IpAddr) -> TlsMetadata {
    let mut out = TlsMetadata {
        version: conn.protocol_version().map(|v| format!("{v:?}")),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|v| format!("{:?}", v.suite())),
        alpn: conn
            .alpn_protocol()
            .map(|v| String::from_utf8_lossy(v).into_owned()),
        ..Default::default()
    };
    if let Some(cert) = conn.peer_certificates().and_then(|c| c.first()) {
        out.certificate_sha256 = Some(sha256_hex(cert.as_ref()));
        if let Ok((_, x)) = parse_x509_certificate(cert.as_ref()) {
            out.subject = Some(x.subject().to_string());
            out.issuer = Some(x.issuer().to_string());
            out.serial = Some(x.raw_serial_as_string());
            out.not_before = Some(x.validity().not_before.to_string());
            out.not_after = Some(x.validity().not_after.to_string());
            out.self_signed = Some(x.subject() == x.issuer());
            out.validity = Some(
                if x.validity().is_valid() {
                    "valid"
                } else if x.validity().not_after.timestamp()
                    < time::OffsetDateTime::now_utc().unix_timestamp()
                {
                    "expired"
                } else {
                    "not_yet_valid"
                }
                .into(),
            );
            if let Ok(Some(san)) = x.subject_alternative_name() {
                for name in &san.value.general_names {
                    match name {
                        GeneralName::DNSName(v) => out.san.push((*v).into()),
                        GeneralName::IPAddress(v) if v.len() == 4 => out
                            .san
                            .push(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string()),
                        _ => {}
                    }
                }
                out.hostname_match =
                    Some(out.san.iter().any(|name| name == &target_ip.to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_http_and_cookie_names_only() {
        let r = parse_http(
            b"HTTP/1.1 200 OK\r\nServer: test\r\nSet-Cookie: sid=secret; Secure\r\n\r\nhello",
            100,
        )
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.cookie_names, vec!["sid"]);
        assert!(!r.headers.contains_key("set-cookie"));
        assert_eq!(r.body, b"hello");
    }
    #[test]
    fn accepts_clearly_http_lf_only_response() {
        let response = parse_http(b"HTTP/1.0 200 OK\nServer: fixture\n\nbody", 100).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"body");
    }
    #[test]
    fn rejects_non_http() {
        assert!(parse_http(b"SSH-2.0-test\r\n", 100).is_err());
    }
}
