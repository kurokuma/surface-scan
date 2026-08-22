use crate::{
    config::{Settings, SuspicionWeights},
    model::{ServiceResult, TlsMetadata},
    util::{favicon_mmh3, sha256_hex},
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
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

#[derive(Debug, Clone)]
pub struct ProbeContext {
    /// Inactivity timeout for a single socket read or write.
    pub http_timeout: Duration,
    /// Hard deadline for a complete HTTP response, whatever the peer does.
    pub http_body_timeout: Duration,
    pub tls_timeout: Duration,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub max_body: usize,
    pub suspicion: SuspicionWeights,
}
impl ProbeContext {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            http_timeout: settings.http_timeout,
            http_body_timeout: settings.http_body_timeout,
            tls_timeout: settings.tls_timeout,
            http_enabled: settings.http_enabled,
            https_enabled: settings.https_enabled,
            max_body: settings.max_body,
            suspicion: settings.suspicion.clone(),
        }
    }
    /// Worst-case wall time one port may consume, used as an outer guard so a
    /// single hostile peer can never stall the pipeline.
    pub fn probe_budget(&self) -> Duration {
        let single = self.tls_timeout + self.http_timeout + self.http_body_timeout;
        // TLS attempt, plain fallback, and the favicon fetch, plus slack.
        single * 3 + Duration::from_secs(2)
    }
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

/// Accepts every chain so that scanning never stops on an invalid certificate
/// (spec section 16). The observed state is reported through `TlsMetadata`
/// (`self_signed`, `validity`, `hostname_match`) instead of being enforced.
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
    tls: TlsConnector,
}
impl Default for WebProbe {
    fn default() -> Self {
        Self::new()
    }
}
impl WebProbe {
    pub fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        Self {
            tls: TlsConnector::from(Arc::new(config)),
        }
    }
}

/// What a TLS attempt established, so the caller knows whether a plain-HTTP
/// fallback is still worth trying.
enum TlsOutcome {
    /// TLS plus a parsable HTTP response.
    Web(Box<ServiceResult>),
    /// TLS handshake succeeded but the peer is not an HTTP server. Certificate
    /// metadata is the whole point of the record, so it is kept.
    TlsOnly(Box<ServiceResult>),
    /// No TLS here; try plain HTTP.
    NoTls(anyhow::Error),
}

#[async_trait]
impl ProtocolProbe for WebProbe {
    fn name(&self) -> &'static str {
        "web"
    }
    async fn probe(&self, target: SocketAddr, known: bool, ctx: &ProbeContext) -> ServiceResult {
        let tls_error = if ctx.https_enabled {
            match self.probe_tls(target, known, ctx).await {
                TlsOutcome::Web(service) | TlsOutcome::TlsOnly(service) => return *service,
                TlsOutcome::NoTls(error) => Some(error),
            }
        } else {
            None
        };
        if ctx.http_enabled {
            match self.probe_plain(target, known, ctx).await {
                Ok(service) => service,
                Err(plain_error) => {
                    let mut service = ServiceResult::unknown_tcp(target.port(), known);
                    service.error = Some(match tls_error {
                        Some(tls_error) => format!(
                            "tls: {}; http: {}",
                            short_error(&tls_error),
                            short_error(&plain_error)
                        ),
                        None => format!("http: {}", short_error(&plain_error)),
                    });
                    service
                }
            }
        } else {
            let mut service = ServiceResult::unknown_tcp(target.port(), known);
            service.error = Some(
                tls_error
                    .map(|error| format!("tls: {}", short_error(&error)))
                    .unwrap_or_else(|| "all web protocols disabled".into()),
            );
            service
        }
    }
}

impl WebProbe {
    async fn probe_tls(&self, target: SocketAddr, known: bool, ctx: &ProbeContext) -> TlsOutcome {
        let started = Instant::now();
        let stream = match self.tls_connect(target, ctx).await {
            Ok(stream) => stream,
            Err(error) => return TlsOutcome::NoTls(error),
        };
        let mut stream = stream;
        let tls_meta = tls_metadata(stream.get_ref().1, target.ip());
        let alpn_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        if alpn_h2 {
            // HTTP/2-only endpoint: recognised as a web surface (spec 14.2), but
            // this version reads no h2 frames, so only TLS metadata is recorded.
            let mut s = ServiceResult::unknown_tcp(target.port(), known);
            s.protocol = "https".into();
            s.response_latency_ms = Some(started.elapsed().as_millis() as u64);
            s.fingerprint_latency_ms = Some(0);
            s.is_unknown_web = true;
            s.classification = Some("unknown_web".into());
            s.tls = Some(tls_meta);
            s.error = Some("http/2-only endpoint; frames not parsed".into());
            return TlsOutcome::Web(Box::new(s));
        }
        match request_http(&mut stream, target.ip(), ctx, "/").await {
            Ok(response) => {
                // Measured before the favicon fetch: latency describes the
                // observed service, not our extra bookkeeping request.
                let latency_ms = started.elapsed().as_millis() as u64;
                let favicon = self.fetch_favicon(target, ctx, true).await;
                let mut service = self.to_service(
                    target.port(),
                    known,
                    "https",
                    response,
                    Some(tls_meta),
                    favicon,
                );
                service.response_latency_ms = Some(latency_ms);
                TlsOutcome::Web(Box::new(service))
            }
            Err(error) => {
                // TLS is confirmed even though HTTP is not. Certificates are the
                // highest-value pivot in this workflow, so the record is kept.
                let mut s = ServiceResult::unknown_tcp(target.port(), known);
                s.protocol = "tls".into();
                s.response_latency_ms = Some(started.elapsed().as_millis() as u64);
                s.tls = Some(tls_meta);
                s.classification = Some("unknown_tls".into());
                s.error = Some(short_error(&error));
                TlsOutcome::TlsOnly(Box::new(s))
            }
        }
    }

    async fn tls_connect(
        &self,
        target: SocketAddr,
        ctx: &ProbeContext,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = timeout(ctx.tls_timeout, TcpStream::connect(target)).await??;
        let ip = match target.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 unsupported")),
        };
        let name = ServerName::IpAddress(IpAddr::V4(ip).into());
        Ok(timeout(ctx.tls_timeout, self.tls.connect(name, tcp)).await??)
    }

    async fn probe_plain(
        &self,
        target: SocketAddr,
        known: bool,
        ctx: &ProbeContext,
    ) -> Result<ServiceResult> {
        let started = Instant::now();
        let mut stream = timeout(ctx.http_timeout, TcpStream::connect(target)).await??;
        let response = request_http(&mut stream, target.ip(), ctx, "/").await?;
        let latency_ms = started.elapsed().as_millis() as u64;
        let favicon = self.fetch_favicon(target, ctx, false).await;
        let mut service = self.to_service(target.port(), known, "http", response, None, favicon);
        service.response_latency_ms = Some(latency_ms);
        Ok(service)
    }

    /// Fetch `/favicon.ico` and hash it, but only when the peer actually
    /// returned an icon. Servers that answer every path with their index page
    /// would otherwise poison the favicon corpus with page hashes.
    async fn fetch_favicon(
        &self,
        target: SocketAddr,
        ctx: &ProbeContext,
        tls: bool,
    ) -> Option<(String, i32)> {
        let icon_ctx = ProbeContext {
            max_body: ctx.max_body.min(65_536),
            ..ctx.clone()
        };
        let response = if tls {
            let mut stream = self.tls_connect(target, &icon_ctx).await.ok()?;
            if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                return None;
            }
            request_http(&mut stream, target.ip(), &icon_ctx, "/favicon.ico")
                .await
                .ok()?
        } else {
            let mut stream = timeout(icon_ctx.http_timeout, TcpStream::connect(target))
                .await
                .ok()?
                .ok()?;
            request_http(&mut stream, target.ip(), &icon_ctx, "/favicon.ico")
                .await
                .ok()?
        };
        if response.status >= 400 || response.body.is_empty() {
            return None;
        }
        if !is_icon(&response) {
            tracing::debug!(port = target.port(), "ignoring non-icon /favicon.ico body");
            return None;
        }
        Some((sha256_hex(&response.body), favicon_mmh3(&response.body)))
    }

    fn to_service(
        &self,
        port: u16,
        known: bool,
        protocol: &str,
        r: ParsedResponse,
        tls: Option<TlsMetadata>,
        favicon: Option<(String, i32)>,
    ) -> ServiceResult {
        let body_text = String::from_utf8_lossy(&r.body);
        let title = extract_title(&body_text);
        let server = r.headers.get("server").cloned();
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
            favicon_hash: favicon.as_ref().map(|(sha256, _)| sha256.clone()),
            favicon_mmh3: favicon.as_ref().map(|(_, mmh3)| *mmh3),
            redirect_destination: r.redirect,
            response_latency_ms: Some(r.elapsed_ms),
            fingerprint_latency_ms: None,
            tls,
            fingerprints: vec![],
            known_product: None,
            classification: None,
            is_unknown_web: false,
            suspicion_score: 0,
            suspicion_reasons: vec![],
            fingerprint_body: Some(body_text.into_owned()),
            protocol_probe_latency_ms: None,
            error: None,
        }
    }
}

/// Recognise an actual icon payload by declared type or magic bytes.
fn is_icon(response: &ParsedResponse) -> bool {
    let content_type = response
        .headers
        .get("content-type")
        .map(|value| value.to_ascii_lowercase());
    if let Some(lower) = &content_type
        && (lower.contains("text/html") || lower.contains("application/json"))
    {
        return false;
    }
    let body = response.body.as_slice();
    let raster = body.starts_with(&[0x00, 0x00, 0x01, 0x00]) // ICO
        || body.starts_with(b"\x89PNG\r\n\x1a\n")             // PNG
        || body.starts_with(b"GIF87a")
        || body.starts_with(b"GIF89a")
        || body.starts_with(&[0xff, 0xd8, 0xff])                 // JPEG
        || (body.len() >= 12 && body.starts_with(b"RIFF") && &body[8..12] == b"WEBP");
    if raster {
        return true;
    }
    // SVG has no fixed binary magic. Require both its MIME type and an actual
    // SVG root near the start; trusting an arbitrary image/* label recreates
    // the false-correlation bug for deliberately mislabeled HTML.
    content_type
        .as_deref()
        .is_some_and(|value| value.contains("image/svg+xml"))
        && String::from_utf8_lossy(&body[..body.len().min(1024)])
            .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
            .contains("<svg")
}

struct ParsedResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    cookie_names: Vec<String>,
    body: Vec<u8>,
    redirect: Option<String>,
    elapsed_ms: u64,
}

/// Issue one `GET` and read the response.
///
/// Two independent limits apply: `http_timeout` bounds a single idle read, and
/// `http_body_timeout` bounds the whole exchange. Without the second bound a
/// peer that trickles one byte per read holds the probe open indefinitely.
async fn request_http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ip: IpAddr,
    ctx: &ProbeContext,
    path: &str,
) -> Result<ParsedResponse> {
    let started = Instant::now();
    let deadline = started + ctx.http_body_timeout;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: surface-scan/0.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    timeout_at(
        deadline.min(Instant::now() + ctx.http_timeout),
        stream.write_all(req.as_bytes()),
    )
    .await??;
    let mut data = Vec::with_capacity(8192);
    let max_total = ctx.max_body.saturating_add(64 * 1024);
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let until = deadline.min(Instant::now() + ctx.http_timeout);
        match timeout_at(until, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let take = n.min(max_total.saturating_sub(data.len()));
                data.extend_from_slice(&buf[..take]);
                if data.len() >= max_total {
                    truncated = true;
                    break;
                }
            }
            Ok(Err(e)) if !data.is_empty() => {
                tracing::debug!(error=%e, "response stream ended after partial data");
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Idle read or overall deadline: keep whatever arrived.
                truncated = true;
                break;
            }
        }
    }
    if truncated {
        tracing::debug!(
            bytes = data.len(),
            "response truncated by limit or deadline"
        );
    }
    let mut parsed = parse_http(&data, ctx.max_body)?;
    parsed.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(parsed)
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
            // Only cookie names are retained; values may be session secrets.
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
        elapsed_ms: 0,
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
        verification_skipped: true,
        ..Default::default()
    };
    if let Some(cert) = conn.peer_certificates().and_then(|c| c.first()) {
        out.certificate_sha256 = Some(sha256_hex(cert.as_ref()));
        if let Ok((_, x)) = parse_x509_certificate(cert.as_ref()) {
            out.subject = Some(x.subject().to_string());
            out.issuer = Some(x.issuer().to_string());
            out.serial = Some(x.raw_serial_as_string());
            out.public_key_sha256 = Some(sha256_hex(x.public_key().raw));
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
    fn body(bytes: &[u8], content_type: Option<&str>) -> ParsedResponse {
        let mut headers = BTreeMap::new();
        if let Some(value) = content_type {
            headers.insert("content-type".into(), value.into());
        }
        ParsedResponse {
            status: 200,
            headers,
            cookie_names: vec![],
            body: bytes.to_vec(),
            redirect: None,
            elapsed_ms: 0,
        }
    }

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
    #[test]
    fn html_served_at_favicon_path_is_not_an_icon() {
        assert!(!is_icon(&body(
            b"<html><body>index</body></html>",
            Some("text/html")
        )));
        assert!(!is_icon(&body(b"<html>no content type</html>", None)));
    }
    #[test]
    fn real_icons_are_accepted() {
        assert!(is_icon(&body(&[0x00, 0x00, 0x01, 0x00, 0x01], None)));
        assert!(!is_icon(&body(b"whatever", Some("image/x-icon"))));
        assert!(is_icon(&body(b"\x89PNG\r\n\x1a\n", None)));
        assert!(!is_icon(&body(
            b"<html>mislabeled</html>",
            Some("image/png")
        )));
    }
    #[test]
    fn probe_budget_is_bounded() {
        let ctx = ProbeContext {
            http_timeout: Duration::from_secs(1),
            http_body_timeout: Duration::from_millis(1500),
            tls_timeout: Duration::from_secs(1),
            http_enabled: true,
            https_enabled: true,
            max_body: 1024,
            suspicion: SuspicionWeights::default(),
        };
        assert!(ctx.probe_budget() <= Duration::from_secs(15));
    }
}
