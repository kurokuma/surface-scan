use crate::{
    config::{FingerprintToggles, SuspicionWeights},
    model::{FingerprintMatch, ServiceResult},
};
use regex::Regex;
use std::{collections::BTreeMap, time::Instant};

#[derive(Debug)]
pub struct WebEvidence<'a> {
    pub title: Option<&'a str>,
    pub server: Option<&'a str>,
    pub headers: &'a BTreeMap<String, String>,
    pub body: &'a str,
}

pub trait Fingerprint: Send + Sync {
    fn name(&self) -> &'static str;
    fn match_surface(&self, response: &WebEvidence<'_>) -> Option<FingerprintMatch>;
}

/// Server headers common enough that their presence is not itself a triage
/// signal. Anything outside this set counts as an uncommon banner.
const COMMON_SERVERS: &[&str] = &[
    "apache",
    "nginx",
    "microsoft-iis",
    "litespeed",
    "openresty",
    "cloudflare",
    "caddy",
    "envoy",
    "gunicorn",
    "jetty",
    "apache-coyote",
    "tomcat",
    "iis",
];

struct RuleFingerprint {
    name: &'static str,
    server: Option<Regex>,
    /// Header name plus a pattern for its value, e.g. `x-powered-by` / `express`.
    header: Option<(&'static str, Regex)>,
    body: Option<Regex>,
    title: Option<Regex>,
}
impl Fingerprint for RuleFingerprint {
    fn name(&self) -> &'static str {
        self.name
    }
    fn match_surface(&self, response: &WebEvidence<'_>) -> Option<FingerprintMatch> {
        let mut evidence = vec![];
        if self
            .server
            .as_ref()
            .is_some_and(|r| response.server.is_some_and(|v| r.is_match(v)))
        {
            evidence.push(format!("server:{}", response.server.unwrap_or_default()));
        }
        if let Some((name, pattern)) = &self.header
            && let Some(value) = response.headers.get(*name)
            && pattern.is_match(value)
        {
            evidence.push(format!("header:{name}:{value}"));
        }
        if self
            .title
            .as_ref()
            .is_some_and(|r| response.title.is_some_and(|v| r.is_match(v)))
        {
            evidence.push(format!("title:{}", response.title.unwrap_or_default()));
        }
        if self
            .body
            .as_ref()
            .is_some_and(|r| r.is_match(response.body))
        {
            evidence.push(format!("body-pattern:{}", self.name));
        }
        // A single weak signal never asserts HFS: spec section 17.1 requires
        // correlated evidence before the finding carries weight.
        let weak_go_header_only = self.name == "go-http"
            && evidence.len() < 2
            && !evidence.iter().any(|item| item.starts_with("server:"));
        if evidence.is_empty() || (self.name == "hfs" && evidence.len() < 2) || weak_go_header_only
        {
            None
        } else {
            let confidence = match self.name {
                "hfs" if evidence.len() >= 2 => 0.96,
                "hfs" => 0.72,
                _ if evidence.len() >= 2 => 0.92,
                _ => 0.78,
            };
            Some(FingerprintMatch {
                name: self.name.into(),
                confidence,
                evidence,
            })
        }
    }
}

pub struct FingerprintEngine {
    rules: Vec<Box<dyn Fingerprint>>,
    toggles: FingerprintToggles,
}
impl Default for FingerprintEngine {
    fn default() -> Self {
        Self::new(&FingerprintToggles::default())
    }
}

impl FingerprintEngine {
    pub fn new(toggles: &FingerprintToggles) -> Self {
        fn regex(v: &str) -> Option<Regex> {
            Some(Regex::new(v).expect("static regex"))
        }
        let all: Vec<Box<dyn Fingerprint>> = vec![
            Box::new(RuleFingerprint {
                name: "hfs",
                server: regex("(?i)\\bhfs(?: |/|$)"),
                header: None,
                body: regex("(?i)(httpfileserver|rejetto|hfs [0-9])"),
                title: regex("(?i)\\bhfs\\b"),
            }),
            Box::new(RuleFingerprint {
                name: "apache",
                server: regex("(?i)^apache(?:/|$)"),
                header: None,
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "nginx",
                server: regex("(?i)^nginx(?:/|$)"),
                header: None,
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "iis",
                server: regex("(?i)microsoft-iis"),
                header: Some(("x-aspnet-version", Regex::new(".").expect("static regex"))),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "python-simplehttpserver",
                server: regex("(?i)(simplehttp|python)/"),
                header: None,
                body: regex("(?i)directory listing for /"),
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "tomcat",
                server: regex("(?i)(apache-coyote|tomcat)"),
                header: None,
                body: regex("(?i)apache tomcat"),
                title: regex("(?i)tomcat"),
            }),
            Box::new(RuleFingerprint {
                name: "jetty",
                server: regex("(?i)jetty"),
                header: None,
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "nodejs",
                server: regex("(?i)(express|node)"),
                // Express advertises itself in a header, not in the body.
                header: Some((
                    "x-powered-by",
                    Regex::new("(?i)(express|next\\.js|nest)").expect("static regex"),
                )),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "go-http",
                server: regex("(?i)(go-http-server|fasthttp|gin|echo)"),
                // Go's net/http sends no Server banner, so the date-only header
                // shape plus Go-specific error text is the usable signal.
                header: Some((
                    "x-content-type-options",
                    Regex::new("(?i)nosniff").expect("static regex"),
                )),
                body: regex(
                    "(?i)(http: named cookie not present|go net/http|^404 page not found\\s*$)",
                ),
                title: None,
            }),
        ];
        let rules = all
            .into_iter()
            .filter(|rule| toggles.rule_enabled(rule.name()))
            .collect();
        Self {
            rules,
            toggles: toggles.clone(),
        }
    }

    pub fn analyze(&self, e: &WebEvidence<'_>) -> (Vec<FingerprintMatch>, String) {
        let matches: Vec<_> = self
            .rules
            .iter()
            .filter_map(|r| r.match_surface(e))
            .collect();
        let lower = format!("{} {}", e.title.unwrap_or_default(), e.body).to_ascii_lowercase();
        let listing = self.toggles.directory_listing
            && (lower.contains("index of /")
                || lower.contains("directory listing for")
                || (lower.contains("parent directory") && lower.contains("href=")));
        let login = self.toggles.login_panel
            && lower.contains("form")
            && (lower.contains("type=\"password\"")
                || lower.contains("type='password'")
                || lower.contains("type=password"));
        let admin = self.toggles.admin_panel
            && (lower.contains("admin panel")
                || lower.contains("administration")
                || lower.contains("dashboard")
                || lower.contains("control panel"));
        let api = e
            .headers
            .get("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().contains("application/json"));
        let hfs = matches
            .iter()
            .any(|m| m.name == "hfs" && m.confidence >= 0.9);
        let classification = if hfs {
            "file_server"
        } else if listing {
            "directory_listing"
        } else if login {
            "login_panel"
        } else if admin {
            "admin_panel"
        } else if api {
            "api"
        } else {
            "generic_web"
        };
        (matches, classification.into())
    }

    /// Stage-3 enrichment. Protocol detection leaves the bounded body sample
    /// only in memory; this method consumes it, applies fingerprints and the
    /// triage score, then clears it before the service reaches output.
    pub fn enrich(&self, service: &mut ServiceResult, weights: &SuspicionWeights) {
        let started = Instant::now();
        let body = service.fingerprint_body.take().unwrap_or_default();
        if service.is_web() {
            let evidence = WebEvidence {
                title: service.title.as_deref(),
                server: service.server.as_deref(),
                headers: &service.response_headers,
                body: &body,
            };
            let (matches, classification) = self.analyze(&evidence);
            let unknown = matches.is_empty();
            service.known_product = matches
                .iter()
                .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
                .map(|fingerprint| fingerprint.name.clone());
            service.fingerprints = matches;
            service.classification = Some(if unknown && classification == "generic_web" {
                "unknown_web".into()
            } else {
                classification
            });
            service.is_unknown_web = unknown;
        }

        if service.is_web() || service.protocol == "tls" {
            let classification = service.classification.as_deref().unwrap_or("unknown_tls");
            let (score, reasons) = suspicion_score(
                &SuspicionInput {
                    is_web: service.is_web(),
                    port: service.port,
                    server: service.server.as_deref(),
                    classification,
                    fingerprints: &service.fingerprints,
                    tls_self_signed: service
                        .tls
                        .as_ref()
                        .and_then(|tls| tls.self_signed)
                        .unwrap_or(false),
                    tls_expired: service.tls.as_ref().and_then(|tls| tls.validity.as_deref())
                        == Some("expired"),
                    body: &body,
                    favicon_known: service.favicon_hash.is_some(),
                },
                weights,
            );
            service.suspicion_score = score;
            service.suspicion_reasons = reasons;
        }
        service.fingerprint_latency_ms = Some(started.elapsed().as_millis() as u64);
    }
}

/// Inputs to the triage score, kept as a struct so callers cannot transpose the
/// boolean arguments by accident.
pub struct SuspicionInput<'a> {
    /// True only when an HTTP response body/favicon could actually be observed.
    pub is_web: bool,
    pub port: u16,
    pub server: Option<&'a str>,
    pub classification: &'a str,
    pub fingerprints: &'a [FingerprintMatch],
    pub tls_self_signed: bool,
    pub tls_expired: bool,
    pub body: &'a str,
    pub favicon_known: bool,
}

/// Triage-only priority score (spec section 20). A high port alone is never
/// treated as malicious; it only raises the review order.
pub fn suspicion_score(input: &SuspicionInput<'_>, w: &SuspicionWeights) -> (u32, Vec<String>) {
    let mut score = 0;
    let mut reasons = vec![];
    let mut add = |points: u32, reason: &str, reasons: &mut Vec<String>| {
        if points > 0 {
            score += points;
            reasons.push(format!("+{points} {reason}"));
        }
    };
    if input.port >= w.high_port_threshold {
        add(
            w.high_port,
            &format!("port >= {}", w.high_port_threshold),
            &mut reasons,
        );
    }
    if input.is_web {
        match input.server {
            None => add(w.absent_server, "server header absent", &mut reasons),
            Some(server) => {
                let lower = server.to_ascii_lowercase();
                if !COMMON_SERVERS.iter().any(|known| lower.contains(known)) {
                    add(w.uncommon_server, "uncommon server header", &mut reasons);
                }
            }
        }
    }
    match input.classification {
        "directory_listing" => add(w.directory_listing, "directory listing", &mut reasons),
        "login_panel" => add(w.login_panel, "login form", &mut reasons),
        "admin_panel" => add(w.admin_panel, "admin keywords", &mut reasons),
        _ => {}
    }
    if input.fingerprints.iter().any(|f| f.name == "hfs") {
        add(w.hfs, "hfs", &mut reasons);
    }
    if input.tls_self_signed {
        add(
            w.self_signed_certificate,
            "self-signed certificate",
            &mut reasons,
        );
    }
    if input.tls_expired {
        add(w.expired_certificate, "expired certificate", &mut reasons);
    }
    let body = input.body.to_ascii_lowercase();
    if [
        ".exe", ".dll", ".zip", ".rar", ".7z", ".msi", ".ps1", ".bat",
    ]
    .iter()
    .any(|extension| body.contains(extension))
    {
        add(
            w.downloadable_artifacts,
            "executable/archive files referenced",
            &mut reasons,
        );
    }
    if input.is_web && input.fingerprints.is_empty() && !input.favicon_known {
        add(
            w.unknown_fingerprint,
            "unknown favicon/body fingerprint",
            &mut reasons,
        );
    }
    (score, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence<'a>(
        title: Option<&'a str>,
        server: Option<&'a str>,
        headers: &'a BTreeMap<String, String>,
        body: &'a str,
    ) -> WebEvidence<'a> {
        WebEvidence {
            title,
            server,
            headers,
            body,
        }
    }

    #[test]
    fn requires_correlated_hfs_evidence_for_high_confidence() {
        let headers = BTreeMap::new();
        let e = evidence(
            Some("HFS"),
            Some("HFS 2.3m"),
            &headers,
            "HttpFileServer by rejetto",
        );
        let (m, c) = FingerprintEngine::default().analyze(&e);
        assert_eq!(c, "file_server");
        assert!(m.iter().any(|x| x.name == "hfs" && x.confidence > 0.9));
    }

    #[test]
    fn detects_login_and_listing() {
        let h = BTreeMap::new();
        let engine = FingerprintEngine::default();
        assert_eq!(
            engine
                .analyze(&evidence(
                    None,
                    None,
                    &h,
                    "<form><input type=\"password\"></form>"
                ))
                .1,
            "login_panel"
        );
        assert_eq!(
            engine
                .analyze(&evidence(
                    None,
                    None,
                    &h,
                    "<form><input type=password></form>"
                ))
                .1,
            "login_panel"
        );
        assert_eq!(
            engine
                .analyze(&evidence(None, None, &h, "<title>Index of /</title>"))
                .1,
            "directory_listing"
        );
    }

    #[test]
    fn express_is_detected_from_its_header_not_the_body() {
        let mut headers = BTreeMap::new();
        headers.insert("x-powered-by".into(), "Express".into());
        let (matches, _) =
            FingerprintEngine::default().analyze(&evidence(None, None, &headers, "<html></html>"));
        assert!(
            matches.iter().any(|m| m.name == "nodejs"),
            "express header should fingerprint node: {matches:?}"
        );
    }

    #[test]
    fn nosniff_alone_does_not_claim_a_go_server() {
        let mut headers = BTreeMap::new();
        headers.insert("x-content-type-options".into(), "nosniff".into());
        let (matches, _) = FingerprintEngine::default().analyze(&evidence(
            None,
            None,
            &headers,
            "<html>generic hardened server</html>",
        ));
        assert!(!matches.iter().any(|item| item.name == "go-http"));
    }

    #[test]
    fn disabled_rules_do_not_fire() {
        let toggles = FingerprintToggles {
            hfs: false,
            ..Default::default()
        };
        let headers = BTreeMap::new();
        let (matches, classification) = FingerprintEngine::new(&toggles).analyze(&evidence(
            Some("HFS"),
            Some("HFS 2.3m"),
            &headers,
            "HttpFileServer by rejetto",
        ));
        assert!(!matches.iter().any(|m| m.name == "hfs"));
        assert_ne!(classification, "file_server");
    }

    #[test]
    fn score_covers_every_documented_signal() {
        let weights = SuspicionWeights::default();
        let (score, reasons) = suspicion_score(
            &SuspicionInput {
                is_web: true,
                port: 27331,
                server: Some("HFS 2.3m"),
                classification: "directory_listing",
                fingerprints: &[FingerprintMatch {
                    name: "hfs".into(),
                    confidence: 0.96,
                    evidence: vec![],
                }],
                tls_self_signed: true,
                tls_expired: true,
                body: "payload.exe",
                favicon_known: false,
            },
            &weights,
        );
        // high port 2 + uncommon server 2 + listing 3 + hfs 3 + self-signed 1
        // + expired 1 + artifacts 2 = 14. Fingerprints exist, so no unknown bonus.
        assert_eq!(score, 14, "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("uncommon server header")));
    }

    #[test]
    fn unknown_surface_earns_the_unknown_fingerprint_bonus() {
        let (score, reasons) = suspicion_score(
            &SuspicionInput {
                is_web: true,
                port: 443,
                server: Some("nginx/1.24.0"),
                classification: "generic_web",
                fingerprints: &[],
                tls_self_signed: false,
                tls_expired: false,
                body: "",
                favicon_known: false,
            },
            &SuspicionWeights::default(),
        );
        assert_eq!(score, 2, "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("unknown favicon")));
    }

    #[test]
    fn tls_only_service_does_not_receive_a_web_fingerprint_bonus() {
        let (score, reasons) = suspicion_score(
            &SuspicionInput {
                is_web: false,
                port: 3389,
                server: None,
                classification: "unknown_tls",
                fingerprints: &[],
                tls_self_signed: true,
                tls_expired: false,
                body: "",
                favicon_known: false,
            },
            &SuspicionWeights::default(),
        );
        assert_eq!(score, 1, "{reasons:?}");
        assert!(!reasons.iter().any(|r| r.contains("server header")));
        assert!(!reasons.iter().any(|r| r.contains("unknown favicon")));
    }
}
