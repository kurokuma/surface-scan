use crate::model::FingerprintMatch;
use regex::Regex;
use std::collections::BTreeMap;

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

struct RuleFingerprint {
    name: &'static str,
    server: Option<Regex>,
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
        if evidence.is_empty() || (self.name == "hfs" && evidence.len() < 2) {
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
}
impl Default for FingerprintEngine {
    fn default() -> Self {
        fn regex(v: &str) -> Option<Regex> {
            Some(Regex::new(v).expect("static regex"))
        }
        let rules: Vec<Box<dyn Fingerprint>> = vec![
            Box::new(RuleFingerprint {
                name: "hfs",
                server: regex("(?i)\\bhfs(?: |/|$)"),
                body: regex("(?i)(httpfileserver|rejetto|hfs [0-9])"),
                title: regex("(?i)\\bhfs\\b"),
            }),
            Box::new(RuleFingerprint {
                name: "apache",
                server: regex("(?i)^apache(?:/|$)"),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "nginx",
                server: regex("(?i)^nginx(?:/|$)"),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "iis",
                server: regex("(?i)microsoft-iis"),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "python-simplehttpserver",
                server: regex("(?i)(simplehttp|python)/"),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "tomcat",
                server: regex("(?i)(apache-coyote|tomcat)"),
                body: regex("(?i)apache tomcat"),
                title: regex("(?i)tomcat"),
            }),
            Box::new(RuleFingerprint {
                name: "jetty",
                server: regex("(?i)jetty"),
                body: None,
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "nodejs",
                server: regex("(?i)(express|node)"),
                body: regex("(?i)x-powered-by.{0,20}express"),
                title: None,
            }),
            Box::new(RuleFingerprint {
                name: "go-http",
                server: regex("(?i)(go-http-server|fasthttp)"),
                body: None,
                title: None,
            }),
        ];
        Self { rules }
    }
}

impl FingerprintEngine {
    pub fn analyze(&self, e: &WebEvidence<'_>) -> (Vec<FingerprintMatch>, String) {
        let matches: Vec<_> = self
            .rules
            .iter()
            .filter_map(|r| r.match_surface(e))
            .collect();
        let lower = format!("{} {}", e.title.unwrap_or_default(), e.body).to_ascii_lowercase();
        let listing = lower.contains("index of /")
            || lower.contains("directory listing for")
            || (lower.contains("parent directory") && lower.contains("href="));
        let login = (lower.contains("type=\"password\"") || lower.contains("type='password'"))
            && lower.contains("form");
        let admin = lower.contains("admin panel")
            || lower.contains("administration")
            || lower.contains("dashboard");
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
}

pub fn suspicion_score(
    port: u16,
    server: Option<&str>,
    classification: &str,
    fingerprints: &[FingerprintMatch],
    tls_self_signed: bool,
    tls_expired: bool,
    body: &str,
) -> u32 {
    let mut score = 0;
    if port >= 10_000 {
        score += 2;
    }
    if server.is_none() {
        score += 1;
    }
    if classification == "directory_listing" {
        score += 3;
    }
    if classification == "login_panel" {
        score += 2;
    }
    if classification == "admin_panel" {
        score += 2;
    }
    if fingerprints.iter().any(|f| f.name == "hfs") {
        score += 3;
    }
    if tls_self_signed {
        score += 1;
    }
    if tls_expired {
        score += 1;
    }
    let b = body.to_ascii_lowercase();
    if [".exe", ".dll", ".zip", ".rar", ".7z"]
        .iter()
        .any(|x| b.contains(x))
    {
        score += 2;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_correlated_hfs_evidence_for_high_confidence() {
        let headers = BTreeMap::new();
        let e = WebEvidence {
            title: Some("HFS"),
            server: Some("HFS 2.3m"),
            headers: &headers,
            body: "HttpFileServer by rejetto",
        };
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
                .analyze(&WebEvidence {
                    title: None,
                    server: None,
                    headers: &h,
                    body: "<form><input type=\"password\"></form>"
                })
                .1,
            "login_panel"
        );
        assert_eq!(
            engine
                .analyze(&WebEvidence {
                    title: None,
                    server: None,
                    headers: &h,
                    body: "<title>Index of /</title>"
                })
                .1,
            "directory_listing"
        );
    }
}
