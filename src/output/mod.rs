use crate::model::{HostResult, Metrics, ServiceResult};
use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Seek, Write},
    path::Path,
};

pub struct OutputWriters {
    jsonl: BufWriter<File>,
    flat: Option<BufWriter<File>>,
    csv: Option<csv::Writer<File>>,
    nmap: Option<BufWriter<File>>,
    urls: Option<BufWriter<File>>,
}
impl OutputWriters {
    pub fn open(
        jsonl: &Path,
        flat: Option<&Path>,
        csv_path: Option<&Path>,
        nmap: Option<&Path>,
        urls: Option<&Path>,
        append: bool,
    ) -> Result<Self> {
        fn file(path: &Path, append: bool) -> Result<File> {
            OpenOptions::new()
                .create(true)
                .write(true)
                .append(append)
                .truncate(!append)
                .open(path)
                .with_context(|| format!("open output {}", path.display()))
        }
        let csv_empty = csv_path
            .map(|p| !p.exists() || p.metadata().map(|m| m.len() == 0).unwrap_or(true))
            .unwrap_or(false);
        let csv = csv_path
            .map(|p| {
                file(p, append).map(|f| {
                    csv::WriterBuilder::new()
                        .has_headers(csv_empty)
                        .from_writer(f)
                })
            })
            .transpose()?;
        Ok(Self {
            jsonl: BufWriter::new(file(jsonl, append)?),
            flat: flat
                .map(|p| file(p, append).map(BufWriter::new))
                .transpose()?,
            csv,
            nmap: nmap
                .map(|p| file(p, append).map(BufWriter::new))
                .transpose()?,
            urls: urls
                .map(|p| file(p, append).map(BufWriter::new))
                .transpose()?,
        })
    }
    pub fn write_host(&mut self, host: &HostResult) -> Result<()> {
        serde_json::to_writer(&mut self.jsonl, host)?;
        writeln!(self.jsonl)?;
        for service in &host.services {
            self.write_service(host, service)?
        }
        Ok(())
    }
    fn write_service(&mut self, host: &HostResult, s: &ServiceResult) -> Result<()> {
        if let Some(w) = &mut self.flat {
            serde_json::to_writer(
                &mut *w,
                &serde_json::json!({"schema_version":"1","ip":host.ip,"service":s}),
            )?;
            writeln!(w)?;
        }
        if let Some(w) = &mut self.csv {
            w.serialize(CsvRow::new(host, s))?;
        }
        if matches!(s.protocol.as_str(), "http" | "https") {
            if let Some(w) = &mut self.nmap {
                writeln!(w, "{}:{}", host.ip, s.port)?
            }
            if let Some(w) = &mut self.urls {
                writeln!(w, "{}://{}:{}/", s.protocol, host.ip, s.port)?
            }
        }
        Ok(())
    }
    pub fn flush(&mut self) -> Result<u64> {
        self.jsonl.flush()?;
        if let Some(w) = &mut self.flat {
            w.flush()?
        }
        if let Some(w) = &mut self.csv {
            w.flush()?
        }
        if let Some(w) = &mut self.nmap {
            w.flush()?
        }
        if let Some(w) = &mut self.urls {
            w.flush()?
        }
        Ok(self.jsonl.stream_position()?)
    }
}

#[derive(serde::Serialize)]
struct CsvRow {
    ip: String,
    port: u16,
    protocol: String,
    status: Option<u16>,
    title: Option<String>,
    server: Option<String>,
    classification: Option<String>,
    fingerprints: String,
    tls_subject: Option<String>,
    tls_issuer: Option<String>,
    body_sha256: Option<String>,
    favicon_hash: Option<String>,
    suspicion_score: u32,
    known_c2_port: bool,
}
impl CsvRow {
    fn new(h: &HostResult, s: &ServiceResult) -> Self {
        Self {
            ip: h.ip.to_string(),
            port: s.port,
            protocol: s.protocol.clone(),
            status: s.status,
            title: s.title.clone(),
            server: s.server.clone(),
            classification: s.classification.clone(),
            fingerprints: s
                .fingerprints
                .iter()
                .map(|f| format!("{}:{:.2}", f.name, f.confidence))
                .collect::<Vec<_>>()
                .join(";"),
            tls_subject: s.tls.as_ref().and_then(|t| t.subject.clone()),
            tls_issuer: s.tls.as_ref().and_then(|t| t.issuer.clone()),
            body_sha256: s.body_sha256.clone(),
            favicon_hash: s.favicon_hash.clone(),
            suspicion_score: s.suspicion_score,
            known_c2_port: s.known_c2_port,
        }
    }
}

pub fn write_metrics(path: &Path, metrics: &Metrics) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(metrics)?)
        .with_context(|| format!("write metrics {}", path.display()))
}
