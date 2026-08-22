use crate::model::{HostResult, MetricsDocument, ServiceResult};
use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
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
        Self::open_at(jsonl, flat, csv_path, nmap, urls, append, None)
    }

    /// Open outputs and, on resume, restore the primary JSONL to the exact
    /// checkpointed byte position. This removes a partial or uncheckpointed
    /// trailing host instead of appending duplicate/corrupt JSON.
    #[allow(clippy::too_many_arguments)]
    pub fn open_at(
        jsonl: &Path,
        flat: Option<&Path>,
        csv_path: Option<&Path>,
        nmap: Option<&Path>,
        urls: Option<&Path>,
        append: bool,
        resume_position: Option<u64>,
    ) -> Result<Self> {
        ensure_unique_paths([Some(jsonl), flat, csv_path, nmap, urls])?;
        fn file(path: &Path, append: bool) -> Result<File> {
            OpenOptions::new()
                .create(true)
                .write(true)
                .append(append)
                .truncate(!append)
                .open(path)
                .with_context(|| format!("open output {}", path.display()))
        }
        fn primary(path: &Path, append: bool, position: Option<u64>) -> Result<File> {
            let Some(position) = position.filter(|_| append) else {
                return file(path, append);
            };
            if !path.exists() && position > 0 {
                anyhow::bail!(
                    "resume output {} is missing but checkpoint position is {}",
                    path.display(),
                    position
                );
            }
            let mut output = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(path)
                .with_context(|| format!("open resume output {}", path.display()))?;
            let length = output.metadata()?.len();
            if length < position {
                anyhow::bail!(
                    "resume output {} is shorter ({}) than checkpoint position ({})",
                    path.display(),
                    length,
                    position
                );
            }
            output.set_len(position)?;
            output.seek(SeekFrom::Start(position))?;
            Ok(output)
        }
        // A fresh run truncates, so it always needs a header row. Only an append
        // onto an existing non-empty file inherits one.
        let rebuild_derived = append && resume_position.is_some();
        let derived_append = append && !rebuild_derived;
        let csv_needs_header = csv_path
            .map(|p| {
                !derived_append || !p.exists() || p.metadata().map(|m| m.len() == 0).unwrap_or(true)
            })
            .unwrap_or(false);
        let csv = csv_path
            .map(|p| -> Result<_> {
                let mut writer = csv::WriterBuilder::new()
                    .has_headers(false)
                    .from_writer(file(p, derived_append)?);
                if csv_needs_header {
                    writer.write_record(CSV_HEADER)?;
                }
                Ok(writer)
            })
            .transpose()?;
        let mut writers = Self {
            jsonl: BufWriter::new(primary(jsonl, append, resume_position)?),
            flat: flat
                .map(|p| file(p, derived_append).map(BufWriter::new))
                .transpose()?,
            csv,
            nmap: nmap
                .map(|p| file(p, derived_append).map(BufWriter::new))
                .transpose()?,
            urls: urls
                .map(|p| file(p, derived_append).map(BufWriter::new))
                .transpose()?,
        };
        if rebuild_derived {
            writers.rebuild_derived(jsonl)?;
        }
        Ok(writers)
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
            // Provenance is repeated per line: flat records are queried on their
            // own in Athena, detached from the host document.
            serde_json::to_writer(
                &mut *w,
                &serde_json::json!({
                    "schema_version": host.schema_version,
                    "meta": host.meta,
                    "ip": host.ip,
                    "host_started_at": host.started_at,
                    "host_completed_at": host.completed_at,
                    "service": s,
                }),
            )?;
            writeln!(w)?;
        }
        if let Some(w) = &mut self.csv {
            w.serialize(CsvRow::new(host, s))?;
        }
        if s.is_web() {
            if let Some(w) = &mut self.nmap {
                writeln!(w, "{}:{}", host.ip, s.port)?
            }
            if let Some(w) = &mut self.urls {
                writeln!(w, "{}://{}:{}/", s.protocol, host.ip, s.port)?
            }
        }
        Ok(())
    }

    /// Derived outputs have no independent checkpoint offsets. On resume they
    /// are therefore regenerated from the checkpoint-truncated authoritative
    /// host JSONL, which prevents duplicates after a crash between output and
    /// checkpoint commits.
    fn rebuild_derived(&mut self, jsonl: &Path) -> Result<()> {
        if self.flat.is_none() && self.csv.is_none() && self.nmap.is_none() && self.urls.is_none() {
            return Ok(());
        }
        for (line_number, line) in BufReader::new(File::open(jsonl)?).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let host: HostResult = serde_json::from_str(&line).with_context(|| {
                format!(
                    "parse checkpointed host JSONL {} line {}",
                    jsonl.display(),
                    line_number + 1
                )
            })?;
            for service in &host.services {
                self.write_service(&host, service)?;
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

fn ensure_unique_paths<'a>(paths: impl IntoIterator<Item = Option<&'a Path>>) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for path in paths.into_iter().flatten() {
        let absolute = std::path::absolute(path)
            .with_context(|| format!("resolve output path {}", path.display()))?;
        if !seen.insert(absolute) {
            anyhow::bail!("output paths must be distinct: {}", path.display());
        }
    }
    Ok(())
}

const CSV_HEADER: &[&str] = &[
    "scan_id",
    "scan_started_at",
    "ip",
    "port",
    "protocol",
    "status",
    "title",
    "server",
    "classification",
    "fingerprints",
    "tls_subject",
    "tls_issuer",
    "tls_validity",
    "tls_self_signed",
    "body_sha256",
    "favicon_hash",
    "favicon_mmh3",
    "suspicion_score",
    "known_c2_port",
];

#[derive(serde::Serialize)]
struct CsvRow {
    scan_id: String,
    scan_started_at: String,
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
    tls_validity: Option<String>,
    tls_self_signed: Option<bool>,
    body_sha256: Option<String>,
    favicon_hash: Option<String>,
    favicon_mmh3: Option<i32>,
    suspicion_score: u32,
    known_c2_port: bool,
}
impl CsvRow {
    fn new(h: &HostResult, s: &ServiceResult) -> Self {
        Self {
            scan_id: h.meta.scan_id.clone(),
            scan_started_at: h.meta.scan_started_at.clone(),
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
            tls_validity: s.tls.as_ref().and_then(|t| t.validity.clone()),
            tls_self_signed: s.tls.as_ref().and_then(|t| t.self_signed),
            body_sha256: s.body_sha256.clone(),
            favicon_hash: s.favicon_hash.clone(),
            favicon_mmh3: s.favicon_mmh3,
            suspicion_score: s.suspicion_score,
            known_c2_port: s.known_c2_port,
        }
    }
}

pub fn write_metrics(path: &Path, document: &MetricsDocument) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(document)?)
        .with_context(|| format!("write metrics {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_truncates_uncheckpointed_jsonl_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.jsonl");
        std::fs::write(&path, b"complete\nuncheckpointed\n").unwrap();
        let position = b"complete\n".len() as u64;
        let mut writers =
            OutputWriters::open_at(&path, None, None, None, None, true, Some(position)).unwrap();
        writers.flush().unwrap();
        drop(writers);
        assert_eq!(std::fs::read(&path).unwrap(), b"complete\n");
    }

    #[test]
    fn an_empty_scan_still_creates_a_csv_header() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl = dir.path().join("hosts.jsonl");
        let csv = dir.path().join("services.csv");
        let mut writers = OutputWriters::open(&jsonl, None, Some(&csv), None, None, false).unwrap();
        writers.flush().unwrap();
        drop(writers);
        let content = std::fs::read_to_string(csv).unwrap();
        assert!(content.starts_with("scan_id,scan_started_at,ip,port,protocol"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn one_path_cannot_be_opened_as_two_output_formats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collision.out");
        assert!(OutputWriters::open(&path, Some(&path), None, None, None, false).is_err());
    }
}
