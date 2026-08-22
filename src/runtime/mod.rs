pub mod multiprocess;
pub mod pipeline;
pub mod shutdown;

use crate::{
    config::Settings,
    fingerprint::FingerprintEngine,
    model::{Metrics, MetricsDocument, SCHEMA_VERSION, ScanMetadata, Target},
    output::{OutputWriters, write_metrics},
    protocol::{ProbeContext, WebProbe},
    runtime::pipeline::Pipeline,
    scanner,
    util::now_rfc3339,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Write, net::Ipv4Addr, path::Path, sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    pub schema_version: String,
    pub target_set_hash: String,
    pub port_spec: String,
    pub completed_hosts: BTreeSet<Ipv4Addr>,
    pub discovered_open_ports: std::collections::BTreeMap<Ipv4Addr, Vec<u16>>,
    pub protocol_probe_completed: BTreeSet<Ipv4Addr>,
    pub output_position: u64,
}
impl Checkpoint {
    pub fn fresh(hash: String, ports: String) -> Self {
        Self {
            schema_version: crate::model::SCHEMA_VERSION.into(),
            target_set_hash: hash,
            port_spec: ports,
            ..Default::default()
        }
    }
    pub fn load(path: &Path, expected_hash: &str, expected_ports: &str) -> Result<Self> {
        let cp: Self = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("read checkpoint {}", path.display()))?,
        )?;
        if cp.schema_version != crate::model::SCHEMA_VERSION {
            bail!(
                "checkpoint schema version {} is not supported (expected {})",
                cp.schema_version,
                crate::model::SCHEMA_VERSION
            )
        }
        if cp.target_set_hash != expected_hash {
            bail!("checkpoint target set does not match current targets")
        }
        if cp.port_spec != expected_ports {
            bail!("checkpoint ports do not match current selection")
        }
        Ok(cp)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        atomic_write_json(path, self)
    }
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let temporary = path.with_extension("state.tmp");
    let mut file = std::fs::File::create(&temporary)
        .with_context(|| format!("create temporary file {}", temporary.display()))?;
    file.write_all(&serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write temporary file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync temporary file {}", temporary.display()))?;
    drop(file);
    replace_file(&temporary, path).with_context(|| format!("commit file {}", path.display()))?;
    Ok(())
}

/// Execute one scan shard. Single-process scans and hidden child workers use
/// this same path so timeout, checkpoint, and output behavior cannot diverge.
pub async fn execute_scan(
    settings: Settings,
    targets: Vec<Target>,
    target_hash: String,
    meta: ScanMetadata,
) -> Result<Metrics> {
    let checkpoint_path = settings
        .checkpoint
        .as_deref()
        .or(settings.resume.as_deref())
        .map(Path::to_path_buf);
    let checkpoint = if let Some(path) = settings.resume.as_deref() {
        Checkpoint::load(path, &target_hash, &settings.ports_spec)?
    } else {
        Checkpoint::fresh(target_hash, settings.ports_spec.clone())
    };
    let backend = scanner::backend(&settings).await?;
    let writers = OutputWriters::open_at(
        &settings.output,
        settings.flat_output.as_deref(),
        settings.csv.as_deref(),
        settings.export_nmap.as_deref(),
        settings.export_urls.as_deref(),
        settings.resume.is_some(),
        settings.resume.as_ref().map(|_| checkpoint.output_position),
    )?;
    let cancel = CancellationToken::new();
    shutdown::watch(cancel.clone());
    let pipeline = Pipeline {
        probe_ctx: ProbeContext::from_settings(&settings),
        probe: Arc::new(WebProbe::new()),
        fingerprint: Arc::new(FingerprintEngine::new(&settings.fingerprints)),
        backend,
        meta: meta.clone(),
        cancel,
        checkpoint_path,
        settings: settings.clone(),
    };
    let total_started = Instant::now();
    let mut metrics = pipeline.run(targets, checkpoint, writers).await?;
    metrics.elapsed_ms = total_started.elapsed().as_millis() as u64;
    metrics.tcp_probe_rate_avg = if metrics.tcp_discovery_wall_ms == 0 {
        0.0
    } else {
        metrics.tcp_probes as f64 / (metrics.tcp_discovery_wall_ms as f64 / 1000.0)
    };
    if let Some(path) = settings.metrics_json.as_deref() {
        write_metrics(
            path,
            &MetricsDocument {
                schema_version: SCHEMA_VERSION.into(),
                meta,
                completed_at: now_rfc3339(),
                metrics: metrics.clone(),
            },
        )?;
    }
    Ok(metrics)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both buffers are NUL-terminated and remain alive for the call.
    let succeeded = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.state");
        let cp = Checkpoint::fresh("abc".into(), "80".into());
        cp.save(&p).unwrap();
        assert_eq!(
            Checkpoint::load(&p, "abc", "80").unwrap().target_set_hash,
            "abc"
        );
        // Saving again must replace the existing file on Windows as well as
        // Unix; std::fs::rename alone cannot do that on Windows.
        let mut updated = cp;
        updated.completed_hosts.insert("192.0.2.1".parse().unwrap());
        updated.save(&p).unwrap();
        assert!(
            Checkpoint::load(&p, "abc", "80")
                .unwrap()
                .completed_hosts
                .contains(&"192.0.2.1".parse().unwrap())
        );
    }
    #[test]
    fn checkpoint_rejects_a_different_target_set() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.state");
        Checkpoint::fresh("abc".into(), "80".into())
            .save(&p)
            .unwrap();
        assert!(Checkpoint::load(&p, "different", "80").is_err());
        assert!(Checkpoint::load(&p, "abc", "1-65535").is_err());
    }
    #[test]
    fn checkpoint_rejects_an_unknown_schema() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.state");
        let mut checkpoint = Checkpoint::fresh("abc".into(), "80".into());
        checkpoint.schema_version = "future".into();
        checkpoint.save(&p).unwrap();
        assert!(Checkpoint::load(&p, "abc", "80").is_err());
    }
}
