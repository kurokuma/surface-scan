use crate::{
    config::Settings,
    model::{HostResult, Metrics, MetricsDocument, SCHEMA_VERSION, ScanMetadata, Target},
    output::{OutputWriters, write_metrics},
    runtime::{atomic_write_json, execute_scan, shutdown},
    util::now_rfc3339,
};
use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Instant,
};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerManifest {
    pub schema_version: String,
    pub settings: Settings,
    pub targets: Vec<Target>,
    pub target_set_hash: String,
    pub meta: ScanMetadata,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoordinatorState {
    schema_version: String,
    target_set_hash: String,
    port_spec: String,
    processes: usize,
    parts_directory: PathBuf,
    complete: bool,
}

pub fn load_worker_manifest(path: &Path) -> Result<WorkerManifest> {
    let manifest: WorkerManifest = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read worker manifest {}", path.display()))?,
    )?;
    if manifest.schema_version != SCHEMA_VERSION {
        bail!("worker manifest schema is not supported")
    }
    Ok(manifest)
}

pub async fn run_worker(manifest: WorkerManifest) -> Result<Metrics> {
    execute_scan(
        manifest.settings,
        manifest.targets,
        manifest.target_set_hash,
        manifest.meta,
    )
    .await
}

pub async fn coordinate(
    settings: Settings,
    targets: Vec<Target>,
    target_set_hash: String,
    meta: ScanMetadata,
    log_level: String,
) -> Result<Metrics> {
    validate_process_budget(&settings, targets.len())?;
    let target_count = meta.target_count;
    let process_count = settings.processes;
    let state_path = settings
        .resume
        .clone()
        .or_else(|| settings.checkpoint.clone())
        .unwrap_or_else(|| automatic_state_path(&settings.output));
    let state_path = std::path::absolute(&state_path)
        .with_context(|| format!("resolve process state {}", state_path.display()))?;
    let resuming = settings.resume.is_some();
    let mut state = if resuming {
        load_state(
            &state_path,
            &target_set_hash,
            &settings.ports_spec,
            process_count,
        )?
    } else {
        if state_path.exists() {
            let old: CoordinatorState = serde_json::from_slice(&std::fs::read(&state_path)?)
                .with_context(|| format!("parse coordinator state {}", state_path.display()))?;
            if !old.complete {
                bail!(
                    "incomplete multi-process state exists at {}; resume it or move it before starting a fresh scan",
                    state_path.display()
                )
            }
        }
        CoordinatorState {
            schema_version: SCHEMA_VERSION.into(),
            target_set_hash: target_set_hash.clone(),
            port_spec: settings.ports_spec.clone(),
            processes: process_count,
            parts_directory: parts_path(&state_path),
            complete: false,
        }
    };
    std::fs::create_dir_all(&state.parts_directory).with_context(|| {
        format!(
            "create multi-process parts directory {}",
            state.parts_directory.display()
        )
    })?;
    state.complete = false;
    atomic_write_json(&state_path, &state)?;

    let shards = shard_targets(targets, process_count);
    let mut manifests = Vec::with_capacity(process_count);
    for (index, shard) in shards.into_iter().enumerate() {
        let mut child = shard_settings(&settings, &state.parts_directory, index, process_count);
        let part_state = child
            .checkpoint
            .clone()
            .expect("shard checkpoint path is assigned");
        if resuming && part_state.exists() {
            child.resume = Some(part_state);
            child.checkpoint = None;
        }
        let manifest = WorkerManifest {
            schema_version: SCHEMA_VERSION.into(),
            settings: child,
            targets: shard,
            target_set_hash: target_set_hash.clone(),
            meta: meta.clone(),
            log_level: log_level.clone(),
        };
        let path = state
            .parts_directory
            .join(format!("part-{index}.manifest.json"));
        atomic_write_json(&path, &manifest)?;
        manifests.push(path);
    }

    tracing::info!(
        processes = process_count,
        worker_threads = settings.worker_threads,
        state = %state_path.display(),
        "starting multi-process scan"
    );
    let cancel = CancellationToken::new();
    shutdown::watch(cancel.clone());
    let started = Instant::now();
    let executable = std::env::current_exe().context("locate scanner executable")?;
    let mut children = FuturesUnordered::new();
    for manifest in manifests {
        let executable = executable.clone();
        children.push(tokio::spawn(async move {
            Command::new(executable)
                .arg("--worker-manifest")
                .arg(&manifest)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await
                .with_context(|| format!("run worker {}", manifest.display()))
        }));
    }
    let mut failed = Vec::new();
    while let Some(joined) = children.next().await {
        let status = joined.context("worker wait task panicked")??;
        if !status.success() {
            failed.push(status.to_string());
        }
    }
    if !failed.is_empty() {
        bail!(
            "{} worker process(es) failed ({}); state preserved at {}",
            failed.len(),
            failed.join(", "),
            state_path.display()
        )
    }

    let (hosts, worker_metrics) = collect_parts(&state.parts_directory, process_count)?;
    let mut metrics = metrics_from_hosts(hosts.values());
    metrics.tcp_discovery_wall_ms = worker_metrics.tcp_discovery_wall_ms;
    metrics.interrupted = worker_metrics.interrupted;
    metrics.targets = target_count;
    metrics.ports_per_target = settings.ports.len();
    metrics.elapsed_ms = started.elapsed().as_millis() as u64;
    metrics.interrupted |= cancel.is_cancelled();
    metrics.tcp_probe_rate_avg = if worker_metrics.tcp_discovery_wall_ms == 0 {
        0.0
    } else {
        worker_metrics.tcp_probes as f64 / (worker_metrics.tcp_discovery_wall_ms as f64 / 1000.0)
    };
    write_merged_outputs(&settings, hosts.values())?;
    if let Some(path) = settings.metrics_json.as_deref() {
        write_metrics(
            path,
            &MetricsDocument {
                schema_version: SCHEMA_VERSION.into(),
                meta: meta.clone(),
                completed_at: now_rfc3339(),
                metrics: metrics.clone(),
            },
        )?;
    }
    state.complete = !metrics.interrupted && metrics.hosts_completed == target_count;
    atomic_write_json(&state_path, &state)?;
    if !state.complete {
        tracing::warn!(state=%state_path.display(), "multi-process scan is resumable but incomplete");
    }
    Ok(metrics)
}

fn validate_process_budget(settings: &Settings, target_count: usize) -> Result<()> {
    let count = settings.processes;
    if count <= 1 {
        bail!("multi-process coordinator requires processes > 1")
    }
    if count > target_count {
        bail!("processes ({count}) cannot exceed target count ({target_count})")
    }
    for (name, value) in [
        ("worker-threads", settings.worker_threads),
        ("rate", settings.rate as usize),
        ("burst", settings.burst as usize),
        ("concurrency", settings.concurrency),
        ("probe-concurrency", settings.probe_concurrency),
        ("fingerprint-concurrency", settings.fingerprint_concurrency),
    ] {
        if value < count {
            bail!("{name} ({value}) must be at least processes ({count})")
        }
    }
    Ok(())
}

fn shard_targets(targets: Vec<Target>, count: usize) -> Vec<Vec<Target>> {
    let mut shards = vec![Vec::new(); count];
    for (index, target) in targets.into_iter().enumerate() {
        shards[index % count].push(target);
    }
    shards
}

fn share(total: usize, count: usize, index: usize) -> usize {
    total / count + usize::from(index < total % count)
}

fn shard_settings(base: &Settings, directory: &Path, index: usize, count: usize) -> Settings {
    let mut child = base.clone();
    child.processes = 1;
    child.worker_threads = share(base.worker_threads, count, index);
    child.rate = share(base.rate as usize, count, index) as u64;
    child.burst = share(base.burst as usize, count, index) as u64;
    child.concurrency = share(base.concurrency, count, index);
    child.probe_concurrency = share(base.probe_concurrency, count, index);
    child.fingerprint_concurrency = share(base.fingerprint_concurrency, count, index);
    child.host_concurrency = share(base.host_concurrency.max(count), count, index);
    child.output = directory.join(format!("part-{index}.hosts.jsonl"));
    child.flat_output = None;
    child.csv = None;
    child.export_nmap = None;
    child.export_urls = None;
    child.metrics_json = Some(directory.join(format!("part-{index}.metrics.json")));
    child.checkpoint = Some(directory.join(format!("part-{index}.state")));
    child.resume = None;
    child
}

fn collect_parts(
    directory: &Path,
    count: usize,
) -> Result<(BTreeMap<Ipv4Addr, HostResult>, Metrics)> {
    let mut hosts = BTreeMap::<Ipv4Addr, HostResult>::new();
    let mut metrics = Metrics::default();
    for index in 0..count {
        let host_path = directory.join(format!("part-{index}.hosts.jsonl"));
        for (line_number, line) in BufReader::new(
            File::open(&host_path)
                .with_context(|| format!("open worker output {}", host_path.display()))?,
        )
        .lines()
        .enumerate()
        {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let host: HostResult = serde_json::from_str(&line).with_context(|| {
                format!("parse {} line {}", host_path.display(), line_number + 1)
            })?;
            match hosts.get(&host.ip) {
                Some(previous) if previous.scan.complete && !host.scan.complete => {}
                _ => {
                    hosts.insert(host.ip, host);
                }
            }
        }
        let metrics_path = directory.join(format!("part-{index}.metrics.json"));
        let document: MetricsDocument = serde_json::from_slice(
            &std::fs::read(&metrics_path)
                .with_context(|| format!("read worker metrics {}", metrics_path.display()))?,
        )?;
        add_metrics(&mut metrics, &document.metrics);
    }
    Ok((hosts, metrics))
}

fn add_metrics(total: &mut Metrics, part: &Metrics) {
    total.hosts_completed += part.hosts_completed;
    total.hosts_interrupted += part.hosts_interrupted;
    total.tcp_probes += part.tcp_probes;
    total.open_ports += part.open_ports;
    total.http_services += part.http_services;
    total.https_services += part.https_services;
    total.tls_non_http_services += part.tls_non_http_services;
    total.unknown_tcp_services += part.unknown_tcp_services;
    total.hfs += part.hfs;
    total.directory_listings += part.directory_listings;
    total.login_admin_panels += part.login_admin_panels;
    total.unknown_web_surfaces += part.unknown_web_surfaces;
    total.tcp_discovery_wall_ms = total.tcp_discovery_wall_ms.max(part.tcp_discovery_wall_ms);
    total.tcp_discovery_ms += part.tcp_discovery_ms;
    total.protocol_detection_ms += part.protocol_detection_ms;
    total.fingerprint_ms += part.fingerprint_ms;
    total.interrupted |= part.interrupted;
}

fn metrics_from_hosts<'a>(hosts: impl IntoIterator<Item = &'a HostResult>) -> Metrics {
    let mut metrics = Metrics::default();
    for host in hosts {
        metrics.tcp_probes += host.scan.tcp_probes_sent;
        metrics.tcp_discovery_ms += host.scan.tcp_discovery_ms;
        metrics.protocol_detection_ms += host.scan.protocol_detection_ms;
        metrics.fingerprint_ms += host.scan.fingerprint_ms;
        metrics.open_ports += host.scan.open_ports as u64;
        if host.scan.complete {
            metrics.hosts_completed += 1;
        } else {
            metrics.hosts_interrupted += 1;
        }
        for service in &host.services {
            match service.protocol.as_str() {
                "http" => metrics.http_services += 1,
                "https" => metrics.https_services += 1,
                "tls" => metrics.tls_non_http_services += 1,
                _ => metrics.unknown_tcp_services += 1,
            }
            if service.fingerprints.iter().any(|item| item.name == "hfs") {
                metrics.hfs += 1;
            }
            match service.classification.as_deref() {
                Some("directory_listing") => metrics.directory_listings += 1,
                Some("login_panel" | "admin_panel") => metrics.login_admin_panels += 1,
                _ => {}
            }
            if service.is_unknown_web {
                metrics.unknown_web_surfaces += 1;
            }
        }
    }
    metrics
}

fn write_merged_outputs<'a>(
    settings: &Settings,
    hosts: impl IntoIterator<Item = &'a HostResult>,
) -> Result<()> {
    let mut writers = OutputWriters::open(
        &settings.output,
        settings.flat_output.as_deref(),
        settings.csv.as_deref(),
        settings.export_nmap.as_deref(),
        settings.export_urls.as_deref(),
        false,
    )?;
    for host in hosts {
        writers.write_host(host)?;
    }
    writers.flush()?;
    Ok(())
}

fn automatic_state_path(output: &Path) -> PathBuf {
    PathBuf::from(format!("{}.mp.state", output.display()))
}

fn parts_path(state: &Path) -> PathBuf {
    PathBuf::from(format!("{}.parts", state.display()))
}

fn load_state(
    path: &Path,
    target_hash: &str,
    ports: &str,
    processes: usize,
) -> Result<CoordinatorState> {
    let state: CoordinatorState = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read state {}", path.display()))?,
    )?;
    if state.schema_version != SCHEMA_VERSION
        || state.target_set_hash != target_hash
        || state.port_spec != ports
        || state.processes != processes
    {
        bail!("multi-process state does not match schema, targets, ports, or process count")
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharding_is_deterministic_and_balanced() {
        let targets: Vec<Target> = (1..=7)
            .map(|last| Target {
                ip: Ipv4Addr::new(192, 0, 2, last),
                known_c2_ports: vec![],
            })
            .collect();
        let shards = shard_targets(targets, 3);
        assert_eq!(shards.iter().map(Vec::len).collect::<Vec<_>>(), [3, 2, 2]);
        assert_eq!(shards[0][1].ip, Ipv4Addr::new(192, 0, 2, 4));
    }

    #[test]
    fn resource_shares_preserve_the_total() {
        let shares: Vec<_> = (0..4).map(|index| share(10_003, 4, index)).collect();
        assert_eq!(shares.iter().sum::<usize>(), 10_003);
        assert!(shares.iter().max().unwrap() - shares.iter().min().unwrap() <= 1);
    }
}
