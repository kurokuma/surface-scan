use crate::{
    config::Settings,
    fingerprint::FingerprintEngine,
    model::{
        HostResult, Metrics, SCHEMA_VERSION, ScanMetadata, ScanSummary, ServiceResult, Target,
    },
    output::OutputWriters,
    protocol::{ProbeContext, ProtocolProbe},
    runtime::Checkpoint,
    scanner::{DiscoveryOutcome, ScannerBackend},
    util::now_rfc3339,
};
use anyhow::{Context, Result};
use futures::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    sync::{Mutex, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// A host whose TCP sweep is finished, queued for application probing.
struct Discovered {
    target: Target,
    outcome: DiscoveryOutcome,
    ports_scanned: usize,
    started_at: String,
    discovery_ms: u64,
}

/// One open port waiting for the application stage. This is deliberately the
/// unit carried by the bounded queue; allocating one future for every open port
/// would make a high-open-ratio host effectively unbounded.
struct ProbeJob {
    ip: Ipv4Addr,
    port: u16,
    known_c2_port: bool,
}

struct FingerprintJob {
    ip: Ipv4Addr,
    service: ServiceResult,
}

enum PipelineEvent {
    HostStarted(Discovered),
    Service {
        ip: Ipv4Addr,
        service: Box<ServiceResult>,
    },
}

struct HostAccumulator {
    discovered: Discovered,
    services: Vec<ServiceResult>,
}

/// Bounded pipeline described in spec section 11.
///
/// Target generation, TCP discovery, protocol probing, and output each run as
/// their own stage joined by bounded channels, so discovery of one host overlaps
/// probing of another and neither can starve the other or grow a queue without
/// limit. Unbounded channels are deliberately not used anywhere.
pub struct Pipeline {
    pub settings: Settings,
    pub meta: ScanMetadata,
    pub backend: Arc<dyn ScannerBackend>,
    pub probe: Arc<dyn ProtocolProbe>,
    pub fingerprint: Arc<FingerprintEngine>,
    pub probe_ctx: ProbeContext,
    pub cancel: CancellationToken,
    pub checkpoint_path: Option<PathBuf>,
}

impl Pipeline {
    pub async fn run(
        self,
        targets: Vec<Target>,
        mut checkpoint: Checkpoint,
        mut writers: OutputWriters,
    ) -> Result<Metrics> {
        let depth = self.settings.queue_depth;
        let (target_tx, target_rx) = mpsc::channel::<Target>(depth);
        let (probe_tx, probe_rx) = mpsc::channel::<ProbeJob>(depth);
        let (fingerprint_tx, fingerprint_rx) = mpsc::channel::<FingerprintJob>(depth);
        let (event_tx, mut event_rx) = mpsc::channel::<PipelineEvent>(depth);

        let mut metrics = Metrics {
            targets: targets.len(),
            ports_per_target: self.settings.ports.len(),
            ..Default::default()
        };

        // Stage 1: target generation. Completed hosts are skipped here so a
        // resume never re-queues finished work.
        let generator_cancel = self.cancel.clone();
        let completed: std::collections::BTreeSet<_> = checkpoint.completed_hosts.clone();
        let generator = tokio::spawn(async move {
            for target in targets {
                if generator_cancel.is_cancelled() {
                    break;
                }
                if completed.contains(&target.ip) {
                    tracing::debug!(ip=%target.ip, "skipping host completed in checkpoint");
                    continue;
                }
                if target_tx.send(target).await.is_err() {
                    break;
                }
            }
        });

        // Stage 2: TCP discovery workers.
        let target_rx = Arc::new(Mutex::new(target_rx));
        let mut discovery_workers = FuturesUnordered::new();
        let discovery_wall_started = std::time::Instant::now();
        for _ in 0..self.settings.host_concurrency {
            let rx = target_rx.clone();
            let jobs = probe_tx.clone();
            let events = event_tx.clone();
            let backend = self.backend.clone();
            let ports = Arc::new(self.settings.ports.clone());
            let cancel = self.cancel.clone();
            discovery_workers.push(tokio::spawn(async move {
                loop {
                    let Some(target) = rx.lock().await.recv().await else {
                        break;
                    };
                    let started_at = now_rfc3339();
                    let started = std::time::Instant::now();
                    // A known C2 port is always swept, even when it falls
                    // outside --ports (spec section 22).
                    let ports = merge_known_ports(&ports, &target.known_c2_ports);
                    let ports_scanned = ports.len();
                    let outcome = match backend.discover(target.ip, &ports, &cancel).await {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            // One unreachable host must not end the scan.
                            tracing::warn!(ip=%target.ip, %error, "discovery failed for host");
                            DiscoveryOutcome {
                                complete: false,
                                ..Default::default()
                            }
                        }
                    };
                    let open_ports = outcome.open.clone();
                    let target_ip = target.ip;
                    let known_c2_ports = target.known_c2_ports.clone();
                    let discovered = Discovered {
                        target,
                        outcome,
                        ports_scanned,
                        started_at,
                        discovery_ms: started.elapsed().as_millis() as u64,
                    };
                    // The host envelope is enqueued before any of its jobs, so
                    // the aggregator always knows the expected service count.
                    if events
                        .send(PipelineEvent::HostStarted(discovered))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    for port in open_ports {
                        let job = ProbeJob {
                            ip: target_ip,
                            port,
                            known_c2_port: known_c2_ports.contains(&port),
                        };
                        if jobs.send(job).await.is_err() {
                            return;
                        }
                    }
                }
            }));
        }
        let discovery_done = tokio::spawn(async move {
            while let Some(worker) = discovery_workers.next().await {
                worker.context("TCP discovery worker panicked")?;
            }
            Ok::<_, anyhow::Error>(discovery_wall_started.elapsed())
        });
        drop(probe_tx);

        // Stage 3: one bounded open-port queue feeding a fixed number of
        // protocol workers. Worker count itself is the global application
        // concurrency limit; no per-host future fan-out exists.
        let probe_rx = Arc::new(Mutex::new(probe_rx));
        let mut probe_workers = FuturesUnordered::new();
        for _ in 0..self.settings.probe_concurrency {
            let rx = probe_rx.clone();
            let fingerprints = fingerprint_tx.clone();
            let probe = self.probe.clone();
            let ctx = self.probe_ctx.clone();
            probe_workers.push(tokio::spawn(async move {
                loop {
                    let Some(job) = rx.lock().await.recv().await else {
                        break;
                    };
                    let address = SocketAddr::from((job.ip, job.port));
                    let probe_started = std::time::Instant::now();
                    let mut service = match timeout(
                        ctx.probe_budget(),
                        probe.probe(address, job.known_c2_port, &ctx),
                    )
                    .await
                    {
                        Ok(service) => service,
                        Err(_) => {
                            let mut service =
                                ServiceResult::unknown_tcp(job.port, job.known_c2_port);
                            service.error = Some("probe budget exceeded".into());
                            service
                        }
                    };
                    service.protocol_probe_latency_ms =
                        Some(probe_started.elapsed().as_millis() as u64);
                    if fingerprints
                        .send(FingerprintJob {
                            ip: job.ip,
                            service,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        drop(fingerprint_tx);

        // Stage 4: body evidence remains only in this bounded queue and is
        // consumed before the enriched service moves to host aggregation.
        let fingerprint_rx = Arc::new(Mutex::new(fingerprint_rx));
        let mut fingerprint_workers = FuturesUnordered::new();
        for _ in 0..self.settings.fingerprint_concurrency {
            let rx = fingerprint_rx.clone();
            let events = event_tx.clone();
            let engine = self.fingerprint.clone();
            let weights = self.settings.suspicion.clone();
            fingerprint_workers.push(tokio::spawn(async move {
                loop {
                    let Some(mut job) = rx.lock().await.recv().await else {
                        break;
                    };
                    engine.enrich(&mut job.service, &weights);
                    if events
                        .send(PipelineEvent::Service {
                            ip: job.ip,
                            service: Box::new(job.service),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        drop(event_tx);

        // Stage 5: a single writer preserves ordering. The bounded event queue
        // absorbs short I/O stalls and applies backpressure instead of allowing
        // memory to grow without limit during a sustained stall.
        let mut hosts = HashMap::<Ipv4Addr, HostAccumulator>::new();
        while let Some(event) = event_rx.recv().await {
            let completed = match event {
                PipelineEvent::HostStarted(discovered) => {
                    if discovered.outcome.open.is_empty() {
                        Some(finish_host(discovered, vec![], &self.meta))
                    } else {
                        hosts.insert(
                            discovered.target.ip,
                            HostAccumulator {
                                discovered,
                                services: vec![],
                            },
                        );
                        None
                    }
                }
                PipelineEvent::Service { ip, service } => {
                    let Some(host) = hosts.get_mut(&ip) else {
                        tracing::error!(%ip, "service arrived before host envelope");
                        continue;
                    };
                    host.services.push(*service);
                    if host.services.len() == host.discovered.outcome.open.len() {
                        let host = hosts.remove(&ip).expect("host accumulator disappeared");
                        Some(finish_host(host.discovered, host.services, &self.meta))
                    } else {
                        None
                    }
                }
            };
            if let Some(host) = completed {
                persist_host(
                    &host,
                    &mut metrics,
                    &mut writers,
                    &mut checkpoint,
                    self.checkpoint_path.as_deref(),
                )?;
            }
        }

        generator.await.context("target generator panicked")?;
        metrics.tcp_discovery_wall_ms = discovery_done
            .await
            .context("discovery supervisor panicked")??
            .as_millis() as u64;
        while let Some(worker) = probe_workers.next().await {
            worker.context("protocol probe worker panicked")?;
        }
        while let Some(worker) = fingerprint_workers.next().await {
            worker.context("fingerprint worker panicked")?;
        }
        if !hosts.is_empty() {
            anyhow::bail!(
                "pipeline ended with {} incomplete host aggregations",
                hosts.len()
            );
        }
        writers.flush()?;
        if let Some(path) = &self.checkpoint_path {
            checkpoint.save(path)?;
        }
        metrics.interrupted = self.cancel.is_cancelled();
        Ok(metrics)
    }
}

/// Union the selected ports with any known C2 ports for this host.
fn merge_known_ports(selected: &[u16], known: &[u16]) -> Vec<u16> {
    if known
        .iter()
        .all(|port| selected.binary_search(port).is_ok())
    {
        return selected.to_vec();
    }
    let mut ports = selected.to_vec();
    ports.extend_from_slice(known);
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn finish_host(
    discovered: Discovered,
    mut services: Vec<ServiceResult>,
    meta: &ScanMetadata,
) -> HostResult {
    let Discovered {
        target,
        outcome,
        ports_scanned,
        started_at,
        discovery_ms,
    } = discovered;
    services.sort_by_key(|s| s.port);
    let protocol_detection_ms: u64 = services
        .iter()
        .filter_map(|service| service.protocol_probe_latency_ms)
        .sum();
    let fingerprint_ms: u64 = services
        .iter()
        .filter_map(|service| service.fingerprint_latency_ms)
        .sum();
    HostResult {
        schema_version: SCHEMA_VERSION.into(),
        meta: meta.clone(),
        ip: target.ip,
        started_at,
        completed_at: now_rfc3339(),
        scan: ScanSummary {
            ports_scanned,
            ports_attempted: outcome.attempted,
            tcp_probes_sent: outcome.probes_sent,
            open_ports: outcome.open.len(),
            tcp_discovery_ms: discovery_ms,
            protocol_detection_ms,
            fingerprint_ms,
            complete: outcome.complete,
        },
        services,
    }
}

fn persist_host(
    host: &HostResult,
    metrics: &mut Metrics,
    writers: &mut OutputWriters,
    checkpoint: &mut Checkpoint,
    checkpoint_path: Option<&std::path::Path>,
) -> Result<()> {
    update_metrics(metrics, host);
    writers.write_host(host)?;
    let flushed_position = writers.flush()?;
    checkpoint
        .discovered_open_ports
        .insert(host.ip, host.services.iter().map(|s| s.port).collect());
    if host.scan.complete {
        checkpoint.output_position = flushed_position;
        checkpoint.protocol_probe_completed.insert(host.ip);
        checkpoint.completed_hosts.insert(host.ip);
    } else {
        checkpoint.protocol_probe_completed.remove(&host.ip);
        checkpoint.completed_hosts.remove(&host.ip);
        tracing::warn!(ip=%host.ip, "host interrupted; it will be rescanned on resume");
    }
    if let Some(path) = checkpoint_path {
        checkpoint.save(path)?;
    }
    tracing::info!(
        ip = %host.ip,
        open_ports = host.scan.open_ports,
        web_services = host.services.iter().filter(|s| s.is_web()).count(),
        complete = host.scan.complete,
        "host complete"
    );
    Ok(())
}

fn update_metrics(m: &mut Metrics, h: &HostResult) {
    m.tcp_probes += h.scan.tcp_probes_sent;
    m.tcp_discovery_ms += h.scan.tcp_discovery_ms;
    m.protocol_detection_ms += h.scan.protocol_detection_ms;
    m.fingerprint_ms += h.scan.fingerprint_ms;
    m.open_ports += h.scan.open_ports as u64;
    if h.scan.complete {
        m.hosts_completed += 1;
    } else {
        m.hosts_interrupted += 1;
    }
    for s in &h.services {
        match s.protocol.as_str() {
            "http" => m.http_services += 1,
            "https" => m.https_services += 1,
            "tls" => m.tls_non_http_services += 1,
            _ => m.unknown_tcp_services += 1,
        }
        if s.fingerprints.iter().any(|f| f.name == "hfs") {
            m.hfs += 1;
        }
        match s.classification.as_deref() {
            Some("directory_listing") => m.directory_listings += 1,
            Some("login_panel" | "admin_panel") => m.login_admin_panels += 1,
            _ => {}
        }
        if s.is_unknown_web {
            m.unknown_web_surfaces += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_ports_are_added_to_the_sweep() {
        assert_eq!(merge_known_ports(&[80, 443], &[1618]), vec![80, 443, 1618]);
        assert_eq!(merge_known_ports(&[80, 443], &[443]), vec![80, 443]);
        assert_eq!(merge_known_ports(&[80], &[]), vec![80]);
    }
}
