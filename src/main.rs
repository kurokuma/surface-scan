use anyhow::{Context, Result, bail};
use clap::Parser;
use futures::{StreamExt, stream::FuturesUnordered};
use operator_surface_scanner::{
    cli::Cli,
    config::Settings,
    model::{HostResult, Metrics, ScanSummary},
    output::{OutputWriters, write_metrics},
    protocol::{ProbeContext, ProtocolProbe, WebProbe},
    runtime::Checkpoint,
    scanner,
    target::parse_targets,
    util::{now_rfc3339, sha256_hex},
};
use std::{io::Read, net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log_level).context("invalid log level")?,
        )
        .with_writer(std::io::stderr)
        .init();
    let settings = Settings::load(&cli)?;
    let target_text = read_target_text(&cli)?;
    let targets = parse_targets(&target_text)?;
    if targets.is_empty() {
        bail!("no targets supplied")
    }
    let target_hash = sha256_hex(
        targets
            .iter()
            .map(|t| format!("{}:{:?}\n", t.ip, t.known_c2_ports))
            .collect::<String>(),
    );
    let checkpoint_path = settings
        .checkpoint
        .as_deref()
        .or(settings.resume.as_deref());
    let mut checkpoint = if let Some(path) = settings.resume.as_deref() {
        Checkpoint::load(path, &target_hash, &settings.ports_spec)?
    } else {
        Checkpoint::fresh(target_hash, settings.ports_spec.clone())
    };
    let append = settings.resume.is_some();
    let mut writers = OutputWriters::open(
        &settings.output,
        settings.flat_output.as_deref(),
        settings.csv.as_deref(),
        settings.export_nmap.as_deref(),
        settings.export_urls.as_deref(),
        append,
    )?;
    let backend = scanner::backend(&settings).await?;
    tracing::info!(
        backend = backend.name(),
        targets = targets.len(),
        ports = settings.ports.len(),
        rate = settings.rate,
        concurrency = settings.concurrency,
        "scan starting"
    );
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("shutdown requested; stopping new probes");
            signal_cancel.cancel();
        }
    });
    let probe = Arc::new(WebProbe::default());
    let probe_sem = Arc::new(Semaphore::new(settings.probe_concurrency));
    let probe_ctx = ProbeContext {
        http_timeout: settings.http_timeout,
        tls_timeout: settings.tls_timeout,
        max_body: settings.max_body,
    };
    let total_started = Instant::now();
    let mut metrics = Metrics {
        targets: targets.len(),
        ports_per_target: settings.ports.len(),
        ..Default::default()
    };
    for target in targets {
        if checkpoint.completed_hosts.contains(&target.ip) {
            tracing::debug!(ip=%target.ip,"skipping completed host");
            continue;
        }
        if cancel.is_cancelled() {
            break;
        }
        let started_text = now_rfc3339();
        let scan_started = Instant::now();
        let open = backend
            .discover(target.ip, &settings.ports, &cancel)
            .await
            .with_context(|| format!("scan {}", target.ip))?;
        let discovery_ms = scan_started.elapsed().as_millis() as u64;
        checkpoint
            .discovered_open_ports
            .insert(target.ip, open.clone());
        if let Some(path) = checkpoint_path {
            checkpoint.save(path)?
        }
        let protocol_started = Instant::now();
        let mut pending = FuturesUnordered::new();
        let mut next_port = 0usize;
        let mut services = vec![];
        while next_port < open.len() || !pending.is_empty() {
            while next_port < open.len()
                && pending.len() < settings.probe_concurrency
                && !cancel.is_cancelled()
            {
                let port = open[next_port];
                next_port += 1;
                let permits = probe_sem.clone();
                let probe = probe.clone();
                let ctx = probe_ctx.clone();
                let known = target.known_c2_ports.contains(&port);
                let ip = target.ip;
                pending.push(async move {
                    let _permit = permits
                        .acquire_owned()
                        .await
                        .expect("probe semaphore closed");
                    probe.probe(SocketAddr::from((ip, port)), known, &ctx).await
                });
            }
            if let Some(service) = pending.next().await {
                services.push(service);
            } else {
                break;
            }
        }
        services.sort_by_key(|s| s.port);
        let combined_protocol_ms = protocol_started.elapsed().as_millis() as u64;
        let fingerprint_ms = services
            .iter()
            .filter_map(|service| service.fingerprint_latency_ms)
            .sum();
        let protocol_ms = combined_protocol_ms.saturating_sub(fingerprint_ms);
        let host = HostResult {
            schema_version: "1".into(),
            ip: target.ip,
            started_at: started_text,
            completed_at: now_rfc3339(),
            scan: ScanSummary {
                ports_scanned: settings.ports.len(),
                open_ports: open.len(),
                tcp_discovery_ms: discovery_ms,
                protocol_detection_ms: protocol_ms,
                fingerprint_ms,
            },
            services,
        };
        update_metrics(&mut metrics, &host);
        writers.write_host(&host)?;
        checkpoint.output_position = writers.flush()?;
        checkpoint.protocol_probe_completed.insert(target.ip);
        checkpoint.completed_hosts.insert(target.ip);
        if let Some(path) = checkpoint_path {
            checkpoint.save(path)?
        }
        tracing::info!(ip=%target.ip,open_ports=host.scan.open_ports,web_services=host.services.iter().filter(|s|matches!(s.protocol.as_str(),"http"|"https")).count(),"host complete");
    }
    metrics.elapsed_ms = total_started.elapsed().as_millis() as u64;
    metrics.tcp_probe_rate_avg = if metrics.elapsed_ms == 0 {
        0.0
    } else {
        metrics.tcp_probes as f64 / (metrics.elapsed_ms as f64 / 1000.0)
    };
    writers.flush()?;
    if let Some(path) = checkpoint_path {
        checkpoint.save(path)?
    }
    if let Some(path) = settings.metrics_json.as_deref() {
        write_metrics(path, &metrics)?
    }
    print_summary(&metrics, cancel.is_cancelled());
    Ok(())
}

fn read_target_text(cli: &Cli) -> Result<String> {
    let mut text = String::new();
    let mut stdin_consumed = false;
    if let Some(path) = &cli.input {
        if path.as_os_str() == "-" {
            std::io::stdin().read_to_string(&mut text)?;
            stdin_consumed = true;
        } else {
            text.push_str(
                &std::fs::read_to_string(path)
                    .with_context(|| format!("read targets {}", path.display()))?,
            );
            text.push('\n')
        }
    }
    for target in &cli.targets {
        if target == "-" {
            if !stdin_consumed {
                std::io::stdin().read_to_string(&mut text)?;
                stdin_consumed = true;
            }
        } else {
            text.push_str(target);
            text.push('\n')
        }
    }
    Ok(text)
}
fn update_metrics(m: &mut Metrics, h: &HostResult) {
    m.tcp_probes += h.scan.ports_scanned as u64;
    m.tcp_discovery_ms += h.scan.tcp_discovery_ms;
    m.protocol_detection_ms += h.scan.protocol_detection_ms;
    m.fingerprint_ms += h.scan.fingerprint_ms;
    m.open_ports += h.scan.open_ports as u64;
    for s in &h.services {
        match s.protocol.as_str() {
            "http" => m.http_services += 1,
            "https" => m.https_services += 1,
            _ => {}
        }
        if s.fingerprints.iter().any(|f| f.name == "hfs") {
            m.hfs += 1
        }
        match s.classification.as_deref() {
            Some("directory_listing") => m.directory_listings += 1,
            Some("login_panel" | "admin_panel") => m.login_admin_panels += 1,
            _ => {}
        }
        if s.is_unknown_web {
            m.unknown_web_surfaces += 1
        }
    }
}
fn print_summary(m: &Metrics, interrupted: bool) {
    eprintln!(
        "\nScan summary{}\nTargets                 {}\nPorts per target        {}\nTCP probes              {}\nOpen ports              {}\nHTTP services           {}\nHTTPS services          {}\nHFS                     {}\nDirectory listings      {}\nLogin/Admin panels      {}\nUnknown web surfaces    {}\nTCP discovery           {:.2}s\nProtocol detection      {:.2}s\nFingerprint             {:.3}s\nElapsed                 {:.2}s\nTCP probe rate avg      {:.0} pps",
        if interrupted { " (interrupted)" } else { "" },
        m.targets,
        m.ports_per_target,
        m.tcp_probes,
        m.open_ports,
        m.http_services,
        m.https_services,
        m.hfs,
        m.directory_listings,
        m.login_admin_panels,
        m.unknown_web_surfaces,
        m.tcp_discovery_ms as f64 / 1000.0,
        m.protocol_detection_ms as f64 / 1000.0,
        m.fingerprint_ms as f64 / 1000.0,
        m.elapsed_ms as f64 / 1000.0,
        m.tcp_probe_rate_avg
    )
}
