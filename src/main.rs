use anyhow::{Context, Result, bail};
use clap::Parser;
use operator_surface_scanner::fingerprint::FingerprintEngine;
use operator_surface_scanner::{
    cli::Cli,
    config::Settings,
    model::{Metrics, MetricsDocument, SCHEMA_VERSION, ScanMetadata, Target},
    output::{OutputWriters, write_metrics},
    protocol::{ProbeContext, WebProbe},
    runtime::{Checkpoint, pipeline::Pipeline, shutdown},
    scanner,
    target::parse_targets,
    util::{now_rfc3339, scan_id, sha256_hex},
};
use std::{io::Read, sync::Arc, time::Instant};
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
    let targets = parse_targets(&target_text, settings.known_service_field.as_deref())?;
    if targets.is_empty() {
        bail!("no targets supplied")
    }
    validate_artifact_paths(&cli, &settings)?;
    let target_hash = target_set_hash(&targets);
    let checkpoint_path = settings
        .checkpoint
        .as_deref()
        .or(settings.resume.as_deref())
        .map(Path::to_path_buf);
    let checkpoint = if let Some(path) = settings.resume.as_deref() {
        Checkpoint::load(path, &target_hash, &settings.ports_spec)?
    } else {
        Checkpoint::fresh(target_hash.clone(), settings.ports_spec.clone())
    };
    // Validate backend/capabilities before touching output files. In
    // particular, a raw-socket initialization failure must not truncate an
    // analyst's existing result path.
    let backend = scanner::backend(&settings).await?;
    let append = settings.resume.is_some();
    let writers = OutputWriters::open_at(
        &settings.output,
        settings.flat_output.as_deref(),
        settings.csv.as_deref(),
        settings.export_nmap.as_deref(),
        settings.export_urls.as_deref(),
        append,
        settings.resume.as_ref().map(|_| checkpoint.output_position),
    )?;
    let meta = build_metadata(&settings, &targets, &target_hash, backend.name());
    tracing::info!(
        backend = backend.name(),
        scan_id = %meta.scan_id,
        targets = targets.len(),
        ports = settings.ports.len(),
        rate = settings.rate,
        concurrency = settings.concurrency,
        host_concurrency = settings.host_concurrency,
        probe_concurrency = settings.probe_concurrency,
        fingerprint_concurrency = settings.fingerprint_concurrency,
        tls_verification = %meta.tls_verification,
        "scan starting"
    );

    let cancel = CancellationToken::new();
    shutdown::watch(cancel.clone());

    let pipeline = Pipeline {
        probe_ctx: ProbeContext::from_settings(&settings),
        probe: Arc::new(WebProbe::new()),
        fingerprint: Arc::new(FingerprintEngine::new(&settings.fingerprints)),
        backend,
        meta: meta.clone(),
        cancel: cancel.clone(),
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
    print_summary(&metrics);
    Ok(())
}

use std::path::Path;

/// Refuse aliases between inputs, outputs, metrics, and state. Multiple file
/// handles aimed at one path can silently truncate the target list or replace
/// scan results with a checkpoint.
fn validate_artifact_paths(cli: &Cli, settings: &Settings) -> Result<()> {
    let mut paths: Vec<(&str, &Path)> = vec![("host JSONL", &settings.output)];
    for (label, path) in [
        ("flat JSONL", settings.flat_output.as_deref()),
        ("CSV", settings.csv.as_deref()),
        ("Nmap export", settings.export_nmap.as_deref()),
        ("URL export", settings.export_urls.as_deref()),
        ("metrics JSON", settings.metrics_json.as_deref()),
        ("checkpoint", settings.checkpoint.as_deref()),
        ("resume checkpoint", settings.resume.as_deref()),
        ("config", cli.config.as_deref()),
    ] {
        if let Some(path) = path {
            paths.push((label, path));
        }
    }
    if let Some(input) = cli.input.as_deref().filter(|path| path.as_os_str() != "-") {
        paths.push(("target input", input));
    }

    let mut seen = std::collections::HashMap::new();
    for (label, path) in paths {
        let absolute = normalized_path(path)?;
        if let Some(previous) = seen.insert(absolute, label) {
            let same_state = matches!(previous, "checkpoint" | "resume checkpoint")
                && matches!(label, "checkpoint" | "resume checkpoint");
            if !same_state {
                bail!("{label} path aliases {previous}: {}", path.display());
            }
        }
    }
    Ok(())
}

fn normalized_path(path: &Path) -> Result<std::path::PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolve artifact path {}", path.display()))?;
    if absolute.exists() {
        return std::fs::canonicalize(&absolute)
            .with_context(|| format!("canonicalize artifact path {}", path.display()));
    }
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name())
        && parent.exists()
    {
        return Ok(std::fs::canonicalize(parent)?.join(name));
    }
    Ok(absolute)
}

fn target_set_hash(targets: &[Target]) -> String {
    sha256_hex(
        targets
            .iter()
            .map(|t| format!("{}:{:?}\n", t.ip, t.known_c2_ports))
            .collect::<String>(),
    )
}

/// Provenance recorded on every output record so an archived result stays
/// interpretable without the original command line.
fn build_metadata(
    settings: &Settings,
    targets: &[Target],
    target_hash: &str,
    backend: &str,
) -> ScanMetadata {
    ScanMetadata {
        tool: "operator-surface-scanner".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        schema_version: SCHEMA_VERSION.into(),
        scan_id: scan_id(),
        scan_label: settings.scan_label.clone(),
        scan_started_at: now_rfc3339(),
        scan_mode: backend.into(),
        port_spec: settings.ports_spec.clone(),
        port_count: settings.ports.len(),
        target_count: targets.len(),
        target_set_hash: target_hash.into(),
        rate: settings.rate,
        burst: settings.burst,
        concurrency: settings.concurrency,
        probe_concurrency: settings.probe_concurrency,
        fingerprint_concurrency: settings.fingerprint_concurrency,
        host_concurrency: settings.host_concurrency,
        queue_depth: settings.queue_depth,
        tcp_timeout_ms: settings.tcp_timeout.as_millis() as u64,
        tcp_retries: settings.tcp_retries,
        tls_timeout_ms: settings.tls_timeout.as_millis() as u64,
        http_enabled: settings.http_enabled,
        https_enabled: settings.https_enabled,
        http_timeout_ms: settings.http_timeout.as_millis() as u64,
        http_body_timeout_ms: settings.http_body_timeout.as_millis() as u64,
        max_body_bytes: settings.max_body,
        tls_verification: "skipped".into(),
        resumed: settings.resume.is_some(),
        host_os: std::env::consts::OS.into(),
    }
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

fn print_summary(m: &Metrics) {
    eprintln!(
        "\nScan summary{}\nTargets                 {}\nPorts per target        {}\nHosts completed         {}\nHosts interrupted       {}\nTCP probes              {}\nOpen ports              {}\nHTTP services           {}\nHTTPS services          {}\nTLS (non-HTTP)          {}\nUnknown TCP             {}\nHFS                     {}\nDirectory listings      {}\nLogin/Admin panels      {}\nUnknown web surfaces    {}\nTCP discovery (wall)    {:.2}s\nTCP discovery (sum)     {:.2}s\nProtocol detection      {:.2}s\nFingerprint             {:.3}s\nElapsed                 {:.2}s\nTCP probe rate avg      {:.0} pps",
        if m.interrupted { " (interrupted)" } else { "" },
        m.targets,
        m.ports_per_target,
        m.hosts_completed,
        m.hosts_interrupted,
        m.tcp_probes,
        m.open_ports,
        m.http_services,
        m.https_services,
        m.tls_non_http_services,
        m.unknown_tcp_services,
        m.hfs,
        m.directory_listings,
        m.login_admin_panels,
        m.unknown_web_surfaces,
        m.tcp_discovery_wall_ms as f64 / 1000.0,
        m.tcp_discovery_ms as f64 / 1000.0,
        m.protocol_detection_ms as f64 / 1000.0,
        m.fingerprint_ms as f64 / 1000.0,
        m.elapsed_ms as f64 / 1000.0,
        m.tcp_probe_rate_avg
    )
}
