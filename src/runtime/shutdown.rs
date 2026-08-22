use tokio_util::sync::CancellationToken;

/// Watch for an operator-initiated stop and cancel the pipeline once.
///
/// Windows delivers three distinct console events; handling only Ctrl+C leaves
/// Ctrl+Break and window close to terminate the process outright, losing the
/// checkpoint and any buffered output.
pub fn watch(cancel: CancellationToken) {
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::warn!("shutdown requested; draining in-flight work");
        cancel.cancel();
        // A second signal means the operator wants out now.
        wait_for_signal().await;
        tracing::error!("second shutdown signal; exiting immediately");
        std::process::exit(130);
    });
}

#[cfg(windows)]
async fn wait_for_signal() {
    use tokio::signal::windows;
    let mut ctrl_c = match windows::ctrl_c() {
        Ok(handler) => handler,
        Err(error) => {
            tracing::warn!(%error, "cannot install Ctrl+C handler");
            return std::future::pending().await;
        }
    };
    let mut ctrl_break = windows::ctrl_break().ok();
    let mut ctrl_close = windows::ctrl_close().ok();
    let mut ctrl_shutdown = windows::ctrl_shutdown().ok();
    tokio::select! {
        _ = ctrl_c.recv() => {}
        _ = async { match &mut ctrl_break { Some(s) => { s.recv().await; }, None => std::future::pending().await } } => {}
        _ = async { match &mut ctrl_close { Some(s) => { s.recv().await; }, None => std::future::pending().await } } => {}
        _ = async { match &mut ctrl_shutdown { Some(s) => { s.recv().await; }, None => std::future::pending().await } } => {}
    }
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(handler) => handler,
        Err(error) => {
            tracing::warn!(%error, "cannot install SIGTERM handler");
            return match tokio::signal::ctrl_c().await {
                Ok(()) => (),
                Err(_) => std::future::pending().await,
            };
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(any(unix, windows)))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
