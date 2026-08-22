use crate::{cli::ScanMode, config::Settings};
use anyhow::Result;
use async_trait::async_trait;
use futures::{StreamExt, stream::FuturesUnordered};
use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

/// Result of discovering one host.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOutcome {
    pub open: Vec<u16>,
    /// Ports the backend actually reached a verdict on.
    pub attempted: usize,
    /// Probes placed on the wire, including retries.
    pub probes_sent: u64,
    /// False when shutdown cut the sweep short. Such a host is never
    /// checkpointed as completed.
    pub complete: bool,
}

#[async_trait]
pub trait ScannerBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn discover(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        cancel: &CancellationToken,
    ) -> Result<DiscoveryOutcome>;
}

pub async fn backend(settings: &Settings) -> Result<Arc<dyn ScannerBackend>> {
    match settings.scan_mode {
        ScanMode::Connect => Ok(Arc::new(ConnectScanner::new(settings))),
        ScanMode::Syn => {
            #[cfg(target_os = "linux")]
            {
                Ok(Arc::new(raw_syn::RawSynScanner::new(settings)?))
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("raw SYN mode is supported only on Linux; use --scan-mode connect")
            }
        }
    }
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last: Instant,
}

/// Async token bucket shared by every host so `--rate` is a process-wide limit.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    state: Mutex<BucketState>,
}
impl TokenBucket {
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate: rate as f64,
            burst: burst as f64,
            state: Mutex::new(BucketState {
                tokens: burst as f64,
                last: Instant::now(),
            }),
        }
    }
    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut s = self.state.lock().await;
                let now = Instant::now();
                s.tokens = (s.tokens + now.duration_since(s.last).as_secs_f64() * self.rate)
                    .min(self.burst);
                s.last = now;
                if s.tokens >= 1.0 {
                    s.tokens -= 1.0;
                    None
                } else {
                    Some(Duration::from_secs_f64((1.0 - s.tokens) / self.rate))
                }
            };
            if let Some(d) = wait {
                sleep(d).await
            } else {
                return;
            }
        }
    }
}

/// Blocking pacer for the raw sender, which runs off the async runtime.
///
/// The async bucket would need a `block_on` per packet; at tens of thousands of
/// packets per second that overhead is the bottleneck.
#[derive(Debug)]
pub struct Pacer {
    interval: Duration,
    burst: u64,
    sent: u64,
    started: Instant,
}
impl Pacer {
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / rate.max(1) as f64),
            burst: burst.max(1),
            sent: 0,
            started: Instant::now(),
        }
    }
    /// Block until the next packet may go out, allowing `burst` packets to run
    /// ahead of schedule.
    pub fn tick(&mut self) {
        self.sent += 1;
        if self.sent <= self.burst {
            return;
        }
        let due = self
            .interval
            .saturating_mul((self.sent - self.burst) as u32);
        let elapsed = self.started.elapsed();
        if due > elapsed {
            std::thread::sleep(due - elapsed);
        }
    }
}

pub struct ConnectScanner {
    /// Per-host in-flight cap; total sockets are capped globally by `sockets`.
    per_host_inflight: usize,
    sockets: Arc<Semaphore>,
    timeout: Duration,
    retries: u32,
    limiter: Arc<TokenBucket>,
}
impl ConnectScanner {
    pub fn new(s: &Settings) -> Self {
        Self {
            per_host_inflight: s.concurrency.div_ceil(s.host_concurrency).max(32),
            sockets: Arc::new(Semaphore::new(s.concurrency)),
            timeout: s.tcp_timeout,
            retries: s.tcp_retries,
            limiter: Arc::new(TokenBucket::new(s.rate, s.burst)),
        }
    }
}

/// Verdict for one connect attempt.
enum Attempt {
    Open,
    /// The peer answered with RST: retrying cannot change the answer.
    Closed,
    /// No answer, or a transient local error: worth retrying.
    Filtered,
}

#[async_trait]
impl ScannerBackend for ConnectScanner {
    fn name(&self) -> &'static str {
        "connect"
    }
    async fn discover(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        cancel: &CancellationToken,
    ) -> Result<DiscoveryOutcome> {
        let mut work = FuturesUnordered::new();
        let mut next = 0;
        let mut open = vec![];
        let mut attempted = 0usize;
        // Counted per call so parallel hosts do not inflate each other.
        let probes = Arc::new(AtomicU64::new(0));
        while next < ports.len() || !work.is_empty() {
            while next < ports.len() && work.len() < self.per_host_inflight {
                if cancel.is_cancelled() {
                    break;
                }
                let port = ports[next];
                next += 1;
                let limiter = self.limiter.clone();
                let sockets = self.sockets.clone();
                let probes = probes.clone();
                let duration = self.timeout;
                let retries = self.retries;
                work.push(async move {
                    let address = SocketAddr::from((ip, port));
                    for attempt in 0..=retries {
                        limiter.acquire().await;
                        let permit = sockets.acquire().await.expect("socket semaphore closed");
                        probes.fetch_add(1, Ordering::Relaxed);
                        let verdict = match timeout(duration, TcpStream::connect(address)).await {
                            Ok(Ok(_)) => Attempt::Open,
                            Ok(Err(e))
                                if matches!(
                                    e.kind(),
                                    ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
                                ) =>
                            {
                                Attempt::Closed
                            }
                            Ok(Err(_)) => Attempt::Filtered,
                            Err(_) => Attempt::Filtered,
                        };
                        drop(permit);
                        match verdict {
                            Attempt::Open => return Some(port),
                            // A refusal is a definitive answer, so stop early
                            // rather than spending the retry budget on it.
                            Attempt::Closed => return None,
                            Attempt::Filtered if attempt == retries => return None,
                            Attempt::Filtered => {}
                        }
                    }
                    None
                });
            }
            if work.is_empty() {
                break;
            }
            match work.next().await {
                Some(result) => {
                    attempted += 1;
                    if let Some(port) = result {
                        open.push(port);
                    }
                }
                None => break,
            }
            if cancel.is_cancelled() && next < ports.len() {
                // Stop queueing new ports but let in-flight attempts finish so
                // their results are not thrown away.
                next = ports.len();
            }
        }
        open.sort_unstable();
        let complete = attempted == ports.len();
        Ok(DiscoveryOutcome {
            open,
            attempted,
            probes_sent: probes.load(Ordering::Relaxed),
            complete,
        })
    }
}

#[cfg(target_os = "linux")]
mod raw_syn;

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn token_bucket_allows_progress() {
        let b = TokenBucket::new(1000, 1);
        b.acquire().await;
        b.acquire().await;
    }
    #[test]
    fn pacer_lets_the_burst_through_immediately() {
        let mut pacer = Pacer::new(10, 5);
        let started = Instant::now();
        for _ in 0..5 {
            pacer.tick();
        }
        assert!(started.elapsed() < Duration::from_millis(50));
    }
}
