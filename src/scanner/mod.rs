use crate::{cli::ScanMode, config::Settings};
use anyhow::Result;
use async_trait::async_trait;
use futures::{StreamExt, stream::FuturesUnordered};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::Mutex,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

#[async_trait]
pub trait ScannerBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn discover(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        cancel: &CancellationToken,
    ) -> Result<Vec<u16>>;
}

pub async fn backend(settings: &Settings) -> Result<Box<dyn ScannerBackend>> {
    match settings.scan_mode {
        ScanMode::Connect => Ok(Box::new(ConnectScanner::new(settings))),
        ScanMode::Syn => {
            #[cfg(target_os = "linux")]
            {
                Ok(Box::new(raw_syn::RawSynScanner::new(settings)?))
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

pub struct ConnectScanner {
    concurrency: usize,
    timeout: Duration,
    retries: u32,
    limiter: Arc<TokenBucket>,
}
impl ConnectScanner {
    pub fn new(s: &Settings) -> Self {
        Self {
            concurrency: s.concurrency,
            timeout: s.tcp_timeout,
            retries: s.tcp_retries,
            limiter: Arc::new(TokenBucket::new(s.rate, s.burst)),
        }
    }
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
    ) -> Result<Vec<u16>> {
        let mut work = FuturesUnordered::new();
        let mut next = 0;
        let mut open = vec![];
        while next < ports.len() || !work.is_empty() {
            while next < ports.len() && work.len() < self.concurrency && !cancel.is_cancelled() {
                let port = ports[next];
                next += 1;
                let limiter = self.limiter.clone();
                let duration = self.timeout;
                let retries = self.retries;
                work.push(async move {
                    limiter.acquire().await;
                    for attempt in 0..=retries {
                        if timeout(duration, TcpStream::connect(SocketAddr::from((ip, port))))
                            .await
                            .is_ok_and(|r| r.is_ok())
                        {
                            return Some(port);
                        }
                        if attempt < retries {
                            limiter.acquire().await;
                        }
                    }
                    None
                });
            }
            if cancel.is_cancelled() {
                break;
            }
            if let Some(Some(port)) = work.next().await {
                open.push(port)
            }
        }
        open.sort_unstable();
        Ok(open)
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
}
