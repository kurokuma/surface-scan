use super::{DiscoveryOutcome, Pacer, ScannerBackend};
use crate::config::Settings;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use pnet::{
    packet::{
        MutablePacket, Packet,
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum},
        tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum as tcp_checksum},
    },
    transport::{TransportChannelType, ipv4_packet_iter, transport_channel},
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub struct RawSynScanner {
    rate: u64,
    burst: u64,
    timeout: Duration,
    retries: u32,
}
impl RawSynScanner {
    pub fn new(s: &Settings) -> Result<Self> {
        // Capability/socket initialization is a fatal configuration error per
        // spec section 30. Probe it before the pipeline starts so it cannot be
        // mistaken for one recoverable target failure.
        let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
        let _ = transport_channel(4096, protocol)
            .context("initialize raw IPv4/TCP channel (root or CAP_NET_RAW required)")?;
        Ok(Self {
            rate: s.rate,
            burst: s.burst,
            timeout: s.tcp_timeout,
            retries: s.tcp_retries,
        })
    }
}

/// One in-flight SYN awaiting a reply.
#[derive(Clone, Copy)]
struct Outstanding {
    seq: u32,
    /// Wall clock after which the probe is abandoned, so the table cannot grow
    /// without bound over a full 65535-port sweep.
    expires_at: Instant,
}

#[async_trait]
impl ScannerBackend for RawSynScanner {
    fn name(&self) -> &'static str {
        "syn"
    }
    async fn discover(
        &self,
        target: Ipv4Addr,
        ports: &[u16],
        cancel: &CancellationToken,
    ) -> Result<DiscoveryOutcome> {
        let rate = self.rate;
        let burst = self.burst;
        let timeout = self.timeout;
        let retries = self.retries;
        let ports = ports.to_vec();
        let cancel = cancel.clone();
        tokio::task::spawn_blocking(move || {
            run_raw(target, &ports, rate, burst, timeout, retries, &cancel)
        })
        .await?
    }
}

fn run_raw(
    target: Ipv4Addr,
    ports: &[u16],
    rate: u64,
    burst: u64,
    timeout: Duration,
    retries: u32,
    cancel: &CancellationToken,
) -> Result<DiscoveryOutcome> {
    let source = source_ip(target)?;
    let source_port = 49152u16.wrapping_add((std::process::id() % 16000) as u16);
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, mut rx) = transport_channel(65535, protocol)
        .context("initialize raw IPv4/TCP channel (root or CAP_NET_RAW required)")?;
    let outstanding = Arc::new(Mutex::new(HashMap::<u16, Outstanding>::new()));
    // Remote and local sequence numbers are both retained so the RST/ACK that
    // closes a discovered half-open connection is valid in both directions.
    let open = Arc::new(Mutex::new(HashMap::<u16, (u32, u32)>::new()));
    let closed = Arc::new(Mutex::new(std::collections::HashSet::<u16>::new()));
    // The receiver runs until the sender says it is done, rather than guessing
    // from an empty table: at startup the table is legitimately empty.
    let sending_done = Arc::new(AtomicBool::new(false));

    let receiver_out = outstanding.clone();
    let receiver_open = open.clone();
    let receiver_closed = closed.clone();
    let receiver_done = sending_done.clone();
    let receiver = thread::spawn(move || -> std::io::Result<()> {
        let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            match iter.next_with_timeout(Duration::from_millis(100)) {
                Ok(Some((packet, _))) => {
                    if packet.get_source() != target || packet.get_destination() != source {
                        continue;
                    }
                    let Some(tcp) = TcpPacket::new(packet.payload()) else {
                        continue;
                    };
                    if tcp.get_destination() != source_port {
                        continue;
                    }
                    let flags = tcp.get_flags();
                    let port = tcp.get_source();
                    let expected = receiver_out
                        .lock()
                        .ok()
                        .and_then(|m| m.get(&port).copied())
                        .filter(|o| tcp.get_acknowledgement() == o.seq.wrapping_add(1));
                    if expected.is_none() {
                        // Unsolicited or already-answered: suppress duplicates.
                        continue;
                    }
                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        if let Ok(mut s) = receiver_open.lock() {
                            s.insert(port, (tcp.get_sequence(), expected.unwrap().seq));
                        }
                    } else if flags & TcpFlags::RST != 0 {
                        if let Ok(mut s) = receiver_closed.lock() {
                            s.insert(port);
                        }
                    } else {
                        continue;
                    }
                    if let Ok(mut m) = receiver_out.lock() {
                        m.remove(&port);
                    }
                }
                Ok(None) => {
                    if receiver_done.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }
        Ok(())
    });

    let mut pacer = Pacer::new(rate, burst);
    let mut send_errors = 0u64;
    let mut probes_sent = 0u64;
    let mut sent_ports = std::collections::HashSet::<u16>::new();
    let mut interrupted = false;
    'attempts: for _attempt in 0..=retries {
        for &port in ports {
            if cancel.is_cancelled() {
                interrupted = true;
                break;
            }
            if open.lock().map(|s| s.contains_key(&port)).unwrap_or(false)
                || closed.lock().map(|s| s.contains(&port)).unwrap_or(false)
            {
                continue;
            }
            pacer.tick();
            // Stable per (host, port) across retries so a late reply to an
            // earlier attempt still validates instead of being discarded.
            let seq = sequence(target, port);
            if let Ok(mut table) = outstanding.lock() {
                if table.len() >= 4096 {
                    let now = Instant::now();
                    table.retain(|_, probe| probe.expires_at > now);
                }
                table.insert(
                    port,
                    Outstanding {
                        seq,
                        expires_at: Instant::now() + timeout,
                    },
                );
            }
            let packet = make_packet(source, target, source_port, port, seq, 0, TcpFlags::SYN);
            match tx.send_to(Ipv4Packet::new(&packet).unwrap(), IpAddr::V4(target)) {
                Ok(_) => {
                    probes_sent += 1;
                    sent_ports.insert(port);
                }
                Err(error) => {
                    // A send failure is a per-probe event, not a scan failure:
                    // ENOBUFS is routine at high packet rates (spec section 30).
                    if let Ok(mut table) = outstanding.lock() {
                        table.remove(&port);
                    }
                    send_errors += 1;
                    if send_errors == 1 || send_errors.is_multiple_of(1000) {
                        tracing::warn!(%error, port, count = send_errors, "raw SYN send failed");
                    }
                }
            }
        }
        if interrupted {
            break;
        }
        // Give the last packets of this round time to be answered.
        let wait_until = Instant::now() + timeout;
        while Instant::now() < wait_until {
            if cancel.is_cancelled() {
                interrupted = true;
                break;
            }
            let remaining = wait_until.saturating_duration_since(Instant::now());
            thread::sleep(Duration::from_millis(20).min(remaining));
            let resolved = open.lock().map(|s| s.len()).unwrap_or(0)
                + closed.lock().map(|s| s.len()).unwrap_or(0);
            if resolved == ports.len() {
                break 'attempts;
            }
        }
        if interrupted {
            break;
        }
    }
    sending_done.store(true, Ordering::Relaxed);
    if let Ok(mut table) = outstanding.lock() {
        table.clear();
    }
    receiver
        .join()
        .map_err(|_| anyhow::anyhow!("raw SYN receiver thread panicked"))??;

    let responses = open.lock().map(|m| m.clone()).unwrap_or_default();
    // Tear down the half-open connections we created.
    for (&port, &(remote_seq, local_seq)) in &responses {
        let rst = make_packet(
            source,
            target,
            source_port,
            port,
            local_seq.wrapping_add(1),
            remote_seq.wrapping_add(1),
            TcpFlags::RST | TcpFlags::ACK,
        );
        let _ = tx.send_to(Ipv4Packet::new(&rst).unwrap(), IpAddr::V4(target));
    }
    if send_errors > 0 {
        tracing::warn!(
            errors = send_errors,
            "raw SYN probes dropped locally before transmission"
        );
    }
    let mut result: Vec<_> = responses.keys().copied().collect();
    result.sort_unstable();
    let all_ports_sent = sent_ports.len() == ports.len();
    Ok(DiscoveryOutcome {
        open: result,
        attempted: sent_ports.len(),
        probes_sent,
        complete: !interrupted && all_ports_sent,
    })
}

fn source_ip(target: Ipv4Addr) -> Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(SocketAddr::from((target, 9)))?;
    match s.local_addr()?.ip() {
        IpAddr::V4(v) => Ok(v),
        _ => bail!("IPv4 source route unavailable"),
    }
}

fn sequence(ip: Ipv4Addr, port: u16) -> u32 {
    u32::from(ip).rotate_left(7) ^ (port as u32).rotate_left(16) ^ 0x5a17_ace1
}

fn make_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    {
        let mut ip = MutableIpv4Packet::new(&mut bytes).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        {
            let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(ack);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
            tcp.set_window(64240);
            tcp.set_checksum(tcp_checksum(&tcp.to_immutable(), &src, &dst));
        }
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    bytes
}
