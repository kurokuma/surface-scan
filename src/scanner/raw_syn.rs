use super::{ScannerBackend, TokenBucket};
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
    sync::{Arc, Mutex},
    thread,
    time::Duration,
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
        if unsafe { libc::geteuid() } != 0 {
            tracing::warn!("raw SYN generally requires root or CAP_NET_RAW");
        }
        Ok(Self {
            rate: s.rate,
            burst: s.burst,
            timeout: s.tcp_timeout,
            retries: s.tcp_retries,
        })
    }
}

#[derive(Clone, Copy)]
struct Outstanding {
    seq: u32,
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
    ) -> Result<Vec<u16>> {
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
) -> Result<Vec<u16>> {
    let source = source_ip(target)?;
    let source_port = 49152u16.wrapping_add((std::process::id() % 16000) as u16);
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, mut rx) = transport_channel(65535, protocol)
        .context("initialize raw IPv4/TCP channel (root or CAP_NET_RAW required)")?;
    let outstanding = Arc::new(Mutex::new(HashMap::<u16, Outstanding>::new()));
    let open = Arc::new(Mutex::new(HashMap::<u16, u32>::new()));
    let receiver_out = outstanding.clone();
    let receiver_open = open.clone();
    let receiver = thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            match iter.next_with_timeout(Duration::from_millis(100)) {
                Ok(Some((packet, _))) => {
                    if packet.get_source() != target || packet.get_destination() != source {
                        continue;
                    }
                    if let Some(tcp) = TcpPacket::new(packet.payload()) {
                        if tcp.get_destination() != source_port {
                            continue;
                        }
                        let flags = tcp.get_flags();
                        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                            let port = tcp.get_source();
                            let valid = receiver_out
                                .lock()
                                .ok()
                                .and_then(|m| m.get(&port).copied())
                                .is_some_and(|o| {
                                    tcp.get_acknowledgement() == o.seq.wrapping_add(1)
                                });
                            if valid {
                                if let Ok(mut s) = receiver_open.lock() {
                                    s.insert(port, tcp.get_sequence());
                                }
                                if let Ok(mut m) = receiver_out.lock() {
                                    m.remove(&port);
                                }
                            }
                        }
                    }
                }
                Ok(None) => {
                    if receiver_out.lock().map(|m| m.is_empty()).unwrap_or(true) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let runtime = tokio::runtime::Handle::current();
    let limiter = TokenBucket::new(rate, burst);
    for attempt in 0..=retries {
        for &port in ports {
            if cancel.is_cancelled() {
                break;
            }
            if open.lock().map(|s| s.contains_key(&port)).unwrap_or(false) {
                continue;
            }
            runtime.block_on(limiter.acquire());
            let seq = sequence(target, port, attempt);
            outstanding
                .lock()
                .unwrap()
                .insert(port, Outstanding { seq });
            let packet = make_packet(source, target, source_port, port, seq, 0, TcpFlags::SYN);
            if let Err(error) = tx.send_to(Ipv4Packet::new(&packet).unwrap(), IpAddr::V4(target)) {
                outstanding.lock().unwrap().remove(&port);
                return Err(error.into());
            }
        }
        thread::sleep(timeout);
        if cancel.is_cancelled() {
            break;
        }
    }
    outstanding.lock().unwrap().clear();
    let _ = receiver.join();
    let responses = open.lock().unwrap().clone();
    for (&port, &remote_seq) in &responses {
        let rst = make_packet(
            source,
            target,
            source_port,
            port,
            0,
            remote_seq.wrapping_add(1),
            TcpFlags::RST | TcpFlags::ACK,
        );
        let _ = tx.send_to(Ipv4Packet::new(&rst).unwrap(), IpAddr::V4(target));
    }
    let mut result: Vec<_> = responses.keys().copied().collect();
    result.sort_unstable();
    Ok(result)
}
fn source_ip(target: Ipv4Addr) -> Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(SocketAddr::from((target, 9)))?;
    match s.local_addr()?.ip() {
        IpAddr::V4(v) => Ok(v),
        _ => bail!("IPv4 source route unavailable"),
    }
}
fn sequence(ip: Ipv4Addr, port: u16, attempt: u32) -> u32 {
    u32::from(ip).rotate_left(7) ^ (port as u32).rotate_left(16) ^ attempt ^ 0x5a17_ace1
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
