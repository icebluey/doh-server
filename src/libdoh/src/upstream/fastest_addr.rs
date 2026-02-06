use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use super::dns_packet::{contains_answer_ip, extract_answer_ips, rewrite_answer_ips_in_place};
use super::stats::{QueryStatistics, UpstreamStatistics};
use super::{exchange_single, upstream_address, validate_exchange_packet, ExchangeOutcome};
use crate::{
    connect_tcp_with_local_bind, DoH, DoHError, FastIpCacheEntry, FastIpCacheStatus,
    Upstream, UpstreamAttemptError,
};

const FASTEST_ADDR_CACHE_TTL_SECS: u64 = 10 * 60;
const FASTEST_ADDR_PING_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
const FASTEST_ADDR_PING_TCP_TIMEOUT: Duration = Duration::from_secs(4);
const FASTEST_ADDR_PING_PORTS: [u16; 2] = [80, 443];

#[derive(Debug)]
struct UpstreamReply {
    packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct PingResult {
    ip: IpAddr,
    latency_ms: u32,
    success: bool,
}

pub(super) async fn exchange_fastest_addr(
    doh: &DoH,
    query: Vec<u8>,
    upstreams: &[Upstream],
) -> ExchangeOutcome {
    let all = exchange_all(doh, query, upstreams).await;
    let query_stats = QueryStatistics::with_main(all.stats);

    if all.replies.is_empty() {
        return ExchangeOutcome {
            packet: Err(all.err.unwrap_or(DoHError::UpstreamIssue)),
            query_stats,
        };
    }

    let replies = all.replies;
    let first_packet = replies[0].packet.clone();

    let mut ip_set: HashSet<IpAddr> = HashSet::new();
    for reply in &replies {
        for ip in extract_answer_ips(&reply.packet) {
            if !ip.is_unspecified() {
                ip_set.insert(ip);
            }
        }
    }

    let ips: Vec<IpAddr> = ip_set.into_iter().collect();
    if ips.is_empty() {
        return ExchangeOutcome {
            packet: Ok(first_packet),
            query_stats,
        };
    }

    let fastest = match ping_all(doh, &ips).await {
        Some(ping) => ping.ip,
        None => {
            return ExchangeOutcome {
                packet: Ok(first_packet),
                query_stats,
            }
        }
    };

    for reply in replies {
        if contains_answer_ip(&reply.packet, fastest) {
            return ExchangeOutcome {
                packet: match filter_response_answer(reply.packet, fastest) {
                    Ok(packet) => Ok(packet),
                    Err(_) => Ok(first_packet),
                },
                query_stats,
            };
        }
    }

    ExchangeOutcome {
        packet: Ok(first_packet),
        query_stats,
    }
}

struct ExchangeAll {
    replies: Vec<UpstreamReply>,
    stats: Vec<UpstreamStatistics>,
    err: Option<DoHError>,
}

async fn exchange_all(
    doh: &DoH,
    query: Vec<u8>,
    upstreams: &[Upstream],
) -> ExchangeAll {
    if upstreams.len() == 1 {
        let started = Instant::now();
        let result = exchange_single(doh, query, &upstreams[0])
            .await
            .and_then(validate_exchange_packet);
        let duration = started.elapsed();
        let address = upstream_address(&upstreams[0]);
        let stats = vec![match &result {
            Ok(_) => UpstreamStatistics::success(address, duration),
            Err(err) => UpstreamStatistics::failure(address, duration, err.to_string()),
        }];
        return match result {
            Ok(packet) => ExchangeAll {
                replies: vec![UpstreamReply { packet }],
                stats,
                err: None,
            },
            Err(err) => ExchangeAll {
                replies: Vec::new(),
                stats,
                err: Some(err),
            },
        };
    }

    struct AttemptOutcome {
        idx: usize,
        result: Result<Vec<u8>, DoHError>,
        duration: Duration,
    }

    let (tx, mut rx) = mpsc::channel::<AttemptOutcome>(upstreams.len());
    for (idx, upstream) in upstreams.iter().cloned().enumerate() {
        let doh = doh.clone();
        let query = query.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let result = exchange_single(&doh, query, &upstream)
                .await
                .and_then(validate_exchange_packet);
            let _ = tx
                .send(AttemptOutcome {
                    idx,
                    result,
                    duration: started.elapsed(),
                })
                .await;
        });
    }
    drop(tx);

    let mut replies = Vec::with_capacity(upstreams.len());
    let mut failures: Vec<UpstreamAttemptError> = Vec::with_capacity(upstreams.len());
    let mut stats: Vec<Option<UpstreamStatistics>> = vec![None; upstreams.len()];
    for _ in 0..upstreams.len() {
        match rx.recv().await {
            Some(AttemptOutcome { idx, result, duration }) => {
                let address = upstream_address(&upstreams[idx]);
                match result {
                    Ok(packet) => {
                        replies.push(UpstreamReply { packet });
                        stats[idx] = Some(UpstreamStatistics::success(address, duration));
                    }
                    Err(err) => {
                        failures.push(UpstreamAttemptError::from_doh_error(
                            address.clone(),
                            duration,
                            &err,
                        ));
                        stats[idx] = Some(UpstreamStatistics::failure(
                            address,
                            duration,
                            err.to_string(),
                        ));
                    }
                }
            }
            None => break,
        }
    }

    ExchangeAll {
        replies,
        stats: stats.into_iter().flatten().collect(),
        err: if failures.is_empty() {
            None
        } else {
            Some(DoHError::from_upstream_attempts(failures))
        },
    }
}

fn filter_response_answer(mut packet: Vec<u8>, selected_ip: IpAddr) -> Result<Vec<u8>, DoHError> {
    rewrite_answer_ips_in_place(&mut packet, selected_ip).map_err(|_| DoHError::InvalidData)?;
    Ok(packet)
}

async fn ping_all(doh: &DoH, ips: &[IpAddr]) -> Option<PingResult> {
    match ips.len() {
        0 => return None,
        1 => {
            return Some(PingResult {
                ip: ips[0],
                latency_ms: 0,
                success: true,
            })
        }
        _ => {}
    }

    let (tx, mut rx) = mpsc::channel::<PingResult>(ips.len() * FASTEST_ADDR_PING_PORTS.len());
    let mut cached_best: Option<PingResult> = None;
    let mut scheduled = 0usize;

    for ip in ips {
        if let Some(cached) = load_fastest_cache(doh, *ip) {
            if cached.status == FastIpCacheStatus::Success
                && cached_best
                    .map(|best| cached.latency_ms < best.latency_ms)
                    .unwrap_or(true)
            {
                cached_best = Some(PingResult {
                    ip: *ip,
                    latency_ms: cached.latency_ms,
                    success: true,
                });
            }
            continue;
        }

        for port in FASTEST_ADDR_PING_PORTS {
            scheduled += 1;
            let doh = doh.clone();
            let ip = *ip;
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = ping_do_tcp(&doh, ip, port).await;
                let _ = tx.send(result).await;
            });
        }
    }
    drop(tx);

    if scheduled == 0 {
        return cached_best;
    }

    let timeout = tokio::time::sleep(FASTEST_ADDR_PING_WAIT_TIMEOUT);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => return cached_best,
            result = rx.recv() => {
                let result = match result {
                    Some(result) => result,
                    None => return cached_best,
                };
                if !result.success {
                    continue;
                }
                return match cached_best {
                    Some(cached) if cached.latency_ms < result.latency_ms => Some(cached),
                    _ => Some(result),
                };
            }
        }
    }
}

async fn ping_do_tcp(doh: &DoH, ip: IpAddr, port: u16) -> PingResult {
    let remote = SocketAddr::new(ip, port);
    let started = Instant::now();
    let connect_res = tokio::time::timeout(
        FASTEST_ADDR_PING_TCP_TIMEOUT,
        connect_tcp_with_local_bind(doh.globals.local_bind_address, remote),
    )
    .await;

    let (success, latency_ms) = match connect_res {
        Ok(Ok(stream)) => {
            drop(stream);
            (true, started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32)
        }
        _ => (
            false,
            started
                .elapsed()
                .as_millis()
                .min(u128::from(u32::MAX)) as u32,
        ),
    };

    let cache_ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    };
    if success {
        store_fastest_success(doh, cache_ip, latency_ms);
    } else {
        store_fastest_failure(doh, cache_ip);
    }

    PingResult {
        ip,
        latency_ms,
        success,
    }
}

fn load_fastest_cache(doh: &DoH, ip: IpAddr) -> Option<FastIpCacheEntry> {
    let now = now_millis();
    let mut guard = doh
        .globals
        .fastest_ip_cache
        .lock()
        .expect("fastest ip cache mutex poisoned");
    guard.get(ip, now)
}

fn store_fastest_failure(doh: &DoH, ip: IpAddr) {
    let now = now_millis();
    let expire_at_ms = now.saturating_add(FASTEST_ADDR_CACHE_TTL_SECS.saturating_mul(1000));
    let mut guard = doh
        .globals
        .fastest_ip_cache
        .lock()
        .expect("fastest ip cache mutex poisoned");
    if guard.get(ip, now).is_some() {
        return;
    }
    guard.upsert(
        ip,
        FastIpCacheEntry {
            status: FastIpCacheStatus::Failure,
            latency_ms: 0,
            expire_at_ms,
        },
    );
}

fn store_fastest_success(doh: &DoH, ip: IpAddr, latency_ms: u32) {
    let now = now_millis();
    let expire_at_ms = now.saturating_add(FASTEST_ADDR_CACHE_TTL_SECS.saturating_mul(1000));
    let mut guard = doh
        .globals
        .fastest_ip_cache
        .lock()
        .expect("fastest ip cache mutex poisoned");
    let should_replace = match guard.get(ip, now) {
        None => true,
        Some(existing) if existing.status == FastIpCacheStatus::Failure => true,
        Some(existing) => latency_ms < existing.latency_ms,
    };
    if should_replace {
        guard.upsert(
            ip,
            FastIpCacheEntry {
                status: FastIpCacheStatus::Success,
                latency_ms,
                expire_at_ms,
            },
        );
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
