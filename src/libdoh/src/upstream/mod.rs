pub(crate) mod dns_packet;
pub(crate) mod msg;
pub(crate) mod rr_types;
pub(crate) mod stats;
mod fastest_addr;
mod load_balance;
mod parallel;

use self::dns_packet::query_qtype;
use self::rr_types::RrType;
use self::stats::QueryStatistics;
use crate::{DoH, DoHError, Upstream, UpstreamMode};

pub(crate) struct ExchangeOutcome {
    pub packet: Result<Vec<u8>, DoHError>,
    pub query_stats: QueryStatistics,
}

pub(crate) async fn exchange(doh: &DoH, query: Vec<u8>) -> ExchangeOutcome {
    let upstreams = &doh.globals.upstreams;
    if upstreams.is_empty() {
        return ExchangeOutcome {
            packet: Err(DoHError::UpstreamIssue),
            query_stats: QueryStatistics::default(),
        };
    }

    match doh.globals.upstream_mode {
        UpstreamMode::Parallel => parallel::exchange_parallel(doh, query, upstreams).await,
        UpstreamMode::FastestAddr => {
            let qtype = query_qtype(&query);
            if matches!(qtype, Some(RrType::A) | Some(RrType::AAAA)) {
                fastest_addr::exchange_fastest_addr(doh, query, upstreams).await
            } else {
                load_balance::exchange_load_balance(doh, query, upstreams).await
            }
        }
        UpstreamMode::LoadBalance => load_balance::exchange_load_balance(doh, query, upstreams).await,
    }
}

pub(super) async fn exchange_single(
    doh: &DoH,
    query: Vec<u8>,
    upstream: &Upstream,
) -> Result<Vec<u8>, DoHError> {
    match upstream {
        Upstream::Dns(server_address) => {
            doh.run_with_timeout(doh.proxy_dns_udp_tcp(query, *server_address))
                .await
        }
        Upstream::Doh(doh_upstream) => doh.proxy_doh(query, doh_upstream).await,
        Upstream::Dot(dot_upstream) => {
            doh.run_with_timeout(doh.proxy_dot(query, dot_upstream)).await
        }
    }
}

pub(super) fn validate_exchange_packet(packet: Vec<u8>) -> Result<Vec<u8>, DoHError> {
    if dns_packet::validate_response_packet(&packet) {
        Ok(packet)
    } else {
        Err(DoHError::UpstreamIssue)
    }
}

pub(super) fn upstream_address(upstream: &Upstream) -> String {
    match upstream {
        Upstream::Dns(addr) => addr.to_string(),
        Upstream::Doh(doh) => doh.url.as_str().to_string(),
        Upstream::Dot(dot) => format!("tls://{}:{}", dot.host, dot.port),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::exchange;
    use crate::odoh::ODoHRotator;
    use crate::{
        ClientsCount, DoH, DoHError, FastestIpCache, Globals, Upstream, UpstreamMode,
        UpstreamRttStats,
    };

    fn dns_query_a() -> Vec<u8> {
        vec![
            0x12, 0x34, // ID
            0x01, 0x00, // RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x00, // root name
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ]
    }

    fn dns_response_ok() -> Vec<u8> {
        vec![
            0x12, 0x34, // ID
            0x81, 0x80, // QR + RD + RA
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x00, // root name
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ]
    }

    fn build_test_doh(mode: UpstreamMode, upstreams: Vec<Upstream>, timeout: Duration) -> DoH {
        let runtime_handle = tokio::runtime::Handle::current();
        let odoh_rotator =
            Arc::new(ODoHRotator::new(runtime_handle.clone()).expect("odoh rotator init"));
        let globals = Globals {
            #[cfg(feature = "tls")]
            tls_cert_path: None,
            #[cfg(feature = "tls")]
            tls_cert_key_path: None,
            listen_addresses: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            local_bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            bootstrap_dns: Vec::new(),
            upstreams,
            upstream_mode: mode,
            upstream_rtt_stats: Arc::new(StdMutex::new(HashMap::<String, UpstreamRttStats>::new())),
            fastest_ip_cache: Arc::new(StdMutex::new(FastestIpCache::default())),
            path: "/dns-query".to_string(),
            max_clients: 1024,
            timeout,
            clients_count: ClientsCount::default(),
            max_concurrent_streams: 128,
            min_ttl: 0,
            max_ttl: u32::MAX,
            err_ttl: 0,
            keepalive: true,
            disable_post: false,
            allow_odoh_post: false,
            enable_ecs: false,
            ecs_prefix_v4: 24,
            ecs_prefix_v6: 56,
            odoh_configs_path: "/odohconfigs".to_string(),
            odoh_rotator,
            runtime_handle,
        };

        DoH {
            globals: Arc::new(globals),
            remote_addr: None,
        }
    }

    async fn spawn_udp_responder(response: Vec<u8>) -> SocketAddr {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind responder");
        let addr = socket.local_addr().expect("responder addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((_, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let _ = socket.send_to(&response, peer).await;
            }
        });
        addr
    }

    async fn spawn_udp_blackhole() -> SocketAddr {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind blackhole");
        let addr = socket.local_addr().expect("blackhole addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                if socket.recv_from(&mut buf).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn load_balance_success_returns_single_main_stat() {
        let ok = spawn_udp_responder(dns_response_ok()).await;
        let bad = spawn_udp_blackhole().await;
        let doh = build_test_doh(
            UpstreamMode::LoadBalance,
            vec![Upstream::Dns(ok), Upstream::Dns(bad)],
            Duration::from_millis(120),
        );

        let outcome = exchange(&doh, dns_query_a()).await;
        assert!(outcome.packet.is_ok(), "load_balance should succeed");
        assert_eq!(outcome.query_stats.main().len(), 1);
        assert!(outcome.query_stats.main()[0].error.is_none());
        assert!(outcome.query_stats.fallback().is_empty());
    }

    #[tokio::test]
    async fn load_balance_all_fail_returns_joined_error_and_all_stats() {
        let bad1 = spawn_udp_blackhole().await;
        let bad2 = spawn_udp_blackhole().await;
        let doh = build_test_doh(
            UpstreamMode::LoadBalance,
            vec![Upstream::Dns(bad1), Upstream::Dns(bad2)],
            Duration::from_millis(80),
        );

        let outcome = exchange(&doh, dns_query_a()).await;
        assert_eq!(outcome.query_stats.main().len(), 2);
        assert!(outcome.query_stats.main().iter().all(|s| s.error.is_some()));
        match outcome.packet.expect_err("must fail") {
            DoHError::UpstreamJoined(errs) => assert_eq!(errs.len(), 2),
            other => panic!("unexpected error type: {}", other),
        }
    }

    #[tokio::test]
    async fn parallel_success_returns_single_main_stat() {
        let ok = spawn_udp_responder(dns_response_ok()).await;
        let bad = spawn_udp_blackhole().await;
        let doh = build_test_doh(
            UpstreamMode::Parallel,
            vec![Upstream::Dns(ok), Upstream::Dns(bad)],
            Duration::from_millis(120),
        );

        let outcome = exchange(&doh, dns_query_a()).await;
        assert!(outcome.packet.is_ok(), "parallel should succeed");
        assert_eq!(outcome.query_stats.main().len(), 1);
        assert!(outcome.query_stats.main()[0].error.is_none());
        assert!(outcome.query_stats.fallback().is_empty());
    }

    #[tokio::test]
    async fn parallel_all_fail_returns_joined_error_and_all_stats() {
        let bad1 = spawn_udp_blackhole().await;
        let bad2 = spawn_udp_blackhole().await;
        let doh = build_test_doh(
            UpstreamMode::Parallel,
            vec![Upstream::Dns(bad1), Upstream::Dns(bad2)],
            Duration::from_millis(80),
        );

        let outcome = exchange(&doh, dns_query_a()).await;
        assert_eq!(outcome.query_stats.main().len(), 2);
        assert!(outcome.query_stats.main().iter().all(|s| s.error.is_some()));
        match outcome.packet.expect_err("must fail") {
            DoHError::UpstreamJoined(errs) => assert_eq!(errs.len(), 2),
            other => panic!("unexpected error type: {}", other),
        }
    }

    #[tokio::test]
    async fn fastest_addr_success_keeps_all_main_stats() {
        let ok = spawn_udp_responder(dns_response_ok()).await;
        let bad = spawn_udp_blackhole().await;
        let doh = build_test_doh(
            UpstreamMode::FastestAddr,
            vec![Upstream::Dns(ok), Upstream::Dns(bad)],
            Duration::from_millis(120),
        );

        let outcome = exchange(&doh, dns_query_a()).await;
        assert!(outcome.packet.is_ok(), "fastest_addr should succeed");
        assert_eq!(outcome.query_stats.main().len(), 2);
        assert!(outcome.query_stats.main().iter().any(|s| s.error.is_none()));
        assert!(outcome.query_stats.main().iter().any(|s| s.error.is_some()));
        assert!(outcome.query_stats.fallback().is_empty());
    }

    #[tokio::test]
    async fn fastest_addr_all_fail_returns_joined_error_and_all_stats() {
        let bad1 = spawn_udp_blackhole().await;
        let bad2 = spawn_udp_blackhole().await;
        let doh = build_test_doh(
            UpstreamMode::FastestAddr,
            vec![Upstream::Dns(bad1), Upstream::Dns(bad2)],
            Duration::from_millis(80),
        );

        let outcome = exchange(&doh, dns_query_a()).await;
        assert_eq!(outcome.query_stats.main().len(), 2);
        assert!(outcome.query_stats.main().iter().all(|s| s.error.is_some()));
        match outcome.packet.expect_err("must fail") {
            DoHError::UpstreamJoined(errs) => assert_eq!(errs.len(), 2),
            other => panic!("unexpected error type: {}", other),
        }
    }
}
