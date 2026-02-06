use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::runtime;
use url::Url;

use crate::odoh::ODoHRotator;
use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;

pub type DohH2Client = HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Debug)]
pub struct Globals {
    #[cfg(feature = "tls")]
    pub tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    pub tls_cert_key_path: Option<PathBuf>,

    pub listen_addresses: Vec<SocketAddr>,
    pub local_bind_address: SocketAddr,
    pub bootstrap_dns: Vec<SocketAddr>,
    pub upstreams: Vec<Upstream>,
    pub upstream_mode: UpstreamMode,
    pub upstream_rtt_stats: Arc<StdMutex<HashMap<String, UpstreamRttStats>>>,
    pub fastest_ip_cache: Arc<StdMutex<FastestIpCache>>,
    pub path: String,
    pub max_clients: usize,
    pub timeout: Duration,
    pub clients_count: ClientsCount,
    pub max_concurrent_streams: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    pub enable_ecs: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,

    pub runtime_handle: runtime::Handle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamMode {
    LoadBalance,
    Parallel,
    FastestAddr,
}

impl UpstreamMode {
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "load_balance" => Some(Self::LoadBalance),
            "parallel" => Some(Self::Parallel),
            "fastest_addr" => Some(Self::FastestAddr),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UpstreamRttStats {
    pub rtt_sum_us: f64,
    pub req_num: f64,
}

impl UpstreamRttStats {
    pub fn update(self, rtt: Duration) -> Self {
        Self {
            rtt_sum_us: self.rtt_sum_us + (rtt.as_micros() as f64),
            req_num: self.req_num + 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastIpCacheStatus {
    Success,
    Failure,
}

#[derive(Clone, Copy, Debug)]
pub struct FastIpCacheEntry {
    pub status: FastIpCacheStatus,
    pub latency_ms: u32,
    pub expire_at_ms: u64,
}

pub const FASTEST_IP_CACHE_MAX_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct FastIpCacheNode {
    entry: FastIpCacheEntry,
    prev: Option<IpAddr>,
    next: Option<IpAddr>,
}

#[derive(Debug)]
pub struct FastestIpCache {
    max_size: usize,
    head: Option<IpAddr>,
    tail: Option<IpAddr>,
    entries: HashMap<IpAddr, FastIpCacheNode>,
}

impl FastestIpCache {
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            max_size: max_size.max(1),
            head: None,
            tail: None,
            entries: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: IpAddr, now_ms: u64) -> Option<FastIpCacheEntry> {
        let node = self.entries.get(&key).copied()?;
        if node.entry.expire_at_ms <= now_ms {
            let _ = self.remove(key);
            return None;
        }
        self.move_to_front(key);
        Some(node.entry)
    }

    pub fn upsert(&mut self, key: IpAddr, entry: FastIpCacheEntry) {
        if let Some(node) = self.entries.get_mut(&key) {
            node.entry = entry;
            self.move_to_front(key);
            return;
        }

        let old_head = self.head;
        self.entries.insert(
            key,
            FastIpCacheNode {
                entry,
                prev: None,
                next: old_head,
            },
        );
        if let Some(h) = old_head {
            if let Some(head_node) = self.entries.get_mut(&h) {
                head_node.prev = Some(key);
            }
        } else {
            self.tail = Some(key);
        }
        self.head = Some(key);
        self.evict_if_needed();
    }

    pub fn remove(&mut self, key: IpAddr) -> Option<FastIpCacheEntry> {
        let node = self.entries.get(&key).copied()?;
        self.detach(key, node.prev, node.next);
        self.entries.remove(&key).map(|n| n.entry)
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.max_size {
            let Some(tail) = self.tail else {
                break;
            };
            let _ = self.remove(tail);
        }
    }

    fn move_to_front(&mut self, key: IpAddr) {
        if self.head == Some(key) {
            return;
        }
        let Some(node) = self.entries.get(&key).copied() else {
            return;
        };

        self.detach(key, node.prev, node.next);
        let old_head = self.head;

        if let Some(current) = self.entries.get_mut(&key) {
            current.prev = None;
            current.next = old_head;
        }

        if let Some(h) = old_head {
            if let Some(head_node) = self.entries.get_mut(&h) {
                head_node.prev = Some(key);
            }
        } else {
            self.tail = Some(key);
        }
        self.head = Some(key);
    }

    fn detach(&mut self, key: IpAddr, prev: Option<IpAddr>, next: Option<IpAddr>) {
        if let Some(p) = prev {
            if let Some(prev_node) = self.entries.get_mut(&p) {
                prev_node.next = next;
            }
        } else {
            self.head = next;
        }

        if let Some(n) = next {
            if let Some(next_node) = self.entries.get_mut(&n) {
                next_node.prev = prev;
            }
        } else {
            self.tail = prev;
        }

        if let Some(current) = self.entries.get_mut(&key) {
            current.prev = None;
            current.next = None;
        }
    }
}

impl Default for FastestIpCache {
    fn default() -> Self {
        Self::with_max_size(FASTEST_IP_CACHE_MAX_SIZE)
    }
}

#[derive(Clone, Debug)]
pub enum Upstream {
    Dns(SocketAddr),
    Doh(DohUpstream),
    Dot(DotUpstream),
}

#[derive(Clone, Debug)]
pub struct DohUpstream {
    pub url: Url,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub authority: String,
    pub h3_only: bool,
    pub protocol_hint: Arc<AtomicU8>,
    pub h3_failures: Arc<AtomicU32>,
    pub h3_last_failure_ms: Arc<AtomicU64>,
    pub h3_backoff_until_ms: Arc<AtomicU64>,
    pub h2_last_rebuild_ms: Arc<AtomicU64>,
    pub h3_last_rebuild_ms: Arc<AtomicU64>,
    pub h2_client: Arc<ArcSwapOption<DohH2Client>>,
    pub h2_target_addr: Arc<StdMutex<Option<SocketAddr>>>,
}

#[derive(Clone, Debug)]
pub struct DotUpstream {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    pub fn current(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0
                && self
                    .0
                    .compare_exchange(count, count - 1, Ordering::Relaxed, Ordering::Relaxed)
                    != Ok(count)
        } {}
        count
    }
}
