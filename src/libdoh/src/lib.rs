mod constants;
pub mod dns;
mod dns_json;
mod edns_ecs;
mod errors;
mod globals;
pub mod odoh;
mod upstream;
#[cfg(feature = "tls")]
mod tls;

use std::env;
use std::collections::HashMap;
use std::error::Error;
use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::Engine;
use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use futures::future::join_all;
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::http;
use hyper::body::Body;
use hyper::body::Incoming;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_rustls::{FixedServerNameResolver, HttpsConnectorBuilder};
use hyper_util::client::legacy::Error as HyperLegacyError;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioTimer;
use hyper_util::server::conn::auto;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::{
    ClientH3Controller, ClientH3Driver, ClientH3Event, ClientRequestSender, H3ConnectionError,
    H3Event, InboundFrameStream, IncomingH3Headers, InboundFrame, NewClientRequest, OutboundFrame,
    OutboundFrameSender, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::{
    connect_with_config,
    SimpleConnectionIdGenerator,
};
use tokio_quiche::quiche::h3::{self, NameValue};
use tokio_quiche::{ConnectionParams, ServerH3Controller, ServerH3Driver};

use rustls_platform_verifier::BuilderVerifierExt;

use crate::constants::*;
pub use crate::errors::*;
pub use crate::globals::*;
use crate::upstream::stats::QueryStatistics;

pub mod reexports {
    pub use tokio;
}

const BASE64_URL_SAFE_NO_PAD: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

static H3_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static DOT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
static DOH_H3_POOLS: OnceLock<StdMutex<HashMap<String, Arc<DohH3Pool>>>> = OnceLock::new();
static BOOTSTRAP_RESOLVER_CACHE: OnceLock<StdMutex<HashMap<BootstrapCacheKey, BootstrapCacheEntry>>> =
    OnceLock::new();
const DOH_PROTO_UNKNOWN: u8 = 0;
const DOH_PROTO_H2: u8 = 1;
const DOH_PROTO_H3: u8 = 2;
const DOH_REQUEST_RETRY_LIMIT: usize = 2;
const DOH_H3_POOL_SIZE: usize = 2;
const DOH_H3_MAX_INFLIGHT_PER_CONN: usize = 64;
const DOH_MIN_REBUILD_INTERVAL_MS: u64 = 1000;
const DOH_PROBE_TLS_TIMEOUT_SECS: u64 = 10;
const DOH_H2_IDLE_CONN_TIMEOUT_SECS: u64 = 300;
const DOH_H2_READ_IDLE_TIMEOUT_SECS: u64 = 30;
const DOH_H2_MAX_IDLE_CONNS_PER_HOST: usize = 2;
const H3_SUPERVISOR_RESTART_DELAY_MS: u64 = 500;
const H3_FAILURE_THRESHOLD: u32 = 3;
const H3_FAILURE_WINDOW_SECS: u64 = 60;
const H3_BACKOFF_SECS: u64 = 30;
const BOOTSTRAP_DNS_FLAG_QR: u16 = 0x8000;
const BOOTSTRAP_DNS_CLASS_IN: u16 = 1;
const BOOTSTRAP_DNS_TYPE_A: u16 = 1;
const BOOTSTRAP_DNS_TYPE_AAAA: u16 = 28;

#[derive(Debug)]
struct H3Failure {
    err: DoHError,
    retryable: bool,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct BootstrapCacheKey {
    resolver: SocketAddr,
    host: String,
}

#[derive(Clone, Debug)]
struct BootstrapCacheEntry {
    addrs: Vec<IpAddr>,
    expire_at_ms: u64,
}

#[derive(Clone, Debug)]
struct BootstrapDnsResult {
    addrs: Vec<IpAddr>,
    min_ttl_secs: u32,
}

#[derive(Debug)]
struct H2Failure {
    err: DoHError,
    retryable: bool,
}

impl H2Failure {
    fn new(err: DoHError, retryable: bool) -> Self {
        Self { err, retryable }
    }

    fn from_doh_error(err: DoHError) -> Self {
        let retryable = is_retryable_doh_error(&err);
        Self::new(err, retryable)
    }

    fn from_hyper_legacy_error(err: HyperLegacyError) -> Self {
        let retryable = is_retryable_h2_client_error(&err);
        let timeout = err
            .source()
            .and_then(|source| source.downcast_ref::<hyper::Error>())
            .map(|source| source.is_timeout())
            .unwrap_or(false);
        let doh_error = if timeout {
            DoHError::UpstreamTimeout
        } else {
            DoHError::UpstreamIssue
        };
        Self::new(doh_error, retryable)
    }

    fn from_hyper_error(err: hyper::Error) -> Self {
        let retryable = is_retryable_hyper_error(&err);
        let doh_error = if err.is_timeout() {
            DoHError::UpstreamTimeout
        } else {
            DoHError::UpstreamIssue
        };
        Self::new(doh_error, retryable)
    }
}

impl H3Failure {
    fn new(err: DoHError, retryable: bool) -> Self {
        Self { err, retryable }
    }

    fn retryable(err: DoHError) -> Self {
        Self::new(err, true)
    }

    fn from_doh_error(err: DoHError) -> Self {
        let retryable = is_retryable_doh_error(&err);
        Self { err, retryable }
    }

    fn from_io(err: io::Error) -> Self {
        let retryable = is_retryable_io_error(&err);
        Self {
            err: DoHError::Io(err),
            retryable,
        }
    }

    fn from_boxed_sync(err: Box<dyn Error + Send + Sync + 'static>) -> Self {
        let retryable = is_retryable_quic_error(err.as_ref());
        match err.downcast::<io::Error>() {
            Ok(io_err) => Self {
                err: DoHError::Io(*io_err),
                retryable,
            },
            Err(_) => Self {
                err: DoHError::UpstreamIssue,
                retryable,
            },
        }
    }

    fn from_send_error<E>(err: E) -> Self
    where
        E: Error + Send + 'static,
    {
        let err_ref: &(dyn Error + 'static) = &err;
        let retryable = is_retryable_std_error(err_ref);
        if let Some(io_err) = err_ref.downcast_ref::<io::Error>() {
            return Self {
                err: DoHError::Io(io::Error::new(io_err.kind(), io_err.to_string())),
                retryable,
            };
        }
        Self {
            err: DoHError::UpstreamIssue,
            retryable,
        }
    }
}

#[derive(Default)]
struct DohH3Pending {
    by_request: HashMap<u64, oneshot::Sender<Result<Vec<u8>, H3Failure>>>,
    by_stream: HashMap<u64, u64>,
}

struct DohH3Client {
    _conn: Box<dyn std::any::Any + Send + Sync>,
    request_sender: ClientRequestSender,
    pending: Arc<Mutex<DohH3Pending>>,
    slot: Arc<Semaphore>,
}

struct PendingH3RequestGuard {
    pending: Arc<Mutex<DohH3Pending>>,
    request_id: u64,
    active: bool,
}

impl PendingH3RequestGuard {
    fn new(pending: Arc<Mutex<DohH3Pending>>, request_id: u64) -> Self {
        Self {
            pending,
            request_id,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for PendingH3RequestGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let pending = Arc::clone(&self.pending);
        let request_id = self.request_id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                clear_pending_h3_request(&pending, request_id).await;
            });
        }
    }
}

impl std::fmt::Debug for DohH3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohH3Client").finish_non_exhaustive()
    }
}

impl DohH3Client {
    fn try_acquire_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.slot.clone().try_acquire_owned().ok()
    }

    async fn acquire_slot(&self) -> OwnedSemaphorePermit {
        self.slot
            .clone()
            .acquire_owned()
            .await
            .expect("h3 client semaphore closed unexpectedly")
    }

    async fn request(
        &self,
        _slot: OwnedSemaphorePermit,
        upstream: &DohUpstream,
        query: &[u8],
    ) -> Result<Vec<u8>, H3Failure> {
        let request_id = H3_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let (body_sender, body_sender_rx) = oneshot::channel::<OutboundFrameSender>();
        let (result_tx, result_rx) = oneshot::channel::<Result<Vec<u8>, H3Failure>>();
        {
            let mut pending = self.pending.lock().await;
            pending.by_request.insert(request_id, result_tx);
        }
        let mut cleanup = PendingH3RequestGuard::new(Arc::clone(&self.pending), request_id);

        let length_value = query.len().to_string();
        let headers = vec![
            h3::Header::new(b":method", b"POST"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", upstream.authority.as_bytes()),
            h3::Header::new(b":path", upstream.path.as_bytes()),
            h3::Header::new(b"content-type", b"application/dns-message"),
            h3::Header::new(b"accept", b"application/dns-message"),
            h3::Header::new(b"content-length", length_value.as_bytes()),
        ];

        if let Err(err) = self.request_sender.send(NewClientRequest {
            request_id,
            headers,
            body_writer: Some(body_sender),
        }) {
            return Err(H3Failure::from_send_error(err));
        }

        let mut outbound = match body_sender_rx.await {
            Ok(outbound) => outbound,
            Err(err) => {
                return Err(H3Failure::from_send_error(err));
            }
        };
        if let Err(err) = outbound
            .send(OutboundFrame::body(BufFactory::buf_from_slice(query), true))
            .await
        {
            return Err(H3Failure::from_send_error(err));
        }

        let result = match result_rx.await {
            Ok(result) => result,
            Err(_) => Err(H3Failure::retryable(DoHError::UpstreamIssue)),
        };
        cleanup.disarm();
        result
    }

    fn close_if_idle(&self) {
        // Dropping the client closes the underlying QUIC connection.
    }

    fn start_event_loop(mut controller: ClientH3Controller, pending: Arc<Mutex<DohH3Pending>>) {
        tokio::spawn(async move {
            let mut body_tasks = futures::stream::FuturesUnordered::new();

            loop {
                tokio::select! {
                    maybe_body = body_tasks.next(), if !body_tasks.is_empty() => {
                        if let Some((stream_id, result)) = maybe_body {
                            complete_pending_h3_stream(&pending, stream_id, result).await;
                        }
                    }
                    maybe_event = controller.event_receiver_mut().recv() => {
                        let event = match maybe_event {
                            Some(event) => event,
                            None => break,
                        };
                        match event {
                            ClientH3Event::NewOutboundRequest {
                                stream_id,
                                request_id,
                            } => {
                                let mut state = pending.lock().await;
                                if state.by_request.contains_key(&request_id) {
                                    state.by_stream.insert(stream_id, request_id);
                                }
                            }
                            ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
                                stream_id,
                                headers,
                                recv,
                                ..
                            })) => {
                                let status = headers
                                    .iter()
                                    .find(|header| header.name() == b":status")
                                    .and_then(|header| std::str::from_utf8(header.value()).ok())
                                    .and_then(|value| value.parse::<u16>().ok())
                                    .unwrap_or(500);
                                if status != 200 {
                                    complete_pending_h3_stream(
                                        &pending,
                                        stream_id,
                                        Err(H3Failure::new(DoHError::UpstreamIssue, false)),
                                    )
                                    .await;
                                    continue;
                                }
                                body_tasks.push(read_h3_response_body(stream_id, recv));
                            }
                            ClientH3Event::Core(H3Event::ConnectionError(err)) => {
                                let retryable = is_retryable_h3_error(&err);
                                fail_all_pending_h3_requests(&pending, retryable).await;
                                return;
                            }
                            ClientH3Event::Core(H3Event::ConnectionShutdown(reason)) => {
                                let retryable = reason
                                    .as_ref()
                                    .map(is_retryable_h3_connection_error)
                                    .unwrap_or(true);
                                fail_all_pending_h3_requests(&pending, retryable).await;
                                return;
                            }
                            ClientH3Event::Core(H3Event::ResetStream { stream_id })
                            | ClientH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                                complete_pending_h3_stream(
                                    &pending,
                                    stream_id,
                                    Err(H3Failure::retryable(DoHError::UpstreamIssue)),
                                )
                                .await;
                            }
                            _ => {}
                        }
                    }
                }
            }
            fail_all_pending_h3_requests(&pending, true).await;
        });
    }
}

async fn read_h3_response_body(
    stream_id: u64,
    mut recv: InboundFrameStream,
) -> (u64, Result<Vec<u8>, H3Failure>) {
    let mut response_body = Vec::new();
    let mut seen_fin = false;
    while let Some(frame) = recv.recv().await {
        if let InboundFrame::Body(data, fin) = frame {
            response_body.extend_from_slice(&data);
            if fin {
                seen_fin = true;
                break;
            }
        }
    }
    if !seen_fin {
        return (
            stream_id,
            Err(H3Failure::retryable(DoHError::UpstreamIssue)),
        );
    }
    (stream_id, Ok(response_body))
}

async fn clear_pending_h3_request(pending: &Arc<Mutex<DohH3Pending>>, request_id: u64) {
    let mut state = pending.lock().await;
    state.by_request.remove(&request_id);
    state.by_stream.retain(|_, rid| *rid != request_id);
}

async fn complete_pending_h3_stream(
    pending: &Arc<Mutex<DohH3Pending>>,
    stream_id: u64,
    result: Result<Vec<u8>, H3Failure>,
) {
    let maybe_sender = {
        let mut state = pending.lock().await;
        let request_id = match state.by_stream.remove(&stream_id) {
            Some(request_id) => request_id,
            None => return,
        };
        state.by_request.remove(&request_id)
    };
    if let Some(sender) = maybe_sender {
        let _ = sender.send(result);
    }
}

async fn fail_all_pending_h3_requests(pending: &Arc<Mutex<DohH3Pending>>, retryable: bool) {
    let senders: Vec<oneshot::Sender<Result<Vec<u8>, H3Failure>>> = {
        let mut state = pending.lock().await;
        state.by_stream.clear();
        state.by_request.drain().map(|(_, sender)| sender).collect()
    };
    for sender in senders {
        let _ = sender.send(Err(H3Failure::new(DoHError::UpstreamIssue, retryable)));
    }
}

struct DohH3Pool {
    clients: StdMutex<Vec<Arc<DohH3Client>>>,
    next: AtomicU64,
}

impl DohH3Pool {
    fn new() -> Self {
        Self {
            clients: StdMutex::new(Vec::new()),
            next: AtomicU64::new(0),
        }
    }

    fn has_clients(&self) -> bool {
        !self
            .clients
            .lock()
            .expect("doh h3 pool mutex poisoned")
            .is_empty()
    }

    fn needs_new_client(&self) -> bool {
        self.clients
            .lock()
            .expect("doh h3 pool mutex poisoned")
            .len()
            < DOH_H3_POOL_SIZE
    }

    fn pick_client(&self) -> Option<Arc<DohH3Client>> {
        let guard = self.clients.lock().expect("doh h3 pool mutex poisoned");
        if guard.is_empty() {
            return None;
        }
        let idx = (self.next.fetch_add(1, Ordering::Relaxed) as usize) % guard.len();
        guard.get(idx).cloned()
    }

    fn try_pick_client_with_slot(&self) -> Option<(Arc<DohH3Client>, OwnedSemaphorePermit)> {
        let guard = self.clients.lock().expect("doh h3 pool mutex poisoned");
        if guard.is_empty() {
            return None;
        }

        let start = (self.next.fetch_add(1, Ordering::Relaxed) as usize) % guard.len();
        for offset in 0..guard.len() {
            let idx = (start + offset) % guard.len();
            let client = guard[idx].clone();
            if let Some(slot) = client.try_acquire_slot() {
                return Some((client, slot));
            }
        }

        None
    }

    fn add_or_pick(
        &self,
        candidate: Arc<DohH3Client>,
    ) -> (Arc<DohH3Client>, bool) {
        let mut guard = self.clients.lock().expect("doh h3 pool mutex poisoned");
        if guard.len() < DOH_H3_POOL_SIZE {
            guard.push(candidate.clone());
            return (candidate, true);
        }
        let idx = (self.next.fetch_add(1, Ordering::Relaxed) as usize) % guard.len();
        (guard[idx].clone(), false)
    }

    fn drain_clients(&self) -> Vec<Arc<DohH3Client>> {
        let mut guard = self.clients.lock().expect("doh h3 pool mutex poisoned");
        std::mem::take(&mut *guard)
    }
}

#[derive(Clone, Debug)]
struct DnsResponse {
    packet: Vec<u8>,
    ttl: u32,
    query_stats: QueryStatistics,
}

#[derive(Clone, Debug)]
struct H3Response {
    status: StatusCode,
    content_type: String,
    body: Vec<u8>,
    cache_control: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DoHType {
    Standard,
    Oblivious,
    Json,
}

impl DoHType {
    fn as_str(&self) -> &'static str {
        match self {
            DoHType::Standard => "application/dns-message",
            DoHType::Oblivious => "application/oblivious-dns-message",
            DoHType::Json => "application/dns-json",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DoH {
    pub globals: Arc<Globals>,
    pub remote_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub(crate) struct ServerConfig {
    keepalive: bool,
    max_concurrent_streams: u32,
}

impl ServerConfig {
    fn build(&self) -> auto::Builder<TokioExecutor> {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder.http1().keep_alive(self.keepalive);
        builder
            .http2()
            .max_concurrent_streams(self.max_concurrent_streams);
        builder
    }
}

#[allow(clippy::unnecessary_wraps)]
fn http_error(status_code: StatusCode) -> Result<Response<Full<Bytes>>, http::Error> {
    let response = Response::builder()
        .status(status_code)
        .body(Full::new(Bytes::new()))
        .unwrap();
    Ok(response)
}

#[allow(clippy::unnecessary_wraps)]
fn http_error_with_cache(status_code: StatusCode) -> Result<Response<Full<Bytes>>, http::Error> {
    // Return error with very long cache time (1 year) to prevent crawler bots from retrying
    let response = Response::builder()
        .status(status_code)
        .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
        .body(Full::new(Bytes::new()))
        .unwrap();
    Ok(response)
}

fn dot_tls_config() -> Result<Arc<ClientConfig>, DoHError> {
    if let Some(config) = DOT_TLS_CONFIG.get() {
        return Ok(config.clone());
    }
    let config = ClientConfig::builder()
        .with_platform_verifier()
        .map_err(|_| DoHError::UpstreamIssue)?
        .with_no_client_auth();
    let _ = DOT_TLS_CONFIG.set(Arc::new(config));
    Ok(DOT_TLS_CONFIG
        .get()
        .expect("DOT_TLS_CONFIG must be initialized")
        .clone())
}

async fn dns_exchange_over_stream<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>, DoHError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if query.len() > u16::MAX as usize {
        return Err(DoHError::TooLarge);
    }
    let mut len_buf = [0u8; 2];
    BigEndian::write_u16(&mut len_buf, query.len() as u16);
    stream.write_all(&len_buf).await.map_err(DoHError::Io)?;
    stream.write_all(query).await.map_err(DoHError::Io)?;
    stream.flush().await.map_err(DoHError::Io)?;
    stream.read_exact(&mut len_buf).await.map_err(DoHError::Io)?;
    let packet_len = BigEndian::read_u16(&len_buf) as usize;
    if !(MIN_DNS_PACKET_LEN..=MAX_DNS_RESPONSE_LEN).contains(&packet_len) {
        return Err(DoHError::UpstreamIssue);
    }
    let mut packet = vec![0u8; packet_len];
    stream.read_exact(&mut packet).await.map_err(DoHError::Io)?;
    Ok(packet)
}

#[allow(clippy::type_complexity)]
impl hyper::service::Service<http::Request<Incoming>> for DoH {
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<Full<Bytes>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let globals = &self.globals;
        let self_inner = self.clone();
        if req.uri().path() == globals.path {
            match *req.method() {
                Method::POST => Box::pin(async move { self_inner.serve_post(req).await }),
                Method::GET => Box::pin(async move { self_inner.serve_get(req).await }),
                _ => Box::pin(async { http_error(StatusCode::METHOD_NOT_ALLOWED) }),
            }
        } else if req.uri().path() == globals.odoh_configs_path {
            match *req.method() {
                Method::GET => Box::pin(async move { self_inner.serve_odoh_configs().await }),
                _ => Box::pin(async { http_error(StatusCode::METHOD_NOT_ALLOWED) }),
            }
        } else {
            Box::pin(async { http_error(StatusCode::NOT_FOUND) })
        }
    }
}

impl DoH {
    async fn serve_get(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, http::Error> {
        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_get(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_get(req).await,
            Ok(DoHType::Json) => self.serve_json_get(req).await,
            Err(response) => Ok(*response),
        }
    }

    async fn serve_post(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, http::Error> {
        match Self::parse_content_type(&req) {
            Ok(DoHType::Standard) => self.serve_doh_post(req).await,
            Ok(DoHType::Oblivious) => self.serve_odoh_post(req).await,
            Ok(DoHType::Json) => http_error(StatusCode::METHOD_NOT_ALLOWED),
            Err(response) => Ok(*response),
        }
    }

    async fn serve_doh_query(
        &self,
        query: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        let resp = match self.proxy(query, client_ip).await {
            Ok(resp) => {
                let _ = resp.query_stats.main();
                self.build_response(resp.packet, resp.ttl, DoHType::Standard.as_str(), true)
            }
            Err(e) => return http_error(StatusCode::from(e)),
        };
        match resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    fn query_from_query_string(&self, req: Request<Incoming>) -> Option<Vec<u8>> {
        let http_query = req.uri().query().unwrap_or("");
        let mut question_str = None;
        for parts in http_query.split('&') {
            let mut kv = parts.split('=');
            if let Some(k) = kv.next() {
                if k == DNS_QUERY_PARAM {
                    question_str = kv.next();
                }
            }
        }
        if let Some(question_str) = question_str {
            if question_str.len() > MAX_DNS_QUESTION_LEN * 4 / 3 {
                return None;
            }
        }
        let query = match question_str
            .and_then(|question_str| BASE64_URL_SAFE_NO_PAD.decode(question_str).ok())
        {
            Some(query) => query,
            _ => return None,
        };
        Some(query)
    }

    async fn serve_doh_get(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        let client_ip = if self.globals.enable_ecs {
            edns_ecs::extract_client_ip(req.headers(), self.remote_addr)
        } else {
            None
        };

        let query = match self.query_from_query_string(req) {
            Some(query) => query,
            _ => return http_error_with_cache(StatusCode::BAD_REQUEST),
        };
        self.serve_doh_query(query, client_ip).await
    }

    async fn serve_doh_post(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        if self.globals.disable_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }

        let client_ip = if self.globals.enable_ecs {
            edns_ecs::extract_client_ip(req.headers(), self.remote_addr)
        } else {
            None
        };

        let query = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_doh_query(query, client_ip).await
    }

    async fn serve_odoh(
        &self,
        encrypted_query: Vec<u8>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
        let (query, context) = match (*odoh_public_key).clone().decrypt_query(encrypted_query) {
            Ok((q, context)) => (q.to_vec(), context),
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let resp = match self.proxy(query, None).await {
            Ok(resp) => resp,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        let _ = resp.query_stats.main();
        let encrypted_resp = match context.encrypt_response(resp.packet) {
            Ok(resp) => self.build_response(resp, 0u32, DoHType::Oblivious.as_str(), false),
            Err(e) => return http_error(StatusCode::from(e)),
        };

        match encrypted_resp {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_odoh_get(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        let encrypted_query = match self.query_from_query_string(req) {
            Some(encrypted_query) => encrypted_query,
            _ => return http_error_with_cache(StatusCode::BAD_REQUEST),
        };
        self.serve_odoh(encrypted_query).await
    }

    async fn serve_odoh_post(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        if self.globals.disable_post && !self.globals.allow_odoh_post {
            return http_error(StatusCode::METHOD_NOT_ALLOWED);
        }
        let encrypted_query = match self.read_body(req.into_body()).await {
            Ok(q) => q,
            Err(e) => return http_error(StatusCode::from(e)),
        };
        self.serve_odoh(encrypted_query).await
    }

    async fn serve_odoh_configs(&self) -> Result<Response<Full<Bytes>>, http::Error> {
        let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
        let configs = (*odoh_public_key).clone().into_config();
        match self.build_response(
            configs,
            ODOH_KEY_ROTATION_SECS,
            "application/octet-stream",
            true,
        ) {
            Ok(resp) => Ok(resp),
            Err(e) => http_error(StatusCode::from(e)),
        }
    }

    async fn serve_json_get(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, http::Error> {
        let query_params = req.uri().query().unwrap_or("");
        let client_ip = if self.globals.enable_ecs {
            edns_ecs::extract_client_ip(req.headers(), self.remote_addr)
        } else {
            None
        };

        let response = match self.serve_json_query(query_params, client_ip).await {
            Ok(response) => response,
            Err(e) => return http_error(StatusCode::from(e)),
        };

        let mut builder = Response::builder()
            .status(response.status)
            .header(hyper::header::CONTENT_TYPE, response.content_type.as_str());
        if let Some(cache_control) = response.cache_control {
            builder = builder.header(hyper::header::CACHE_CONTROL, cache_control);
        }
        builder
            .header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Full::new(Bytes::from(response.body)))
            .or_else(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR))
    }

    async fn serve_json_query(
        &self,
        query_params: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<H3Response, DoHError> {
        use serde_json::json;

        // Parse query parameters
        let mut json_query = dns_json::DnsJsonQuery {
            name: String::new(),
            qtype: None,
            cd: None,
            ct: None,
            do_: None,
            edns_client_subnet: None,
        };

        // Parse query string
        for parts in query_params.split('&') {
            let mut kv = parts.split('=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                match k {
                    "name" => {
                        json_query.name = urlencoding::decode(v).unwrap_or_default().into_owned()
                    }
                    "type" => json_query.qtype = v.parse().ok(),
                    "cd" => json_query.cd = Some(v == "1" || v == "true"),
                    "ct" => json_query.ct = Some(v.to_string()),
                    "do" => json_query.do_ = Some(v == "1" || v == "true"),
                    "edns_client_subnet" => json_query.edns_client_subnet = Some(v.to_string()),
                    _ => {}
                }
            }
        }

        // Validate query
        if json_query.name.is_empty() {
            let error_response = json!({
                "Status": 400,
                "Comment": "Missing 'name' parameter"
            });
            return Ok(H3Response {
                status: StatusCode::BAD_REQUEST,
                content_type: DoHType::Json.as_str().to_string(),
                body: error_response.to_string().into_bytes(),
                cache_control: None,
            });
        }

        // Build DNS query packet
        let query_packet = match dns_json::build_dns_query(&json_query) {
            Ok(packet) => packet,
            Err(e) => {
                let error_response = json!({
                    "Status": 400,
                    "Comment": format!("Invalid query: {}", e)
                });
                return Ok(H3Response {
                    status: StatusCode::BAD_REQUEST,
                    content_type: DoHType::Json.as_str().to_string(),
                    body: error_response.to_string().into_bytes(),
                    cache_control: None,
                });
            }
        };

        let dns_response = self.proxy(query_packet, client_ip).await?;
        let _ = dns_response.query_stats.main();

        // Parse DNS response to JSON
        match dns_json::parse_dns_to_json(&dns_response.packet) {
            Ok(json_response) => {
                let json_string =
                    serde_json::to_string(&json_response).map_err(|_| DoHError::InvalidData)?;
                Ok(H3Response {
                    status: StatusCode::OK,
                    content_type: DoHType::Json.as_str().to_string(),
                    body: json_string.into_bytes(),
                    cache_control: Some(format!(
                        "max-age={}, stale-if-error={}, stale-while-revalidate={}",
                        dns_response.ttl, STALE_IF_ERROR_SECS, STALE_WHILE_REVALIDATE_SECS
                    )),
                })
            }
            Err(e) => {
                let error_response = json!({
                    "Status": 500,
                    "Comment": format!("Failed to parse DNS response: {}", e)
                });
                Ok(H3Response {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    content_type: DoHType::Json.as_str().to_string(),
                    body: error_response.to_string().into_bytes(),
                    cache_control: None,
                })
            }
        }
    }

    fn acceptable_content_type(
        headers: &HeaderMap,
        content_types: &[&'static str],
    ) -> Option<&'static str> {
        let accept = headers.get(hyper::header::ACCEPT);
        let accept = accept?;
        for part in accept.to_str().unwrap_or("").split(',').map(|s| s.trim()) {
            if let Some(found) = part
                .split(';')
                .next()
                .map(|s| s.trim().to_ascii_lowercase())
            {
                if let Some(&content_type) = content_types
                    .iter()
                    .find(|&&content_type| content_type == found)
                {
                    return Some(content_type);
                }
            }
        }
        None
    }

    fn parse_content_type(
        req: &Request<Incoming>,
    ) -> Result<DoHType, Box<Response<Full<Bytes>>>> {
        const CT_DOH: &str = "application/dns-message";
        const CT_ODOH: &str = "application/oblivious-dns-message";
        const CT_JSON: &str = "application/dns-json";

        let headers = req.headers();
        let content_type = match headers.get(hyper::header::CONTENT_TYPE) {
            None => {
                let acceptable_content_type =
                    Self::acceptable_content_type(headers, &[CT_DOH, CT_ODOH, CT_JSON]);
                match acceptable_content_type {
                    None => {
                        // Return NOT_ACCEPTABLE with long cache time for crawler bots
                        let response = Response::builder()
                            .status(StatusCode::NOT_ACCEPTABLE)
                            .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                        return Err(Box::new(response));
                    }
                    Some(content_type) => content_type,
                }
            }
            Some(content_type) => match content_type.to_str() {
                Err(_) => {
                    // Return BAD_REQUEST with long cache time for invalid content type
                    let response = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
                        .body(Full::new(Bytes::new()))
                        .unwrap();
                    return Err(Box::new(response));
                }
                Ok(content_type) => content_type,
            },
        };

        match content_type.to_ascii_lowercase().as_str() {
            CT_DOH => Ok(DoHType::Standard),
            CT_ODOH => Ok(DoHType::Oblivious),
            CT_JSON => Ok(DoHType::Json),
            _ => {
                // Return UNSUPPORTED_MEDIA_TYPE with long cache time
                let response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .header(hyper::header::CACHE_CONTROL, "max-age=31536000, immutable")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                Err(Box::new(response))
            }
        }
    }

    fn parse_h3_content_type(
        content_type: Option<&str>,
        accept: Option<&str>,
    ) -> Result<DoHType, StatusCode> {
        const CT_DOH: &str = "application/dns-message";
        const CT_ODOH: &str = "application/oblivious-dns-message";
        const CT_JSON: &str = "application/dns-json";

        let content_type = match content_type {
            Some(value) => value.to_string(),
            None => {
                let accept = accept.ok_or(StatusCode::NOT_ACCEPTABLE)?;
                let mut found = None;
                for part in accept.split(',').map(|s| s.trim()) {
                    if let Some(found_ct) = part
                        .split(';')
                        .next()
                        .map(|s| s.trim().to_ascii_lowercase())
                    {
                        if [CT_DOH, CT_ODOH, CT_JSON].contains(&found_ct.as_str()) {
                            found = Some(found_ct);
                            break;
                        }
                    }
                }
                match found {
                    Some(ct) => ct,
                    None => return Err(StatusCode::NOT_ACCEPTABLE),
                }
            }
        };

        let content_type = content_type
            .split(';')
            .next()
            .unwrap_or(content_type.as_str())
            .trim();
        match content_type.to_ascii_lowercase().as_str() {
            CT_DOH => Ok(DoHType::Standard),
            CT_ODOH => Ok(DoHType::Oblivious),
            CT_JSON => Ok(DoHType::Json),
            _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
        }
    }

    fn query_from_path(&self, path: &str) -> Option<Vec<u8>> {
        let http_query = path.split('?').nth(1).unwrap_or("");
        let mut question_str = None;
        for parts in http_query.split('&') {
            let mut kv = parts.split('=');
            if let Some(k) = kv.next() {
                if k == DNS_QUERY_PARAM {
                    question_str = kv.next();
                }
            }
        }
        if let Some(question_str) = question_str {
            if question_str.len() > MAX_DNS_QUESTION_LEN * 4 / 3 {
                return None;
            }
        }
        let query = match question_str
            .and_then(|question_str| BASE64_URL_SAFE_NO_PAD.decode(question_str).ok())
        {
            Some(query) => query,
            _ => return None,
        };
        Some(query)
    }

    async fn read_body(&self, body: Incoming) -> Result<Vec<u8>, DoHError> {
        if let Some(upper) = body.size_hint().upper() {
            if upper >= MAX_DNS_QUESTION_LEN as u64 {
                return Err(DoHError::TooLarge);
            }
        }
        let collected = body.collect().await.map_err(|_| DoHError::TooLarge)?;
        let bytes = collected.to_bytes();
        if bytes.len() >= MAX_DNS_QUESTION_LEN {
            return Err(DoHError::TooLarge);
        }
        Ok(bytes.to_vec())
    }

    async fn proxy(
        &self,
        query: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Result<DnsResponse, DoHError> {
        self._proxy(query, client_ip).await
    }

    async fn _proxy(
        &self,
        mut query: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Result<DnsResponse, DoHError> {
        if query.len() < MIN_DNS_PACKET_LEN {
            return Err(DoHError::Incomplete);
        }
        let _ = dns::set_edns_max_payload_size(&mut query, MAX_DNS_RESPONSE_LEN as _);

        // Add EDNS Client Subnet if enabled and we have a client IP
        if self.globals.enable_ecs {
            if let Some(client_ip) = client_ip {
                if let Err(e) = edns_ecs::add_ecs_to_packet(
                    &mut query,
                    client_ip,
                    self.globals.ecs_prefix_v4,
                    self.globals.ecs_prefix_v6,
                ) {
                    eprintln!("Failed to add EDNS Client Subnet: {}", e);
                }
            }
        }
        let globals = &self.globals;
        let outcome = upstream::exchange(self, query).await;
        let mut packet = outcome.packet?;
        let query_stats = outcome.query_stats;
        let (min_ttl, max_ttl, err_ttl) = (globals.min_ttl, globals.max_ttl, globals.err_ttl);

        let ttl = if dns::is_recoverable_error(&packet) {
            err_ttl
        } else {
            match dns::min_ttl(&packet, min_ttl, max_ttl, err_ttl) {
                Err(_) => return Err(DoHError::UpstreamIssue),
                Ok(ttl) => ttl,
            }
        };
        dns::add_edns_padding(&mut packet)
            .map_err(|_| DoHError::TooLarge)
            .ok();
        Ok(DnsResponse {
            packet,
            ttl,
            query_stats,
        })
    }

    async fn run_with_timeout<T>(
        &self,
        fut: impl Future<Output = Result<T, DoHError>>,
    ) -> Result<T, DoHError> {
        let timeout = self.globals.timeout;
        if timeout == Duration::ZERO {
            fut.await
        } else {
            tokio::time::timeout(timeout, fut)
                .await
                .map_err(|_| DoHError::UpstreamTimeout)?
        }
    }

    async fn proxy_dns_udp_tcp(
        &self,
        query: Vec<u8>,
        server_address: SocketAddr,
    ) -> Result<Vec<u8>, DoHError> {
        let globals = &self.globals;
        let mut packet = vec![0; MAX_DNS_RESPONSE_LEN];

        // UDP
        {
            let socket = UdpSocket::bind(&globals.local_bind_address)
                .await
                .map_err(DoHError::Io)?;
            let expected_server_address = server_address;
            socket
                .send_to(&query, &server_address)
                .await
                .map_err(DoHError::Io)?;
            let (len, response_server_address) = socket
                .recv_from(&mut packet)
                .await
                .map_err(DoHError::Io)?;
            if len < MIN_DNS_PACKET_LEN || expected_server_address != response_server_address {
                return Err(DoHError::UpstreamIssue);
            }
            packet.truncate(len);
        }

        // TCP
        if dns::is_truncated(&packet) {
            let clients_count = self.globals.clients_count.current();
            if self.globals.max_clients >= UDP_TCP_RATIO
                && clients_count >= self.globals.max_clients / UDP_TCP_RATIO
            {
                return Err(DoHError::TooManyTcpSessions);
            }
            let mut ext_socket = connect_tcp_with_local_bind(globals.local_bind_address, server_address)
                .await
                .map_err(DoHError::Io)?;
            ext_socket.set_nodelay(true).map_err(DoHError::Io)?;
            let mut binlen = [0u8, 0];
            BigEndian::write_u16(&mut binlen, query.len() as u16);
            ext_socket.write_all(&binlen).await.map_err(DoHError::Io)?;
            ext_socket.write_all(&query).await.map_err(DoHError::Io)?;
            ext_socket.flush().await.map_err(DoHError::Io)?;
            ext_socket
                .read_exact(&mut binlen)
                .await
                .map_err(DoHError::Io)?;
            let packet_len = BigEndian::read_u16(&binlen) as usize;
            if !(MIN_DNS_PACKET_LEN..=MAX_DNS_RESPONSE_LEN).contains(&packet_len) {
                return Err(DoHError::UpstreamIssue);
            }
            packet = vec![0u8; packet_len];
            ext_socket
                .read_exact(&mut packet)
                .await
                .map_err(DoHError::Io)?;
        }

        Ok(packet)
    }

    async fn proxy_dot(
        &self,
        query: Vec<u8>,
        upstream: &DotUpstream,
    ) -> Result<Vec<u8>, DoHError> {
        let local_bind_address = self.globals.local_bind_address;
        let server_name = ServerName::try_from(upstream.host.as_str())
            .map_err(|_| DoHError::UpstreamIssue)?
            .to_owned();
        let config = dot_tls_config()?;
        let connector = TlsConnector::from(config);
        let addrs = self
            .resolve_upstream_addrs(upstream.host.as_str(), upstream.port)
            .await?;

        let mut last_err: Option<DoHError> = None;
        for addr in addrs {
            match connect_tcp_with_local_bind(local_bind_address, addr).await {
                Ok(stream) => {
                    if let Err(e) = stream.set_nodelay(true) {
                        last_err = Some(DoHError::Io(e));
                        continue;
                    }
                    let mut tls_stream = match connector.connect(server_name.clone(), stream).await
                    {
                        Ok(stream) => stream,
                        Err(_) => {
                            last_err = Some(DoHError::UpstreamIssue);
                            continue;
                        }
                    };
                    return dns_exchange_over_stream(&mut tls_stream, &query).await;
                }
                Err(e) => last_err = Some(DoHError::Io(e)),
            }
        }

        if let Some(err) = last_err {
            return Err(err);
        }

        Err(DoHError::UpstreamIssue)
    }

    async fn proxy_doh(&self, query: Vec<u8>, upstream: &DohUpstream) -> Result<Vec<u8>, DoHError> {
        let local_bind_address = self.globals.local_bind_address;
        let timeout = self.globals.timeout;
        let fut = async {
            if upstream.h3_only {
                return self
                    .doh_post_h3_with_retries(upstream, query)
                    .await
                    .map_err(Self::doh_h3_error_to_doh_error);
            }

            let mut protocol = upstream.protocol_hint.load(Ordering::Relaxed);
            if protocol == DOH_PROTO_H3 && h3_backoff_active(upstream) {
                protocol = DOH_PROTO_H2;
            }
            if protocol == DOH_PROTO_UNKNOWN {
                protocol = self.select_doh_protocol(upstream).await?;
                if !(protocol == DOH_PROTO_H2 && h3_backoff_active(upstream)) {
                    upstream
                        .protocol_hint
                        .store(protocol, Ordering::Relaxed);
                }
            }

            match protocol {
                DOH_PROTO_H3 => match self.doh_post_h3_with_retries(upstream, query.clone()).await {
                    Ok(packet) => {
                        clear_h3_failures(upstream);
                        Ok(packet)
                    }
                    Err(failure) => {
                        if failure.retryable {
                            let h3_backoff = record_h3_failure(upstream);
                            let reset_hint = Self::is_retryable_h3_failure(&failure) || h3_backoff;
                            if reset_hint {
                                upstream
                                    .protocol_hint
                                    .store(DOH_PROTO_UNKNOWN, Ordering::Relaxed);
                            }
                        } else {
                            reset_h3_failure_counter(upstream);
                            upstream
                                .protocol_hint
                                .store(DOH_PROTO_H2, Ordering::Relaxed);
                        }
                        self.doh_post_h2_with_retries(upstream, query, local_bind_address).await
                    }
                },
                DOH_PROTO_H2 | _ => {
                    self.doh_post_h2_with_retries(upstream, query, local_bind_address).await
                }
            }
        };

        if timeout == Duration::ZERO {
            return fut.await;
        }
        match tokio::time::timeout(timeout, fut).await {
            Ok(res) => res,
            Err(_) => {
                maybe_reset_doh_h2_client(upstream);
                maybe_reset_doh_h3_client(upstream);
                if !upstream.h3_only {
                    upstream
                        .protocol_hint
                        .store(DOH_PROTO_UNKNOWN, Ordering::Relaxed);
                }
                Err(DoHError::UpstreamTimeout)
            }
        }
    }

    fn probe_quic_timeout(&self) -> Duration {
        if self.globals.timeout == Duration::ZERO {
            Duration::from_secs(DOH_PROBE_TLS_TIMEOUT_SECS)
        } else {
            self.globals.timeout
        }
    }

    fn is_retryable_h3_failure(failure: &H3Failure) -> bool {
        failure.retryable
    }

    fn doh_h3_error_to_doh_error(failure: H3Failure) -> DoHError {
        failure.err
    }

    async fn resolve_doh_addr(&self, upstream: &DohUpstream) -> Result<SocketAddr, DoHError> {
        let local_bind_address = self.globals.local_bind_address;
        let addrs = self
            .resolve_upstream_addrs(upstream.host.as_str(), upstream.port)
            .await?;
        let mut last_err: Option<io::Error> = None;
        let mut family_mismatch = false;
        for addr in addrs {
            let bind_addr = match local_bind_for_peer(local_bind_address, &addr) {
                Some(bind_addr) => bind_addr,
                None => {
                    family_mismatch = true;
                    continue;
                }
            };
            let socket = UdpSocket::bind(bind_addr).await.map_err(DoHError::Io)?;
            match socket.connect(addr).await {
                Ok(_) => return Ok(addr),
                Err(err) => last_err = Some(err),
            }
        }
        if let Some(err) = last_err {
            return Err(DoHError::Io(err));
        }
        if family_mismatch {
            return Err(DoHError::Io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "local bind address family mismatch",
            )));
        }
        Err(DoHError::UpstreamIssue)
    }

    async fn resolve_upstream_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DoHError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if self.globals.bootstrap_dns.is_empty() {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| DoHError::UpstreamIssue)?
                .collect();
            if addrs.is_empty() {
                return Err(DoHError::UpstreamIssue);
            }
            return Ok(addrs);
        }

        let mut ips = self.resolve_upstream_ips_with_bootstrap(host).await?;
        let mut addrs = Vec::with_capacity(ips.len());
        for ip in ips.drain(..) {
            addrs.push(SocketAddr::new(ip, port));
        }
        if addrs.is_empty() {
            return Err(DoHError::UpstreamIssue);
        }
        Ok(addrs)
    }

    async fn resolve_upstream_ips_with_bootstrap(&self, host: &str) -> Result<Vec<IpAddr>, DoHError> {
        // Go dnsproxy behavior: with multiple bootstraps, query all in parallel
        // and use the first successful resolver response.
        let mut pending = futures::stream::FuturesUnordered::new();
        for resolver in self.globals.bootstrap_dns.clone() {
            let doh = self.clone();
            let host = host.to_string();
            pending.push(async move { doh.resolve_with_bootstrap_resolver(resolver, &host).await });
        }

        let mut last_err: Option<DoHError> = None;
        while let Some(result) = pending.next().await {
            match result {
                Ok(addrs) => return Ok(addrs),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(DoHError::UpstreamIssue))
    }

    async fn resolve_with_bootstrap_resolver(
        &self,
        resolver: SocketAddr,
        host: &str,
    ) -> Result<Vec<IpAddr>, DoHError> {
        let normalized_host = normalize_bootstrap_host(host)?;
        if let Some(cached_addrs) = load_bootstrap_cache(&resolver, &normalized_host) {
            return Ok(cached_addrs);
        }
        let query_host = normalized_host.trim_end_matches('.');

        // Go dnsproxy behavior: query A and AAAA in parallel for a resolver.
        let (a_result, aaaa_result) = tokio::join!(
            self.resolve_one_bootstrap(&resolver, query_host, BOOTSTRAP_DNS_TYPE_A),
            self.resolve_one_bootstrap(&resolver, query_host, BOOTSTRAP_DNS_TYPE_AAAA),
        );
        let (a_res, mut aaaa_res) = match (a_result, aaaa_result) {
            (Ok(a), Ok(aaaa)) => (a, aaaa),
            (Err(err), _) => return Err(err),
            (_, Err(err)) => return Err(err),
        };

        let mut a_addrs = a_res.addrs;
        a_addrs.append(&mut aaaa_res.addrs);

        let ttl_secs = a_res.min_ttl_secs.min(aaaa_res.min_ttl_secs);
        store_bootstrap_cache(resolver, normalized_host, &a_addrs, ttl_secs);

        Ok(a_addrs)
    }

    async fn resolve_one_bootstrap(
        &self,
        resolver: &SocketAddr,
        host: &str,
        qtype: u16,
    ) -> Result<BootstrapDnsResult, DoHError> {
        let (query_packet, query_id) = build_bootstrap_dns_query(host, qtype)?;
        let bind_addr =
            local_bind_for_peer(self.globals.local_bind_address, resolver).ok_or_else(|| {
                DoHError::Io(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "local bind address family mismatch",
                ))
            })?;
        let socket = UdpSocket::bind(bind_addr).await.map_err(DoHError::Io)?;
        socket.connect(*resolver).await.map_err(DoHError::Io)?;

        socket.send(&query_packet).await.map_err(DoHError::Io)?;
        let mut packet = vec![0u8; MAX_DNS_RESPONSE_LEN];
        let recv_fut = socket.recv(&mut packet);
        let packet_len = if self.globals.timeout == Duration::ZERO {
            recv_fut.await.map_err(DoHError::Io)?
        } else {
            tokio::time::timeout(self.globals.timeout, recv_fut)
                .await
                .map_err(|_| DoHError::UpstreamTimeout)?
                .map_err(DoHError::Io)?
        };
        packet.truncate(packet_len);
        parse_bootstrap_dns_response(&packet, query_id, qtype)
    }

    async fn select_doh_protocol(&self, upstream: &DohUpstream) -> Result<u8, DoHError> {
        if h3_backoff_active(upstream) {
            return Ok(DOH_PROTO_H2);
        }
        let peer_addr = match self.resolve_doh_addr(upstream).await {
            Ok(addr) => addr,
            Err(_) => return Ok(DOH_PROTO_H2),
        };
        let quic_timeout = self.probe_quic_timeout();
        let tls_timeout = Duration::from_secs(DOH_PROBE_TLS_TIMEOUT_SECS);

        let mut h3_fut = Box::pin(self.probe_h3(peer_addr, upstream, quic_timeout));
        let mut h2_fut = Box::pin(self.probe_tls(peer_addr, upstream, tls_timeout));

        tokio::select! {
            res = &mut h3_fut => {
                if res.is_ok() {
                    Ok(DOH_PROTO_H3)
                } else {
                    Ok(DOH_PROTO_H2)
                }
            }
            res = &mut h2_fut => {
                if res.is_ok() {
                    Ok(DOH_PROTO_H2)
                } else {
                    Ok(DOH_PROTO_H3)
                }
            }
        }
    }

    async fn probe_tls(
        &self,
        peer_addr: SocketAddr,
        upstream: &DohUpstream,
        timeout: Duration,
    ) -> Result<(), DoHError> {
        let local_bind_address = self.globals.local_bind_address;
        let server_name = ServerName::try_from(upstream.host.as_str())
            .map_err(|_| DoHError::UpstreamIssue)?
            .to_owned();
        let base_config = dot_tls_config()?;
        let mut config = (*base_config).clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(config));

        tokio::time::timeout(timeout, async move {
            let stream = connect_tcp_with_local_bind(local_bind_address, peer_addr)
                .await
                .map_err(DoHError::Io)?;
            let _tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|_| DoHError::UpstreamIssue)?;
            Ok::<(), DoHError>(())
        })
        .await
        .map_err(|_| DoHError::UpstreamTimeout)?
    }

    async fn probe_h3(
        &self,
        peer_addr: SocketAddr,
        upstream: &DohUpstream,
        timeout: Duration,
    ) -> Result<(), DoHError> {
        let local_bind_address = self.globals.local_bind_address;
        tokio::time::timeout(timeout, async move {
            let bind_addr = local_bind_for_peer(local_bind_address, &peer_addr)
                .ok_or_else(|| DoHError::Io(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "local bind address family mismatch",
                )))?;
            let socket = UdpSocket::bind(bind_addr)
                .await
                .map_err(DoHError::Io)?;
            socket.connect(peer_addr).await.map_err(DoHError::Io)?;

            let socket: tokio_quiche::socket::Socket<
                std::sync::Arc<UdpSocket>,
                std::sync::Arc<UdpSocket>,
            > = tokio_quiche::socket::Socket::<
                std::sync::Arc<UdpSocket>,
                std::sync::Arc<UdpSocket>,
            >::from_udp(socket)
            .map_err(DoHError::Io)?;

            let (driver, _controller) = ClientH3Driver::new(Http3Settings::default());
            let mut params = ConnectionParams::default();
            params.settings.max_idle_timeout = Some(Duration::from_secs(5));
            params.settings.verify_peer = true;

            connect_with_config(socket, Some(upstream.host.as_str()), &params, driver)
                .await
                .map_err(|_| DoHError::UpstreamIssue)?;

            Ok::<(), DoHError>(())
        })
        .await
        .map_err(|_| DoHError::UpstreamTimeout)?
    }

    async fn doh_post_h2_with_retries(
        &self,
        upstream: &DohUpstream,
        query: Vec<u8>,
        local_bind_address: SocketAddr,
    ) -> Result<Vec<u8>, DoHError> {
        let had_cached_client = upstream.h2_client.load_full().is_some();
        let mut retries = 0usize;
        loop {
            match self
                .doh_post_h2_once(upstream, query.clone(), local_bind_address)
                .await
            {
                Ok(packet) => return Ok(packet),
                Err(failure) => {
                    if !(had_cached_client
                        && failure.retryable
                        && retries < DOH_REQUEST_RETRY_LIMIT)
                    {
                        if failure.retryable {
                            maybe_reset_doh_h2_client(upstream);
                        }
                        return Err(failure.err);
                    }
                    retries += 1;
                    maybe_reset_doh_h2_client(upstream);
                }
            }
        }
    }

    async fn doh_post_h2_once(
        &self,
        upstream: &DohUpstream,
        query: Vec<u8>,
        local_bind_address: SocketAddr,
    ) -> Result<Vec<u8>, H2Failure> {
        let client = self
            .doh_h2_client(upstream, local_bind_address)
            .await
            .map_err(H2Failure::from_doh_error)?;
        let connect_authority = {
            let target = upstream
                .h2_target_addr
                .lock()
                .expect("doh h2 target addr mutex poisoned");
            match *target {
                Some(addr) => socket_addr_to_authority(addr),
                None => upstream.authority.clone(),
            }
        };
        let uri: Uri = format!("https://{}{}", connect_authority, upstream.path)
            .parse()
            .map_err(|_| H2Failure::new(DoHError::InvalidData, false))?;

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(hyper::header::CONTENT_TYPE, "application/dns-message")
            .header(hyper::header::ACCEPT, "application/dns-message")
            .header(hyper::header::CONTENT_LENGTH, query.len())
            .header(hyper::header::HOST, upstream.authority.as_str())
            .body(Full::new(Bytes::from(query)))
            .map_err(|_| H2Failure::new(DoHError::InvalidData, false))?;

        let response: Response<Incoming> = client
            .request(request)
            .await
            .map_err(H2Failure::from_hyper_legacy_error)?;
        if response.status() != StatusCode::OK {
            return Err(H2Failure::new(DoHError::UpstreamIssue, false));
        }
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(H2Failure::from_hyper_error)?
            .to_bytes();
        Ok(bytes.to_vec())
    }

    async fn doh_h2_client(
        &self,
        upstream: &DohUpstream,
        local_bind_address: SocketAddr,
    ) -> Result<Arc<DohH2Client>, DoHError> {
        if let Some(client) = upstream.h2_client.load_full() {
            return Ok(client);
        }

        let use_bootstrap = self.use_bootstrap_for_upstream_host(upstream);
        let target_addr = if use_bootstrap {
            let addrs = self
                .resolve_upstream_addrs(upstream.host.as_str(), upstream.port)
                .await?;
            addrs
                .into_iter()
                .find(|addr| local_bind_for_peer(local_bind_address, addr).is_some())
                .ok_or_else(|| {
                    DoHError::Io(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "local bind address family mismatch",
                    ))
                })?
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        match local_bind_address {
            SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                http.set_local_addresses(Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
            }
            SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                http.set_local_addresses(Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
            }
            SocketAddr::V4(v4) => {
                http.set_local_address(Some(IpAddr::V4(*v4.ip())));
            }
            SocketAddr::V6(v6) => {
                http.set_local_address(Some(IpAddr::V6(*v6.ip())));
            }
        }

        let mut https_builder = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| DoHError::UpstreamIssue)?
            .https_only();
        if use_bootstrap {
            let server_name = ServerName::try_from(upstream.host.clone())
                .map_err(|_| DoHError::UpstreamIssue)?;
            https_builder = https_builder
                .with_server_name_resolver(FixedServerNameResolver::new(server_name));
        }
        let https = https_builder.enable_http1().enable_http2().wrap_connector(http);
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        builder.pool_timer(TokioTimer::new());
        builder.pool_idle_timeout(Duration::from_secs(DOH_H2_IDLE_CONN_TIMEOUT_SECS));
        builder.pool_max_idle_per_host(DOH_H2_MAX_IDLE_CONNS_PER_HOST);
        builder.http2_keep_alive_interval(Duration::from_secs(DOH_H2_READ_IDLE_TIMEOUT_SECS));
        builder.http2_keep_alive_while_idle(true);
        let client = Arc::new(builder.build(https));
        {
            let mut target = upstream
                .h2_target_addr
                .lock()
                .expect("doh h2 target addr mutex poisoned");
            *target = if use_bootstrap { Some(target_addr) } else { None };
        }
        upstream.h2_client.store(Some(Arc::clone(&client)));

        Ok(upstream.h2_client.load_full().unwrap_or(client))
    }

    fn use_bootstrap_for_upstream_host(&self, upstream: &DohUpstream) -> bool {
        !self.globals.bootstrap_dns.is_empty() && upstream.host.parse::<IpAddr>().is_err()
    }

    async fn doh_post_h3_with_retries(
        &self,
        upstream: &DohUpstream,
        query: Vec<u8>,
    ) -> Result<Vec<u8>, H3Failure> {
        let had_cached_client = doh_h3_client_cached(upstream);
        let mut retries = 0usize;
        loop {
            match self.doh_post_h3_once(upstream, query.clone()).await {
                Ok(packet) => return Ok(packet),
                Err(failure) => {
                    if !(had_cached_client
                        && failure.retryable
                        && retries < DOH_REQUEST_RETRY_LIMIT)
                    {
                        if failure.retryable {
                            maybe_reset_doh_h3_client(upstream);
                        }
                        return Err(failure);
                    }
                    retries += 1;
                    maybe_reset_doh_h3_client(upstream);
                }
            }
        }
    }

    async fn doh_post_h3_once(
        &self,
        upstream: &DohUpstream,
        query: Vec<u8>,
    ) -> Result<Vec<u8>, H3Failure> {
        let (client, slot) = self.doh_h3_client(upstream).await?;
        client.request(slot, upstream, &query).await
    }

    async fn doh_h3_client(
        &self,
        upstream: &DohUpstream,
    ) -> Result<(Arc<DohH3Client>, OwnedSemaphorePermit), H3Failure> {
        let pool = load_or_init_doh_h3_pool(upstream);
        if let Some((client, slot)) = pool.try_pick_client_with_slot() {
            return Ok((client, slot));
        }

        if pool.needs_new_client() {
            let candidate = match self.create_doh_h3_client(upstream).await {
                Ok(client) => client,
                Err(err) => {
                    if let Some((client, slot)) = pool.try_pick_client_with_slot() {
                        return Ok((client, slot));
                    }
                    if let Some(existing) = pool.pick_client() {
                        let slot = existing.acquire_slot().await;
                        return Ok((existing, slot));
                    }
                    return Err(err);
                }
            };

            let (selected, inserted) = pool.add_or_pick(candidate.clone());
            if !inserted {
                candidate.close_if_idle();
            }
            let slot = selected.acquire_slot().await;
            return Ok((selected, slot));
        }

        if let Some((client, slot)) = pool.try_pick_client_with_slot() {
            return Ok((client, slot));
        }
        if let Some(existing) = pool.pick_client() {
            let slot = existing.acquire_slot().await;
            return Ok((existing, slot));
        }

        let candidate = self.create_doh_h3_client(upstream).await?;
        let (selected, inserted) = pool.add_or_pick(candidate.clone());
        if !inserted {
            candidate.close_if_idle();
        }
        let slot = selected.acquire_slot().await;
        Ok((selected, slot))
    }

    async fn create_doh_h3_client(
        &self,
        upstream: &DohUpstream,
    ) -> Result<Arc<DohH3Client>, H3Failure> {
        let local_bind_address = self.globals.local_bind_address;
        let peer_addr = self
            .resolve_doh_addr(upstream)
            .await
            .map_err(H3Failure::from_doh_error)?;

        let bind_addr = local_bind_for_peer(local_bind_address, &peer_addr).ok_or_else(|| {
            H3Failure::from_io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "local bind address family mismatch",
            ))
        })?;
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(H3Failure::from_io)?;
        socket
            .connect(peer_addr)
            .await
            .map_err(H3Failure::from_io)?;

        let socket: tokio_quiche::socket::Socket<
            std::sync::Arc<UdpSocket>,
            std::sync::Arc<UdpSocket>,
        > = tokio_quiche::socket::Socket::<
            std::sync::Arc<UdpSocket>,
            std::sync::Arc<UdpSocket>,
        >::from_udp(socket)
        .map_err(H3Failure::from_io)?;

        let (driver, controller) = ClientH3Driver::new(Http3Settings::default());
        let mut params = ConnectionParams::default();
        params.settings.max_idle_timeout = Some(Duration::from_secs(30));
        params.settings.verify_peer = true;

        let conn = connect_with_config(socket, Some(upstream.host.as_str()), &params, driver)
            .await
            .map_err(H3Failure::from_boxed_sync)?;
        let pending = Arc::new(Mutex::new(DohH3Pending::default()));
        let request_sender = controller.request_sender();
        DohH3Client::start_event_loop(controller, Arc::clone(&pending));
        Ok(Arc::new(DohH3Client {
            _conn: Box::new(conn),
            request_sender,
            pending,
            slot: Arc::new(Semaphore::new(DOH_H3_MAX_INFLIGHT_PER_CONN)),
        }))
    }

    fn build_response(
        &self,
        packet: Vec<u8>,
        ttl: u32,
        content_type: &str,
        cors: bool,
    ) -> Result<Response<Full<Bytes>>, DoHError> {
        let packet_len = packet.len();
        let mut response_builder = Response::builder()
            .header(hyper::header::CONTENT_LENGTH, packet_len)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .header(
                hyper::header::CACHE_CONTROL,
                format!(
                    "max-age={ttl}, stale-if-error={STALE_IF_ERROR_SECS}, \
                     stale-while-revalidate={STALE_WHILE_REVALIDATE_SECS}"
                )
                .as_str(),
            );
        if cors {
            response_builder =
                response_builder.header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        }
        let response = response_builder
            .body(Full::new(Bytes::from(packet)))
            .map_err(|_| DoHError::InvalidData)?;
        Ok(response)
    }

    async fn client_serve<I>(self, stream: I, server_config: Arc<ServerConfig>)
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let clients_count = self.globals.clients_count.clone();
        if clients_count.increment() >= self.globals.max_clients {
            clients_count.decrement();
            return;
        }
        self.client_serve_reserved(stream, server_config, clients_count)
            .await;
    }

    async fn client_serve_reserved<I>(
        self,
        stream: I,
        server_config: Arc<ServerConfig>,
        clients_count: ClientsCount,
    ) where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let timeout = self.globals.timeout + Duration::from_secs(1);
        self.globals.runtime_handle.clone().spawn(async move {
            let server = server_config.build();
            let io = TokioIo::new(stream);
            let _ = tokio::time::timeout(timeout, server.serve_connection(io, self)).await;
            clients_count.decrement();
        });
    }

    async fn serve_listener_without_tls(
        self,
        listener: TcpListener,
        server_config: Arc<ServerConfig>,
    ) {
        while let Ok((stream, client_addr)) = listener.accept().await {
            let mut doh = self.clone();
            doh.remote_addr = Some(client_addr);
            doh.client_serve(stream, Arc::clone(&server_config)).await;
        }
    }

    #[cfg(feature = "tls")]
    async fn start_http3(
        self,
        listen_addresses: &[SocketAddr],
        mut reload_rx: mpsc::UnboundedReceiver<()>,
    ) -> Result<(), DoHError> {
        let certs_path = match &self.globals.tls_cert_path {
            Some(path) => path.clone(),
            None => return Err(DoHError::InvalidData),
        };
        let certs_keys_path = match &self.globals.tls_cert_key_path {
            Some(path) => path.clone(),
            None => return Err(DoHError::InvalidData),
        };

        loop {
            if let Err(err) = Self::validate_tls_files(&certs_path, &certs_keys_path) {
                eprintln!("TLS certificates error: {err}");
                if reload_rx.recv().await.is_none() {
                    return Err(DoHError::UpstreamIssue);
                }
                continue;
            }

            let mut sockets = Vec::new();
            let mut last_error: Option<io::Error> = None;
            for address in listen_addresses {
                match UdpSocket::bind(address).await {
                    Ok(socket) => sockets.push(socket),
                    Err(err) => {
                        eprintln!("Warning: Failed to bind HTTP/3 socket {address}: {err}");
                        last_error = Some(err);
                    }
                }
            }
            if sockets.is_empty() {
                let err = last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "No available HTTP/3 listen addresses",
                    )
                });
                return Err(DoHError::Io(err));
            }

            let certs_path_str = certs_path.to_string_lossy().to_string();
            let certs_keys_path_str = certs_keys_path.to_string_lossy().to_string();
            let tls_paths = tokio_quiche::settings::TlsCertificatePaths {
                cert: certs_path_str.as_str(),
                private_key: certs_keys_path_str.as_str(),
                kind: tokio_quiche::settings::CertificateKind::X509,
            };

            let listeners = listen(
                sockets,
                ConnectionParams::new_server(Default::default(), tls_paths, Default::default()),
                SimpleConnectionIdGenerator,
                DefaultMetrics,
            )
            .map_err(|_| DoHError::UpstreamIssue)?;

            let (shutdown_tx, shutdown_rx) = watch::channel(());

            let mut handles = Vec::new();
            for mut accept_stream in listeners {
                let doh = self.clone();
                let mut shutdown_rx = shutdown_rx.clone();
                let handle = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.changed() => break,
                            conn = accept_stream.next() => {
                                let conn = match conn {
                                    Some(Ok(conn)) => conn,
                                    Some(Err(err)) => {
                                        eprintln!("Warning: HTTP/3 accept error: {err}");
                                        continue;
                                    }
                                    None => break,
                                };
                                let client_addr = conn.peer_addr();
                                let (driver, controller) =
                                    ServerH3Driver::new(Http3Settings::default());
                                conn.start(driver);
                                let mut doh = doh.clone();
                                doh.remote_addr = Some(client_addr);
                                tokio::spawn(async move {
                                    doh.handle_h3_connection(controller).await;
                                });
                            }
                        }
                    }
                    Ok::<_, DoHError>(())
                });
                handles.push(handle);
            }

            let mut accept_join = tokio::spawn(async move {
                for handle in handles {
                    handle.await.map_err(|_| DoHError::UpstreamIssue)??;
                }
                Ok::<_, DoHError>(())
            });

            loop {
                tokio::select! {
                    res = &mut accept_join => {
                        res.map_err(|_| DoHError::UpstreamIssue)??;
                        return Err(DoHError::UpstreamIssue);
                    }
                    reload = reload_rx.recv() => {
                        if reload.is_none() {
                            accept_join.await.map_err(|_| DoHError::UpstreamIssue)??;
                            return Err(DoHError::UpstreamIssue);
                        }
                        while reload_rx.try_recv().is_ok() {}
                        if let Err(err) = Self::validate_tls_files(&certs_path, &certs_keys_path) {
                            eprintln!("TLS certificates error: {err}");
                            continue;
                        }
                        let _ = shutdown_tx.send(());
                        accept_join.await.map_err(|_| DoHError::UpstreamIssue)??;
                        eprintln!("TLS certificates updated, restarting HTTP/3 listeners");
                        break;
                    }
                }
            }
        }
    }

    #[cfg(feature = "tls")]
    fn validate_tls_files(
        certs_path: &Path,
        certs_keys_path: &Path,
    ) -> io::Result<()> {
        crate::tls::create_tls_acceptor(certs_path, certs_keys_path).map(|_| ())
    }

    #[cfg(feature = "tls")]
    fn spawn_cert_watcher(
        certs_path: PathBuf,
        certs_keys_path: PathBuf,
        reload_tx: mpsc::UnboundedSender<()>,
    ) -> Option<std::sync::mpsc::Sender<()>> {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        match std::thread::Builder::new()
            .name("cert-watcher".to_string())
            .spawn(move || {
                use notify_debouncer_full::{new_debouncer, DebounceEventResult};
                use notify_debouncer_full::notify::RecursiveMode;

                let debounce = Duration::from_millis(400);
                let certs_path = Self::absolutize_path(certs_path);
                let certs_keys_path = Self::absolutize_path(certs_keys_path);
                let mut watch_dirs = Vec::new();
                for path in [&certs_path, &certs_keys_path] {
                    let dir = path.parent().unwrap_or_else(|| Path::new("."));
                    if !watch_dirs.iter().any(|item| item == dir) {
                        watch_dirs.push(dir.to_path_buf());
                    }
                }

                let handler = move |result: DebounceEventResult| {
                    match result {
                        Ok(events) => {
                            let mut changed = false;
                            for event in events {
                                if event.paths.iter().any(|path| {
                                    path == &certs_path || path == &certs_keys_path
                                }) {
                                    changed = true;
                                    break;
                                }
                            }
                            if changed {
                                let _ = reload_tx.send(());
                            }
                        }
                        Err(errors) => {
                            eprintln!(
                                "Warning: Certificate watcher error: {errors:?}"
                            );
                        }
                    }
                };

                let mut debouncer = match new_debouncer(debounce, None, handler) {
                    Ok(debouncer) => debouncer,
                    Err(err) => {
                        eprintln!(
                            "Warning: Failed to initialize certificate watcher: {err}"
                        );
                        return;
                    }
                };

                for dir in &watch_dirs {
                    if let Err(err) = debouncer.watch(dir, RecursiveMode::NonRecursive) {
                        eprintln!(
                            "Warning: Failed to watch certificate directory {dir:?}: {err}"
                        );
                        return;
                    }
                }

                let _ = shutdown_rx.recv();
            }) {
            Ok(_) => Some(shutdown_tx),
            Err(err) => {
                eprintln!("Warning: Failed to spawn certificate watcher: {err}");
                None
            }
        }
    }

    #[cfg(feature = "tls")]
    async fn run_http3_supervisor(
        self,
        listen_addresses: Vec<SocketAddr>,
        mut stop_rx: watch::Receiver<()>,
    ) {
        let certs_path = match self.globals.tls_cert_path.clone() {
            Some(path) => path,
            None => {
                eprintln!("Warning: HTTP/3 supervisor missing certificate path");
                return;
            }
        };
        let certs_keys_path = match self.globals.tls_cert_key_path.clone() {
            Some(path) => path,
            None => {
                eprintln!("Warning: HTTP/3 supervisor missing certificate key path");
                return;
            }
        };

        loop {
            match stop_rx.has_changed() {
                Ok(true) | Err(_) => break,
                Ok(false) => {}
            }

            let (reload_tx, reload_rx) = mpsc::unbounded_channel();
            let watcher_shutdown = match Self::spawn_cert_watcher(
                certs_path.clone(),
                certs_keys_path.clone(),
                reload_tx,
            ) {
                Some(tx) => tx,
                None => {
                    eprintln!("Warning: Certificate watcher unavailable, retrying");
                    tokio::select! {
                        _ = stop_rx.changed() => break,
                        _ = tokio::time::sleep(Duration::from_millis(H3_SUPERVISOR_RESTART_DELAY_MS)) => {}
                    }
                    continue;
                }
            };

            let mut h3_runner = std::pin::pin!(self.clone().start_http3(&listen_addresses, reload_rx));
            let should_restart = tokio::select! {
                _ = stop_rx.changed() => {
                    let _ = watcher_shutdown.send(());
                    false
                }
                res = &mut h3_runner => {
                    let _ = watcher_shutdown.send(());
                    match res {
                        Ok(()) => false,
                        Err(err) => {
                            eprintln!("Warning: HTTP/3 listener exited, restarting: {err}");
                            true
                        }
                    }
                }
            };

            if !should_restart {
                break;
            }

            tokio::select! {
                _ = stop_rx.changed() => break,
                _ = tokio::time::sleep(Duration::from_millis(H3_SUPERVISOR_RESTART_DELAY_MS)) => {}
            }
        }
    }

    #[cfg(feature = "tls")]
    fn absolutize_path(path: PathBuf) -> PathBuf {
        if path.is_absolute() {
            path
        } else {
            let fallback = path.clone();
            env::current_dir()
                .map(|cwd| cwd.join(&path))
                .unwrap_or(fallback)
        }
    }

    async fn handle_h3_connection(self, mut controller: ServerH3Controller) {
        while let Some(ServerH3Event::Core(event)) = controller.event_receiver_mut().recv().await {
            match event {
                H3Event::IncomingHeaders(IncomingH3Headers {
                    send,
                    headers,
                    recv,
                    ..
                }) => {
                    let doh = self.clone();
                    tokio::spawn(async move {
                        let _ = doh.handle_h3_request(send, headers, recv).await;
                    });
                }
                _ => {}
            }
        }
    }

    async fn handle_h3_request(
        &self,
        mut send: OutboundFrameSender,
        headers: Vec<h3::Header>,
        mut recv: InboundFrameStream,
    ) -> Result<(), DoHError> {
        let method = h3_header_value(&headers, b":method").unwrap_or_else(|| "GET".to_string());
        let path = h3_header_value(&headers, b":path").unwrap_or_else(|| "/".to_string());
        let path_only = path.split('?').next().unwrap_or(path.as_str());
        let content_type = h3_header_value(&headers, b"content-type");
        let accept = h3_header_value(&headers, b"accept");

        if path_only == self.globals.odoh_configs_path {
            if method == "GET" {
                let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
                let configs = (*odoh_public_key).clone().into_config();
                self.send_h3_response(
                    &mut send,
                    StatusCode::OK,
                    "application/octet-stream",
                    configs,
                    Some(format!(
                        "max-age={ODOH_KEY_ROTATION_SECS}, stale-if-error={STALE_IF_ERROR_SECS}, stale-while-revalidate={STALE_WHILE_REVALIDATE_SECS}"
                    )),
                    true,
                )
                .await?;
            } else {
                self.send_h3_error(&mut send, StatusCode::METHOD_NOT_ALLOWED, false)
                    .await?;
            }
            return Ok(());
        }

        if path_only != self.globals.path {
            self.send_h3_error(&mut send, StatusCode::NOT_FOUND, true)
                .await?;
            return Ok(());
        }

        let doh_type = match Self::parse_h3_content_type(
            content_type.as_deref(),
            accept.as_deref(),
        ) {
            Ok(doh_type) => doh_type,
            Err(status) => {
                self.send_h3_error(&mut send, status, true).await?;
                return Ok(());
            }
        };
        let client_ip = if self.globals.enable_ecs {
            self.remote_addr.map(|addr| addr.ip())
        } else {
            None
        };

        match (method.as_str(), &doh_type) {
            ("GET", DoHType::Json) => {
                let query = path.split('?').nth(1).unwrap_or("");
                match self.serve_json_query(query, client_ip).await {
                    Ok(response) => {
                        self.send_h3_response(
                            &mut send,
                            response.status,
                            response.content_type.as_str(),
                            response.body,
                            response.cache_control,
                            true,
                        )
                        .await?;
                    }
                    Err(e) => {
                        self.send_h3_error(&mut send, StatusCode::from(e), false)
                            .await?;
                    }
                }
            }
            ("GET", _) => {
                let query = self.query_from_path(&path);
                let query = match query {
                    Some(q) => q,
                    None => {
                        self.send_h3_error(&mut send, StatusCode::BAD_REQUEST, true)
                            .await?;
                        return Ok(());
                    }
                };
                self.handle_doh_payload(
                    &mut send,
                    query,
                    doh_type.clone(),
                    client_ip,
                    doh_type == DoHType::Standard,
                )
                .await?;
            }
            ("POST", DoHType::Json) => {
                self.send_h3_error(&mut send, StatusCode::METHOD_NOT_ALLOWED, false)
                    .await?;
            }
            ("POST", _) => {
                if doh_type == DoHType::Standard && self.globals.disable_post {
                    self.send_h3_error(&mut send, StatusCode::METHOD_NOT_ALLOWED, false)
                        .await?;
                    return Ok(());
                }
                if doh_type == DoHType::Oblivious
                    && self.globals.disable_post
                    && !self.globals.allow_odoh_post
                {
                    self.send_h3_error(&mut send, StatusCode::METHOD_NOT_ALLOWED, false)
                        .await?;
                    return Ok(());
                }
                let mut body = Vec::new();
                let mut body_len = 0usize;
                while let Some(frame) = recv.recv().await {
                    if let InboundFrame::Body(data, fin) = frame {
                        body_len = body_len.saturating_add(data.len());
                        if body_len > MAX_DNS_QUESTION_LEN {
                            self.send_h3_error(
                                &mut send,
                                StatusCode::PAYLOAD_TOO_LARGE,
                                false,
                            )
                            .await?;
                            return Ok(());
                        }
                        body.extend_from_slice(&data);
                        if fin {
                            break;
                        }
                    }
                }
                if body.is_empty() {
                    self.send_h3_error(&mut send, StatusCode::BAD_REQUEST, true)
                        .await?;
                    return Ok(());
                }
                self.handle_doh_payload(
                    &mut send,
                    body,
                    doh_type.clone(),
                    client_ip,
                    doh_type == DoHType::Standard,
                )
                .await?;
            }
            _ => {
                self.send_h3_error(&mut send, StatusCode::METHOD_NOT_ALLOWED, false)
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_doh_payload(
        &self,
        send: &mut OutboundFrameSender,
        payload: Vec<u8>,
        doh_type: DoHType,
        client_ip: Option<IpAddr>,
        cors: bool,
    ) -> Result<(), DoHError> {
        match doh_type {
            DoHType::Standard => {
                let resp = self.proxy(payload, client_ip).await?;
                let _ = resp.query_stats.main();
                let cache_control = format!(
                    "max-age={}, stale-if-error={}, stale-while-revalidate={}",
                    resp.ttl, STALE_IF_ERROR_SECS, STALE_WHILE_REVALIDATE_SECS
                );
                self.send_h3_response(
                    send,
                    StatusCode::OK,
                    DoHType::Standard.as_str(),
                    resp.packet,
                    Some(cache_control),
                    cors,
                )
                .await?;
            }
            DoHType::Oblivious => {
                let odoh_public_key = (*self.globals.odoh_rotator).clone().current_public_key();
                let (query, context) = (*odoh_public_key).clone().decrypt_query(payload)?;
                let resp = self.proxy(query, None).await?;
                let _ = resp.query_stats.main();
                let encrypted_resp = context.encrypt_response(resp.packet)?;
                self.send_h3_response(
                    send,
                    StatusCode::OK,
                    DoHType::Oblivious.as_str(),
                    encrypted_resp,
                    Some(format!(
                        "max-age=0, stale-if-error={}, stale-while-revalidate={}",
                        STALE_IF_ERROR_SECS, STALE_WHILE_REVALIDATE_SECS
                    )),
                    false,
                )
                .await?;
            }
            DoHType::Json => {
                self.send_h3_error(send, StatusCode::METHOD_NOT_ALLOWED, false)
                    .await?;
            }
        }
        Ok(())
    }

    async fn send_h3_response(
        &self,
        send: &mut OutboundFrameSender,
        status: StatusCode,
        content_type: &str,
        body: Vec<u8>,
        cache_control: Option<String>,
        cors: bool,
    ) -> Result<(), DoHError> {
        let status_value = status.as_u16().to_string();
        let length_value = body.len().to_string();
        let mut headers = vec![
            h3::Header::new(b":status", status_value.as_bytes()),
            h3::Header::new(b"content-type", content_type.as_bytes()),
            h3::Header::new(b"content-length", length_value.as_bytes()),
        ];
        if let Some(cache_control) = cache_control {
            headers.push(h3::Header::new(
                b"cache-control",
                cache_control.as_bytes(),
            ));
        }
        if cors {
            headers.push(h3::Header::new(
                b"access-control-allow-origin",
                b"*",
            ));
        }
        send.send(OutboundFrame::Headers(headers, None))
            .await
            .map_err(|_| DoHError::UpstreamIssue)?;
        if !body.is_empty() {
            send.send(OutboundFrame::body(
                BufFactory::buf_from_slice(&body),
                true,
            ))
            .await
            .map_err(|_| DoHError::UpstreamIssue)?;
        }
        Ok(())
    }

    async fn send_h3_error(
        &self,
        send: &mut OutboundFrameSender,
        status: StatusCode,
        long_cache: bool,
    ) -> Result<(), DoHError> {
        let cache_control = if long_cache {
            Some("max-age=31536000, immutable".to_string())
        } else {
            None
        };
        self.send_h3_response(send, status, "text/plain", Vec::new(), cache_control, false)
            .await
    }
    async fn start_without_tls(
        self,
        listeners: Vec<TcpListener>,
        server_config: Arc<ServerConfig>,
    ) -> Result<(), DoHError> {
        let mut handles = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let doh = self.clone();
            let server_config = Arc::clone(&server_config);
            handles.push(tokio::spawn(async move {
                doh.serve_listener_without_tls(listener, server_config).await;
            }));
        }
        let _ = join_all(handles).await;
        Ok(())
    }

    async fn bind_listeners(&self) -> Result<Vec<(SocketAddr, TcpListener)>, DoHError> {
        let mut listeners = Vec::new();
        let mut last_error: Option<io::Error> = None;
        let total = self.globals.listen_addresses.len();

        if total == 0 {
            return Err(DoHError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No listen addresses configured",
            )));
        }

        for address in &self.globals.listen_addresses {
            match TcpListener::bind(address).await {
                Ok(listener) => listeners.push((*address, listener)),
                Err(err) => {
                    eprintln!("Warning: Failed to bind {address}: {err}");
                    last_error = Some(err);
                }
            }
        }

        if listeners.is_empty() {
            let err = last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "No available listen addresses",
                )
            });
            return Err(DoHError::Io(err));
        }

        if total > 1 && listeners.len() < total {
            eprintln!(
                "Warning: Bound {} of {} configured listen addresses.",
                listeners.len(),
                total
            );
        }

        Ok(listeners)
    }

    pub async fn entrypoint(self) -> Result<(), DoHError> {
        let bound_listeners = self.bind_listeners().await?;
        let path = &self.globals.path;

        let tls_enabled: bool;
        #[cfg(not(feature = "tls"))]
        {
            tls_enabled = false;
        }
        #[cfg(feature = "tls")]
        {
            tls_enabled =
                self.globals.tls_cert_path.is_some() && self.globals.tls_cert_key_path.is_some();
        }
        if tls_enabled {
            for (address, _) in &bound_listeners {
                println!("Listening on https://{address}{path}");
            }
        } else {
            for (address, _) in &bound_listeners {
                println!("Listening on http://{address}{path}");
            }
        }

        let server_config = Arc::new(ServerConfig {
            keepalive: self.globals.keepalive,
            max_concurrent_streams: self.globals.max_concurrent_streams,
        });

        let h3_listen_addrs: Vec<SocketAddr> =
            bound_listeners.iter().map(|(addr, _)| *addr).collect();

        let listeners: Vec<TcpListener> = bound_listeners
            .into_iter()
            .map(|(_, listener)| listener)
            .collect();

        #[cfg(feature = "tls")]
        {
            if tls_enabled {
                let (h3_stop_tx, h3_stop_rx) = watch::channel(());
                let doh = self.clone();
                let h3_addrs = h3_listen_addrs.clone();
                let h3_task = tokio::spawn(async move {
                    doh.run_http3_supervisor(h3_addrs, h3_stop_rx).await;
                });
                let tls_result = self
                    .start_with_tls(listeners, Arc::clone(&server_config))
                    .await;
                let _ = h3_stop_tx.send(());
                let _ = h3_task.await;
                tls_result?;
                return Ok(());
            }
        }
        self.start_without_tls(listeners, server_config).await?;
        Ok(())
    }
}

fn h3_header_value(headers: &[h3::Header], name: &[u8]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name() == name)
        .and_then(|header| std::str::from_utf8(header.value()).ok())
        .map(|value| value.to_string())
}

fn build_bootstrap_dns_query(host: &str, qtype: u16) -> Result<(Vec<u8>, u16), DoHError> {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err(DoHError::UpstreamIssue);
    }

    let query_id: u16 = rand::random();
    let mut packet = vec![0u8; 12];
    BigEndian::write_u16(&mut packet[0..2], query_id);
    BigEndian::write_u16(&mut packet[2..4], 0x0100);
    BigEndian::write_u16(&mut packet[4..6], 1);

    for label in host.split('.') {
        let label_bytes = label.as_bytes();
        if label_bytes.is_empty() || label_bytes.len() > 63 || label_bytes.contains(&0) {
            return Err(DoHError::UpstreamIssue);
        }
        packet.push(label_bytes.len() as u8);
        packet.extend_from_slice(label_bytes);
    }
    packet.push(0);

    let mut qtail = [0u8; 4];
    BigEndian::write_u16(&mut qtail[0..2], qtype);
    BigEndian::write_u16(&mut qtail[2..4], BOOTSTRAP_DNS_CLASS_IN);
    packet.extend_from_slice(&qtail);
    Ok((packet, query_id))
}

fn parse_bootstrap_dns_response(
    packet: &[u8],
    query_id: u16,
    qtype: u16,
) -> Result<BootstrapDnsResult, DoHError> {
    if packet.len() < 12 {
        return Err(DoHError::UpstreamIssue);
    }

    let response_id = BigEndian::read_u16(&packet[0..2]);
    if response_id != query_id {
        return Err(DoHError::UpstreamIssue);
    }

    let flags = BigEndian::read_u16(&packet[2..4]);
    if flags & BOOTSTRAP_DNS_FLAG_QR == 0 {
        return Err(DoHError::UpstreamIssue);
    }

    let qdcount = BigEndian::read_u16(&packet[4..6]) as usize;
    let ancount = BigEndian::read_u16(&packet[6..8]) as usize;
    if qdcount == 0 {
        return Err(DoHError::UpstreamIssue);
    }

    let (question_name, mut offset) = parse_dns_name_lower(packet, 12)?;
    if packet.len().saturating_sub(offset) < 4 {
        return Err(DoHError::UpstreamIssue);
    }
    offset += 4;
    for _ in 1..qdcount {
        offset = dns::skip_name(packet, offset).map_err(|_| DoHError::UpstreamIssue)?;
        if packet.len().saturating_sub(offset) < 4 {
            return Err(DoHError::UpstreamIssue);
        }
        offset += 4;
    }

    let mut addrs = Vec::new();
    let mut min_ttl_secs = u32::MAX;
    // Go dnsproxy resolver extracts addresses from Answer records only.
    for _ in 0..ancount {
        let (owner_name, rr_offset) = parse_dns_name_lower(packet, offset)?;
        offset = rr_offset;
        if packet.len().saturating_sub(offset) < 10 {
            return Err(DoHError::UpstreamIssue);
        }

        let rr_type = BigEndian::read_u16(&packet[offset..offset + 2]);
        let rr_class = BigEndian::read_u16(&packet[offset + 2..offset + 4]);
        let rr_ttl = BigEndian::read_u32(&packet[offset + 4..offset + 8]);
        let rdlen = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
        let rdata_offset = offset + 10;
        if packet.len().saturating_sub(rdata_offset) < rdlen {
            return Err(DoHError::UpstreamIssue);
        }

        if owner_name == question_name && rr_class == BOOTSTRAP_DNS_CLASS_IN && rr_type == qtype {
            match (rr_type, rdlen) {
                (BOOTSTRAP_DNS_TYPE_A, 4) => {
                    let ip = Ipv4Addr::new(
                        packet[rdata_offset],
                        packet[rdata_offset + 1],
                        packet[rdata_offset + 2],
                        packet[rdata_offset + 3],
                    );
                    addrs.push(IpAddr::V4(ip));
                    min_ttl_secs = min_ttl_secs.min(rr_ttl);
                }
                (BOOTSTRAP_DNS_TYPE_AAAA, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[rdata_offset..rdata_offset + 16]);
                    addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
                    min_ttl_secs = min_ttl_secs.min(rr_ttl);
                }
                _ => {}
            }
        }

        offset = rdata_offset + rdlen;
    }

    Ok(BootstrapDnsResult {
        addrs,
        min_ttl_secs,
    })
}

fn parse_dns_name_lower(packet: &[u8], start_offset: usize) -> Result<(Vec<u8>, usize), DoHError> {
    if start_offset >= packet.len() {
        return Err(DoHError::UpstreamIssue);
    }

    let mut cursor = start_offset;
    let mut next_offset = start_offset;
    let mut jumped = false;
    let mut jump_count = 0usize;
    let mut first_label = true;
    let mut name = Vec::new();

    loop {
        if cursor >= packet.len() {
            return Err(DoHError::UpstreamIssue);
        }
        let len = packet[cursor];
        match len & 0xC0 {
            0xC0 => {
                if packet.len().saturating_sub(cursor) < 2 {
                    return Err(DoHError::UpstreamIssue);
                }
                let ptr = (((len & 0x3F) as usize) << 8) | packet[cursor + 1] as usize;
                if ptr >= packet.len() {
                    return Err(DoHError::UpstreamIssue);
                }
                if !jumped {
                    next_offset = cursor + 2;
                    jumped = true;
                }
                cursor = ptr;
                jump_count += 1;
                if jump_count > packet.len() {
                    return Err(DoHError::UpstreamIssue);
                }
            }
            0x00 => {
                cursor += 1;
                if len == 0 {
                    if !jumped {
                        next_offset = cursor;
                    }
                    name.push(b'.');
                    break;
                }
                let label_len = len as usize;
                if label_len > 63 || packet.len().saturating_sub(cursor) < label_len {
                    return Err(DoHError::UpstreamIssue);
                }
                if !first_label {
                    name.push(b'.');
                }
                first_label = false;
                for b in &packet[cursor..cursor + label_len] {
                    name.push(b.to_ascii_lowercase());
                }
                cursor += label_len;
            }
            _ => return Err(DoHError::UpstreamIssue),
        }
    }

    Ok((name, next_offset))
}

fn bootstrap_resolver_cache(
) -> &'static StdMutex<HashMap<BootstrapCacheKey, BootstrapCacheEntry>> {
    BOOTSTRAP_RESOLVER_CACHE.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn normalize_bootstrap_host(host: &str) -> Result<String, DoHError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(DoHError::UpstreamIssue);
    }

    let lower = trimmed.to_ascii_lowercase();
    let normalized = if lower.ends_with('.') {
        lower
    } else {
        format!("{lower}.")
    };
    Ok(normalized)
}

fn load_bootstrap_cache(resolver: &SocketAddr, host: &str) -> Option<Vec<IpAddr>> {
    let key = BootstrapCacheKey {
        resolver: *resolver,
        host: host.to_string(),
    };
    let now = now_millis();
    let cache = bootstrap_resolver_cache();
    let guard = cache.lock().expect("bootstrap resolver cache mutex poisoned");
    let entry = guard.get(&key)?;
    if entry.expire_at_ms >= now {
        Some(entry.addrs.clone())
    } else {
        None
    }
}

fn store_bootstrap_cache(resolver: SocketAddr, host: String, addrs: &[IpAddr], ttl_secs: u32) {
    let key = BootstrapCacheKey { resolver, host };
    let ttl_ms = u64::from(ttl_secs).saturating_mul(1000);
    let entry = BootstrapCacheEntry {
        addrs: addrs.to_vec(),
        expire_at_ms: now_millis().saturating_add(ttl_ms),
    };
    let cache = bootstrap_resolver_cache();
    let mut guard = cache.lock().expect("bootstrap resolver cache mutex poisoned");
    guard.insert(key, entry);
}

fn local_bind_for_peer(local: SocketAddr, peer: &SocketAddr) -> Option<SocketAddr> {
    match (local, peer) {
        (SocketAddr::V4(local_v4), SocketAddr::V4(_)) => Some(SocketAddr::V4(local_v4)),
        (SocketAddr::V6(local_v6), SocketAddr::V6(_)) => Some(SocketAddr::V6(local_v6)),
        (SocketAddr::V4(local_v4), SocketAddr::V6(_)) if local_v4.ip().is_unspecified() => {
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                local_v4.port(),
                0,
                0,
            )))
        }
        (SocketAddr::V6(local_v6), SocketAddr::V4(_)) if local_v6.ip().is_unspecified() => {
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                local_v6.port(),
            )))
        }
        _ => None,
    }
}

async fn connect_tcp_with_local_bind(
    local_bind_address: SocketAddr,
    peer_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let bind_addr = local_bind_for_peer(local_bind_address, &peer_addr).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "local bind address family mismatch",
        )
    })?;
    let socket = match peer_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;
    socket.bind(bind_addr)?;
    socket.connect(peer_addr).await
}

fn socket_addr_to_authority(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

fn reset_doh_h2_client(upstream: &DohUpstream) {
    upstream.h2_client.store(None);
    let mut target = upstream
        .h2_target_addr
        .lock()
        .expect("doh h2 target addr mutex poisoned");
    *target = None;
}

fn doh_h3_pools() -> &'static StdMutex<HashMap<String, Arc<DohH3Pool>>> {
    DOH_H3_POOLS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn doh_h3_client_cache_key(upstream: &DohUpstream) -> String {
    upstream.url.as_str().to_string()
}

fn load_or_init_doh_h3_pool(upstream: &DohUpstream) -> Arc<DohH3Pool> {
    let key = doh_h3_client_cache_key(upstream);
    let mut guard = doh_h3_pools().lock().expect("doh h3 pool cache mutex poisoned");
    if let Some(existing) = guard.get(&key) {
        return existing.clone();
    }
    let pool = Arc::new(DohH3Pool::new());
    guard.insert(key, pool.clone());
    pool
}

fn doh_h3_client_cached(upstream: &DohUpstream) -> bool {
    let key = doh_h3_client_cache_key(upstream);
    let guard = doh_h3_pools().lock().expect("doh h3 pool cache mutex poisoned");
    guard
        .get(&key)
        .map(|pool| pool.has_clients())
        .unwrap_or(false)
}

fn reset_doh_h3_client(upstream: &DohUpstream) {
    let key = doh_h3_client_cache_key(upstream);
    let pool = {
        let mut guard = doh_h3_pools().lock().expect("doh h3 pool cache mutex poisoned");
        guard.remove(&key)
    };
    if let Some(pool) = pool {
        for client in pool.drain_clients() {
            client.close_if_idle();
        }
    }
}

fn can_rebuild(last_rebuild_ms: &AtomicU64) -> bool {
    let now = now_millis();
    loop {
        let prev = last_rebuild_ms.load(Ordering::Relaxed);
        if prev != 0 && now.saturating_sub(prev) < DOH_MIN_REBUILD_INTERVAL_MS {
            return false;
        }
        if last_rebuild_ms
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn maybe_reset_doh_h2_client(upstream: &DohUpstream) {
    if can_rebuild(&upstream.h2_last_rebuild_ms) {
        reset_doh_h2_client(upstream);
    }
}

fn maybe_reset_doh_h3_client(upstream: &DohUpstream) {
    if can_rebuild(&upstream.h3_last_rebuild_ms) {
        reset_doh_h3_client(upstream);
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn h3_backoff_active(upstream: &DohUpstream) -> bool {
    let now = now_millis();
    let until = upstream.h3_backoff_until_ms.load(Ordering::Relaxed);
    until > now
}

fn clear_h3_failures(upstream: &DohUpstream) {
    upstream.h3_failures.store(0, Ordering::Relaxed);
    upstream.h3_last_failure_ms.store(0, Ordering::Relaxed);
    upstream.h3_backoff_until_ms.store(0, Ordering::Relaxed);
}

fn reset_h3_failure_counter(upstream: &DohUpstream) {
    upstream.h3_failures.store(0, Ordering::Relaxed);
    upstream.h3_last_failure_ms.store(0, Ordering::Relaxed);
}

fn record_h3_failure(upstream: &DohUpstream) -> bool {
    let now = now_millis();
    let last = upstream.h3_last_failure_ms.load(Ordering::Relaxed);
    let window_ms = H3_FAILURE_WINDOW_SECS * 1000;
    let threshold = H3_FAILURE_THRESHOLD;

    let count = if last == 0 || now.saturating_sub(last) > window_ms {
        upstream.h3_failures.store(1, Ordering::Relaxed);
        1
    } else {
        upstream.h3_failures.fetch_add(1, Ordering::Relaxed) + 1
    };

    upstream.h3_last_failure_ms.store(now, Ordering::Relaxed);

    if count >= threshold {
        upstream.h3_failures.store(0, Ordering::Relaxed);
        upstream
            .h3_backoff_until_ms
            .store(now.saturating_add(H3_BACKOFF_SECS * 1000), Ordering::Relaxed);
        return true;
    }

    false
}

fn is_retryable_doh_error(err: &DoHError) -> bool {
    !is_no_rebuild_doh_error(err)
}

fn is_no_rebuild_doh_error(err: &DoHError) -> bool {
    match err {
        DoHError::Incomplete
        | DoHError::InvalidData
        | DoHError::TooLarge
        | DoHError::StaleKey
        | DoHError::TooManyTcpSessions => true,
        DoHError::Hyper(hyper_err) => is_no_rebuild_hyper_error(hyper_err),
        DoHError::Io(io_err) => is_no_rebuild_io_error(io_err),
        _ => false,
    }
}

fn is_retryable_h2_client_error(err: &HyperLegacyError) -> bool {
    if err.is_connect() {
        return true;
    }

    err.source().map(is_retryable_std_error).unwrap_or(true)
}

fn is_no_rebuild_hyper_error(err: &hyper::Error) -> bool {
    err.is_parse() || err.is_parse_too_large() || err.is_parse_status() || err.is_user()
}

fn is_retryable_hyper_error(err: &hyper::Error) -> bool {
    !is_no_rebuild_hyper_error(err)
}

fn is_retryable_std_error(err: &(dyn Error + 'static)) -> bool {
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        return is_retryable_io_error(io_err);
    }
    if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
        return is_retryable_hyper_error(hyper_err);
    }

    if err.downcast_ref::<tokio_quiche::quic::HandshakeError>().is_some()
        || err.downcast_ref::<H3ConnectionError>().is_some()
        || err.downcast_ref::<h3::Error>().is_some()
    {
        return is_retryable_quic_error(err);
    }

    true
}

fn is_no_rebuild_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::Unsupported
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::AlreadyExists
            | io::ErrorKind::AddrInUse
    )
}

fn is_retryable_io_error(err: &io::Error) -> bool {
    if is_no_rebuild_io_error(err) {
        return false;
    }

    err.get_ref()
        .map(|source| is_retryable_std_error(source))
        .unwrap_or(true)
}

fn is_retryable_quic_error(err: &(dyn Error + 'static)) -> bool {
    if let Some(_hs_err) = err.downcast_ref::<tokio_quiche::quic::HandshakeError>()
    {
        return true;
    }

    if let Some(conn_err) = err.downcast_ref::<H3ConnectionError>() {
        return is_retryable_h3_connection_error(conn_err);
    }

    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        return is_retryable_io_error(io_err);
    }

    if let Some(h3_err) = err.downcast_ref::<h3::Error>() {
        return is_retryable_h3_error(h3_err);
    }

    true
}

fn is_no_rebuild_h3_error(err: &h3::Error) -> bool {
    matches!(
        err,
        h3::Error::TransportError(tokio_quiche::quiche::Error::TlsFail)
            | h3::Error::TransportError(tokio_quiche::quiche::Error::CryptoFail)
    )
}

fn is_retryable_h3_error(err: &h3::Error) -> bool {
    !is_no_rebuild_h3_error(err)
}

fn is_no_rebuild_h3_connection_error(err: &H3ConnectionError) -> bool {
    match err {
        H3ConnectionError::H3(h3_err) => is_no_rebuild_h3_error(h3_err),
        H3ConnectionError::NonexistentStream => true,
        _ => false,
    }
}

fn is_retryable_h3_connection_error(err: &H3ConnectionError) -> bool {
    !is_no_rebuild_h3_connection_error(err)
}
