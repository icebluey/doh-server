use std::io;
use std::time::Duration;

use hyper::StatusCode;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UpstreamErrorKind {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    UpstreamTimeout,
    StaleKey,
    Hyper,
    Io,
    ODoHConfigError,
    TooManyTcpSessions,
}

impl UpstreamErrorKind {
    fn from_doh_error(err: &DoHError) -> Self {
        match err {
            DoHError::Incomplete => Self::Incomplete,
            DoHError::InvalidData => Self::InvalidData,
            DoHError::TooLarge => Self::TooLarge,
            DoHError::UpstreamIssue => Self::UpstreamIssue,
            DoHError::UpstreamTimeout => Self::UpstreamTimeout,
            DoHError::StaleKey => Self::StaleKey,
            DoHError::Hyper(_) => Self::Hyper,
            DoHError::Io(_) => Self::Io,
            DoHError::ODoHConfigError(_) => Self::ODoHConfigError,
            DoHError::TooManyTcpSessions => Self::TooManyTcpSessions,
            DoHError::UpstreamJoined(_) => Self::UpstreamIssue,
        }
    }
}

impl std::fmt::Display for UpstreamErrorKind {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = match self {
            Self::Incomplete => "incomplete",
            Self::InvalidData => "invalid_data",
            Self::TooLarge => "too_large",
            Self::UpstreamIssue => "upstream_issue",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::StaleKey => "stale_key",
            Self::Hyper => "hyper",
            Self::Io => "io",
            Self::ODoHConfigError => "odoh_config_error",
            Self::TooManyTcpSessions => "too_many_tcp_sessions",
        };
        write!(fmt, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamAttemptError {
    pub address: String,
    pub duration: Duration,
    pub error_kind: UpstreamErrorKind,
    pub error_message: String,
}

impl UpstreamAttemptError {
    pub fn from_doh_error(address: String, duration: Duration, err: &DoHError) -> Self {
        Self {
            address,
            duration,
            error_kind: UpstreamErrorKind::from_doh_error(err),
            error_message: err.to_string(),
        }
    }
}

#[derive(Debug)]
pub enum DoHError {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    UpstreamTimeout,
    StaleKey,
    Hyper(hyper::Error),
    Io(io::Error),
    ODoHConfigError(anyhow::Error),
    TooManyTcpSessions,
    UpstreamJoined(Vec<UpstreamAttemptError>),
}

impl std::error::Error for DoHError {}

impl std::fmt::Display for DoHError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DoHError::Incomplete => write!(fmt, "Incomplete"),
            DoHError::InvalidData => write!(fmt, "Invalid data"),
            DoHError::TooLarge => write!(fmt, "Too large"),
            DoHError::UpstreamIssue => write!(fmt, "Upstream error"),
            DoHError::UpstreamTimeout => write!(fmt, "Upstream timeout"),
            DoHError::StaleKey => write!(fmt, "Stale key material"),
            DoHError::Hyper(e) => write!(fmt, "HTTP error: {e}"),
            DoHError::Io(e) => write!(fmt, "IO error: {e}"),
            DoHError::ODoHConfigError(e) => write!(fmt, "ODoH config error: {e}"),
            DoHError::TooManyTcpSessions => write!(fmt, "Too many TCP sessions"),
            DoHError::UpstreamJoined(attempts) => {
                write!(fmt, "All upstreams failed")?;
                for attempt in attempts {
                    write!(
                        fmt,
                        "; {} (kind={}, duration_ms={}): {}",
                        attempt.address,
                        attempt.error_kind,
                        attempt.duration.as_millis(),
                        attempt.error_message
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl DoHError {
    pub fn from_upstream_attempts(attempts: Vec<UpstreamAttemptError>) -> Self {
        if attempts.is_empty() {
            Self::UpstreamIssue
        } else {
            Self::UpstreamJoined(attempts)
        }
    }
}

impl From<DoHError> for StatusCode {
    fn from(e: DoHError) -> StatusCode {
        match e {
            DoHError::Incomplete => StatusCode::UNPROCESSABLE_ENTITY,
            DoHError::InvalidData => StatusCode::BAD_REQUEST,
            DoHError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            DoHError::UpstreamIssue => StatusCode::BAD_GATEWAY,
            DoHError::UpstreamTimeout => StatusCode::BAD_GATEWAY,
            DoHError::StaleKey => StatusCode::UNAUTHORIZED,
            DoHError::Hyper(_) => StatusCode::SERVICE_UNAVAILABLE,
            DoHError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DoHError::ODoHConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DoHError::TooManyTcpSessions => StatusCode::SERVICE_UNAVAILABLE,
            DoHError::UpstreamJoined(_) => StatusCode::BAD_GATEWAY,
        }
    }
}
