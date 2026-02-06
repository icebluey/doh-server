use std::time::Duration;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct UpstreamStatistics {
    pub error: Option<String>,
    pub address: String,
    pub query_duration: Duration,
    pub is_cached: bool,
}

impl UpstreamStatistics {
    pub(crate) fn success(address: String, query_duration: Duration) -> Self {
        Self {
            error: None,
            address,
            query_duration,
            is_cached: false,
        }
    }

    pub(crate) fn failure(address: String, query_duration: Duration, error: String) -> Self {
        Self {
            error: Some(error),
            address,
            query_duration,
            is_cached: false,
        }
    }

}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct QueryStatistics {
    main: Vec<UpstreamStatistics>,
    fallback: Vec<UpstreamStatistics>,
}

#[allow(dead_code)]
impl QueryStatistics {
    pub(crate) fn with_main(main: Vec<UpstreamStatistics>) -> Self {
        Self {
            main,
            fallback: Vec::new(),
        }
    }

    pub fn main(&self) -> &[UpstreamStatistics] {
        &self.main
    }

    pub fn fallback(&self) -> &[UpstreamStatistics] {
        &self.fallback
    }
}
