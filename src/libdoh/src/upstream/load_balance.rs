use std::time::{Duration, Instant};

use crate::{DoH, DoHError, Upstream, UpstreamAttemptError};

use super::stats::{QueryStatistics, UpstreamStatistics};
use super::{exchange_single, upstream_address, validate_exchange_packet, ExchangeOutcome};

const LOAD_BALANCE_FAILURE_PENALTY: Duration = Duration::from_secs(10);

pub(super) async fn exchange_load_balance(
    doh: &DoH,
    query: Vec<u8>,
    upstreams: &[Upstream],
) -> ExchangeOutcome {
    if upstreams.len() == 1 {
        let started = Instant::now();
        let result = exchange_single(doh, query, &upstreams[0])
            .await
            .and_then(validate_exchange_packet);
        let duration = started.elapsed();
        let address = upstream_address(&upstreams[0]);
        let stats = QueryStatistics::with_main(vec![match &result {
            Ok(_) => UpstreamStatistics::success(address, duration),
            Err(err) => UpstreamStatistics::failure(address, duration, err.to_string()),
        }]);
        return ExchangeOutcome {
            packet: result,
            query_stats: stats,
        };
    }

    let weights = calc_weights(doh, upstreams);
    let mut remaining: Vec<usize> = (0..upstreams.len()).collect();
    let mut failures: Vec<UpstreamAttemptError> = Vec::with_capacity(upstreams.len());
    let mut attempts: Vec<Option<UpstreamStatistics>> = vec![None; upstreams.len()];

    while !remaining.is_empty() {
        let pick_pos = sample_weighted_index(&remaining, &weights);
        let idx = remaining.swap_remove(pick_pos);
        let started_at = Instant::now();
        let result = exchange_single(doh, query.clone(), &upstreams[idx])
            .await
            .and_then(validate_exchange_packet);
        let duration = started_at.elapsed();
        let address = upstream_address(&upstreams[idx]);
        match result {
            Ok(packet) => {
                update_rtt(doh, &upstreams[idx], duration);
                attempts[idx] = Some(UpstreamStatistics::success(address, duration));
                return ExchangeOutcome {
                    packet: Ok(packet),
                    query_stats: QueryStatistics::with_main(vec![attempts[idx]
                        .clone()
                        .expect("attempt stat must be present")]),
                };
            }
            Err(err) => {
                failures.push(UpstreamAttemptError::from_doh_error(
                    address.clone(),
                    duration,
                    &err,
                ));
                update_rtt(doh, &upstreams[idx], LOAD_BALANCE_FAILURE_PENALTY);
                attempts[idx] = Some(UpstreamStatistics::failure(address, duration, err.to_string()));
            }
        }
    }

    let main = attempts.into_iter().flatten().collect::<Vec<_>>();
    ExchangeOutcome {
        packet: Err(DoHError::from_upstream_attempts(failures)),
        query_stats: QueryStatistics::with_main(main),
    }
}

fn calc_weights(doh: &DoH, upstreams: &[Upstream]) -> Vec<f64> {
    let guard = doh
        .globals
        .upstream_rtt_stats
        .lock()
        .expect("upstream rtt stats mutex poisoned");
    let mut weights = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
        let key = upstream_key(upstream);
        let stat = guard.get(&key).copied().unwrap_or_default();
        let weight = if stat.rtt_sum_us <= 0.0 || stat.req_num <= 0.0 {
            1.0
        } else {
            1.0 / (stat.rtt_sum_us / stat.req_num)
        };
        weights.push(weight);
    }
    weights
}

fn sample_weighted_index(remaining: &[usize], weights: &[f64]) -> usize {
    let mut total = 0.0f64;
    for idx in remaining {
        let w = weights[*idx];
        if w.is_finite() && w > 0.0 {
            total += w;
        }
    }

    if total <= 0.0 {
        return 0;
    }

    let mut cursor = rand::random::<f64>() * total;
    for (pos, idx) in remaining.iter().enumerate() {
        let w = weights[*idx];
        if !w.is_finite() || w <= 0.0 {
            continue;
        }
        if cursor <= w {
            return pos;
        }
        cursor -= w;
    }

    0
}

fn update_rtt(doh: &DoH, upstream: &Upstream, elapsed: Duration) {
    let key = upstream_key(upstream);
    let mut guard = doh
        .globals
        .upstream_rtt_stats
        .lock()
        .expect("upstream rtt stats mutex poisoned");
    let current = guard.get(&key).copied().unwrap_or_default();
    guard.insert(key, current.update(elapsed));
}

fn upstream_key(upstream: &Upstream) -> String {
    upstream_address(upstream)
}
