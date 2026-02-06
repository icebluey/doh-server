use std::time::Instant;

use tokio::sync::mpsc;

use crate::{DoH, DoHError, Upstream, UpstreamAttemptError};

use super::stats::{QueryStatistics, UpstreamStatistics};
use super::{exchange_single, upstream_address, validate_exchange_packet, ExchangeOutcome};

pub(super) async fn exchange_parallel(
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

    struct AttemptOutcome {
        idx: usize,
        result: Result<Vec<u8>, DoHError>,
        duration: std::time::Duration,
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

    let mut failures: Vec<UpstreamAttemptError> = Vec::with_capacity(upstreams.len());
    let mut attempts: Vec<Option<UpstreamStatistics>> = vec![None; upstreams.len()];
    for _ in 0..upstreams.len() {
        match rx.recv().await {
            Some(AttemptOutcome { idx, result, duration }) => {
                let address = upstream_address(&upstreams[idx]);
                match result {
                    Ok(packet) => {
                        let stat = UpstreamStatistics::success(address, duration);
                        return ExchangeOutcome {
                            packet: Ok(packet),
                            query_stats: QueryStatistics::with_main(vec![stat]),
                        };
                    }
                    Err(err) => {
                        failures.push(UpstreamAttemptError::from_doh_error(
                            address.clone(),
                            duration,
                            &err,
                        ));
                        attempts[idx] = Some(UpstreamStatistics::failure(
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

    let main = attempts.into_iter().flatten().collect::<Vec<_>>();
    ExchangeOutcome {
        packet: Err(DoHError::from_upstream_attempts(failures)),
        query_stats: QueryStatistics::with_main(main),
    }
}
