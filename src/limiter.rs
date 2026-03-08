use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SharedRateLimiter {
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    bytes_per_second: u64,
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
}

impl SharedRateLimiter {
    pub fn new(bytes_per_second: u64) -> Arc<Self> {
        let capacity = bucket_capacity(bytes_per_second);
        Arc::new(Self {
            state: Mutex::new(BucketState {
                bytes_per_second,
                capacity,
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        })
    }

    pub fn set_rate(&self, bytes_per_second: u64) {
        let mut state = self.state.lock().expect("rate limiter poisoned");
        refill(&mut state);
        state.bytes_per_second = bytes_per_second;
        state.capacity = bucket_capacity(bytes_per_second);
        if state.tokens > state.capacity {
            state.tokens = state.capacity;
        }
    }

    pub async fn consume(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let requested = bytes as f64;
        loop {
            let wait = {
                let mut state = self.state.lock().expect("rate limiter poisoned");
                refill(&mut state);
                if state.bytes_per_second == 0 {
                    return;
                }
                if state.tokens >= requested {
                    state.tokens -= requested;
                    return;
                }
                let missing = requested - state.tokens;
                let seconds = missing / state.bytes_per_second as f64;
                Duration::from_secs_f64(seconds.max(0.001)).min(Duration::from_millis(100))
            };
            tokio::time::sleep(wait).await;
        }
    }
}

fn refill(state: &mut BucketState) {
    let now = Instant::now();
    let elapsed = now
        .saturating_duration_since(state.last_refill)
        .as_secs_f64();
    state.last_refill = now;
    if state.bytes_per_second == 0 {
        state.tokens = state.capacity;
        return;
    }
    state.tokens = (state.tokens + elapsed * state.bytes_per_second as f64).min(state.capacity);
}

fn bucket_capacity(bytes_per_second: u64) -> f64 {
    if bytes_per_second == 0 {
        0.0
    } else {
        bytes_per_second.max(16 * 1024) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_rate() {
        let limiter = SharedRateLimiter::new(1024);
        limiter.set_rate(2048);
        let state = limiter.state.lock().expect("rate limiter poisoned");
        assert_eq!(state.bytes_per_second, 2048);
    }
}
