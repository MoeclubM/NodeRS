use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TCP_REPLAY_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Default)]
pub(crate) struct TcpReplayCache {
    inner: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
}

impl TcpReplayCache {
    pub(crate) fn accept(&self, salt: &[u8]) -> bool {
        let now = Instant::now();
        let mut guard = self
            .inner
            .lock()
            .expect("Shadowsocks 2022 TCP replay cache lock poisoned");
        guard.retain(|_, seen_at| now.duration_since(*seen_at) <= TCP_REPLAY_TTL);
        if guard.contains_key(salt) {
            return false;
        }
        guard.insert(salt.to_vec(), now);
        true
    }
}

pub(super) struct SlidingWindow {
    last: u64,
    ring: [u64; 128],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0u64; 128],
        }
    }
}

impl SlidingWindow {
    pub(super) fn check(&self, counter: u64) -> bool {
        const BLOCK_BITS: u64 = 64;
        const RING_BLOCKS: u64 = 128;
        const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS;

        if counter > self.last {
            return true;
        }
        if self.last - counter > WINDOW_SIZE {
            return false;
        }

        let block_index = ((counter >> 6) & (RING_BLOCKS - 1)) as usize;
        let bit_index = (counter & (BLOCK_BITS - 1)) as usize;
        (self.ring[block_index] >> bit_index) & 1 == 0
    }

    pub(super) fn add(&mut self, counter: u64) {
        const BLOCK_BITS: u64 = 64;
        const RING_BLOCKS: u64 = 128;
        const RING_MASK: u64 = RING_BLOCKS - 1;

        let block_index = counter >> 6;
        if counter > self.last {
            let mut last_block_index = self.last >> 6;
            let mut diff = block_index.saturating_sub(last_block_index);
            if diff > RING_BLOCKS {
                diff = RING_BLOCKS;
            }
            for _ in 0..diff {
                last_block_index = (last_block_index + 1) & RING_MASK;
                self.ring[last_block_index as usize] = 0;
            }
            self.last = counter;
        }
        let ring_index = (block_index & RING_MASK) as usize;
        let bit_index = (counter & (BLOCK_BITS - 1)) as usize;
        self.ring[ring_index] |= 1u64 << bit_index;
    }
}
