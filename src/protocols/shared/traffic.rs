use std::sync::Arc;

use crate::accounting::{Accounting, SessionControl, SpeedLimiter, UsageCounter};

#[derive(Clone)]
pub struct TrafficRecorder {
    counter: Arc<UsageCounter>,
    limiter: Arc<SpeedLimiter>,
    direction: TrafficDirection,
}

#[derive(Clone, Copy)]
enum TrafficDirection {
    Upload,
    Download,
}

impl TrafficRecorder {
    pub fn upload(accounting: Arc<Accounting>, uid: i64) -> Self {
        Self {
            counter: accounting.traffic_counter(uid),
            limiter: accounting.speed_limiter(uid),
            direction: TrafficDirection::Upload,
        }
    }

    pub fn download(accounting: Arc<Accounting>, uid: i64) -> Self {
        Self {
            counter: accounting.traffic_counter(uid),
            limiter: accounting.speed_limiter(uid),
            direction: TrafficDirection::Download,
        }
    }

    pub fn record(&self, bytes: u64) {
        match self.direction {
            TrafficDirection::Upload => self.counter.record_upload(bytes),
            TrafficDirection::Download => self.counter.record_download(bytes),
        }
    }

    pub async fn limit(&self, bytes: u64, control: &SessionControl) {
        self.limiter.wait(bytes, control).await;
    }
}
