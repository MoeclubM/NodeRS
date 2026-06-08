use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::panel::PanelUser;

#[derive(Debug, Default)]
pub struct UsageCounter {
    upload: AtomicU64,
    download: AtomicU64,
}

impl UsageCounter {
    pub fn record_upload(&self, bytes: u64) {
        if bytes > 0 {
            self.upload.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn record_download(&self, bytes: u64) {
        if bytes > 0 {
            self.download.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn snapshot_if_ready(&self, min_traffic_bytes: u64) -> Option<[u64; 2]> {
        let upload = self.upload.swap(0, Ordering::AcqRel);
        let download = self.download.swap(0, Ordering::AcqRel);
        let total = upload + download;
        if total == 0 {
            return None;
        }
        if total < min_traffic_bytes {
            self.restore(upload, download);
            return None;
        }
        Some([upload, download])
    }

    fn restore(&self, upload: u64, download: u64) {
        if upload > 0 {
            self.upload.fetch_add(upload, Ordering::Release);
        }
        if download > 0 {
            self.download.fetch_add(download, Ordering::Release);
        }
    }
}

#[derive(Debug, Default)]
pub struct Accounting {
    traffic: RwLock<HashMap<i64, Arc<UsageCounter>>>,
}

impl Accounting {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn replace_users(&self, users: &[PanelUser]) {
        let valid_ids = users.iter().map(|user| user.id).collect::<HashSet<_>>();
        let mut traffic = self.traffic.write().expect("traffic lock poisoned");
        for user in users {
            traffic
                .entry(user.id)
                .or_insert_with(|| Arc::new(UsageCounter::default()));
        }
        traffic.retain(|uid, _| valid_ids.contains(uid));
    }

    pub fn traffic_counter(&self, uid: i64) -> Arc<UsageCounter> {
        if let Some(counter) = self
            .traffic
            .read()
            .expect("traffic lock poisoned")
            .get(&uid)
            .cloned()
        {
            return counter;
        }
        let mut guard = self.traffic.write().expect("traffic lock poisoned");
        guard
            .entry(uid)
            .or_insert_with(|| Arc::new(UsageCounter::default()))
            .clone()
    }

    pub fn snapshot_traffic(&self, min_traffic_bytes: u64) -> HashMap<i64, [u64; 2]> {
        let counters = self
            .traffic
            .read()
            .expect("traffic lock poisoned")
            .iter()
            .map(|(uid, counter)| (*uid, counter.clone()))
            .collect::<Vec<_>>();
        let mut snapshot = HashMap::new();
        for (uid, counter) in counters {
            if let Some(usage) = counter.snapshot_if_ready(min_traffic_bytes) {
                snapshot.insert(uid, usage);
            }
        }
        snapshot
    }

    pub fn restore_traffic(&self, traffic: &HashMap<i64, [u64; 2]>) {
        for (uid, [upload, download]) in traffic {
            self.traffic_counter(*uid).restore(*upload, *download);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_users_removes_old_counters() {
        let accounting = Accounting::new();
        accounting.replace_users(&[PanelUser {
            id: 1,
            ..Default::default()
        }]);
        accounting.traffic_counter(1).record_upload(100);

        accounting.replace_users(&[PanelUser {
            id: 2,
            ..Default::default()
        }]);

        assert!(accounting.snapshot_traffic(0).is_empty());
        accounting.traffic_counter(2).record_download(40);
        assert_eq!(accounting.snapshot_traffic(0).get(&2), Some(&[0, 40]));
    }

    #[test]
    fn restores_traffic_after_failed_push() {
        let accounting = Accounting::new();
        let counter = accounting.traffic_counter(1);
        counter.record_upload(100);
        counter.record_download(40);

        let snapshot = accounting.snapshot_traffic(0);
        assert_eq!(snapshot.get(&1), Some(&[100, 40]));
        assert!(accounting.snapshot_traffic(0).is_empty());

        accounting.restore_traffic(&snapshot);
        assert_eq!(accounting.snapshot_traffic(0).get(&1), Some(&[100, 40]));
    }

    #[test]
    fn keeps_small_traffic_until_threshold_is_met() {
        let accounting = Accounting::new();
        let counter = accounting.traffic_counter(1);
        counter.record_upload(10);
        counter.record_download(5);

        assert!(accounting.snapshot_traffic(20).is_empty());
        counter.record_upload(5);
        assert_eq!(accounting.snapshot_traffic(20).get(&1), Some(&[15, 5]));
    }
}
