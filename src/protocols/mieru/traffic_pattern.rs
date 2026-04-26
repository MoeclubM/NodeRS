use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use prost::Message;
use rand::RngExt;
use sha2::Digest as _;
use std::sync::atomic::{AtomicBool, Ordering};

const COMMON64_SET: &[u8; 64] = b"!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz<>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficPatternConfig {
    effective: TrafficPattern,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrafficPattern {
    pub tcp_fragment: TcpFragment,
    pub nonce: NoncePattern,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpFragment {
    pub enable: bool,
    pub max_sleep_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoncePattern {
    pub kind: NoncePatternKind,
    pub apply_to_all_udp_packets: bool,
    pub min_len: u32,
    pub max_len: u32,
    pub custom_prefixes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoncePatternKind {
    #[default]
    Random,
    Printable,
    PrintableSubset,
    Fixed,
}

#[derive(Debug)]
pub struct NoncePatternState {
    pattern: NoncePattern,
    applied_to_udp_packet: AtomicBool,
}

impl Default for TrafficPatternConfig {
    fn default() -> Self {
        Self {
            effective: generate_effective_pattern(proto::TrafficPattern::default()),
        }
    }
}

impl Clone for NoncePatternState {
    fn clone(&self) -> Self {
        Self {
            pattern: self.pattern.clone(),
            applied_to_udp_packet: AtomicBool::new(
                self.applied_to_udp_packet.load(Ordering::SeqCst),
            ),
        }
    }
}

impl TrafficPatternConfig {
    pub fn decode(encoded: &str) -> anyhow::Result<Self> {
        let encoded = encoded.trim();
        if encoded.is_empty() {
            return Ok(Self::default());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("decode Mieru traffic_pattern base64")?;
        let original = proto::TrafficPattern::decode(bytes.as_slice())
            .context("decode Mieru traffic_pattern protobuf")?;
        validate_pattern(&original)?;
        Ok(Self {
            effective: generate_effective_pattern(original),
        })
    }

    pub fn effective(&self) -> &TrafficPattern {
        &self.effective
    }
}

impl NoncePatternState {
    pub fn new(pattern: NoncePattern) -> Self {
        Self {
            pattern,
            applied_to_udp_packet: AtomicBool::new(false),
        }
    }

    pub fn rewrite_nonce(&self, nonce: &mut [u8], implicit_nonce: bool) {
        if self.pattern.kind == NoncePatternKind::Random {
            return;
        }
        if !implicit_nonce
            && self.applied_to_udp_packet.swap(true, Ordering::SeqCst)
            && !self.pattern.apply_to_all_udp_packets
        {
            return;
        }

        match self.pattern.kind {
            NoncePatternKind::Random => {}
            NoncePatternKind::Printable => {
                rewrite_printable(nonce, self.rewrite_len(nonce.len()), false);
            }
            NoncePatternKind::PrintableSubset => {
                rewrite_printable(nonce, self.rewrite_len(nonce.len()), true);
            }
            NoncePatternKind::Fixed => {
                if self.pattern.custom_prefixes.is_empty() {
                    return;
                }
                let index = if self.pattern.custom_prefixes.len() == 1 {
                    0
                } else {
                    rand::rng().random_range(0..self.pattern.custom_prefixes.len())
                };
                let prefix = &self.pattern.custom_prefixes[index];
                let copy_len = prefix.len().min(nonce.len());
                nonce[..copy_len].copy_from_slice(&prefix[..copy_len]);
            }
        }
    }

    fn rewrite_len(&self, nonce_len: usize) -> usize {
        let max_len = self.pattern.max_len.min(nonce_len as u32) as usize;
        let min_len = self.pattern.min_len.min(max_len as u32) as usize;
        if min_len >= max_len {
            min_len
        } else {
            rand::rng().random_range(min_len..=max_len)
        }
    }
}

fn rewrite_printable(nonce: &mut [u8], rewrite_len: usize, subset: bool) {
    for byte in nonce.iter_mut().take(rewrite_len) {
        if subset {
            *byte = COMMON64_SET[usize::from(*byte & 0x3f)];
            continue;
        }
        if (0x20..=0x7e).contains(byte) {
            continue;
        }
        let low_bits = *byte & 0x7f;
        if (0x20..=0x7e).contains(&low_bits) {
            *byte = low_bits;
        } else {
            *byte = rand::rng().random_range(0x20u8..=0x7eu8);
        }
    }
}

fn validate_pattern(pattern: &proto::TrafficPattern) -> anyhow::Result<()> {
    if let Some(fragment) = pattern.tcp_fragment.as_ref() {
        if let Some(max_sleep_ms) = fragment.max_sleep_ms {
            ensure!(
                max_sleep_ms >= 0,
                "Mieru traffic_pattern tcpFragment.maxSleepMs {max_sleep_ms} is negative"
            );
            ensure!(
                max_sleep_ms <= 100,
                "Mieru traffic_pattern tcpFragment.maxSleepMs {max_sleep_ms} exceeds maximum value 100"
            );
        }
    }

    if let Some(nonce) = pattern.nonce.as_ref() {
        validate_nonce_len("minLen", nonce.min_len)?;
        validate_nonce_len("maxLen", nonce.max_len)?;
        if let (Some(min_len), Some(max_len)) = (nonce.min_len, nonce.max_len) {
            ensure!(
                min_len <= max_len,
                "Mieru traffic_pattern nonce minLen {min_len} is greater than maxLen {max_len}"
            );
        }
        for hex_string in &nonce.custom_hex_strings {
            let decoded = hex::decode(hex_string).with_context(|| {
                format!(
                    "Mieru traffic_pattern nonce customHexStrings contains invalid hex string {hex_string:?}"
                )
            })?;
            ensure!(
                decoded.len() <= 12,
                "Mieru traffic_pattern nonce customHexStrings entry exceeds maximum 12 bytes"
            );
        }
    }

    Ok(())
}

fn validate_nonce_len(field: &str, value: Option<i32>) -> anyhow::Result<()> {
    if let Some(value) = value {
        if value < 0 {
            bail!("Mieru traffic_pattern nonce {field} {value} is negative");
        }
        if value > 12 {
            bail!("Mieru traffic_pattern nonce {field} {value} exceeds maximum value 12");
        }
    }
    Ok(())
}

fn generate_effective_pattern(original: proto::TrafficPattern) -> TrafficPattern {
    let seed = original
        .seed
        .unwrap_or_else(|| fixed_int_version_host(i32::MAX as usize) as i32);
    let unlock_all = original.unlock_all.unwrap_or(false);

    let mut tcp_fragment = original.tcp_fragment.unwrap_or_default();
    if tcp_fragment.enable.is_none() {
        tcp_fragment.enable = Some(if unlock_all {
            fixed_int(2, &format!("{seed}:tcpFragment.enable")) == 1
        } else {
            false
        });
    }
    if tcp_fragment.max_sleep_ms.is_none() {
        tcp_fragment.max_sleep_ms = Some(if unlock_all {
            (fixed_int(100, &format!("{seed}:tcpFragment.maxSleepMs")) + 1) as i32
        } else {
            0
        });
    }

    let mut nonce = original.nonce.unwrap_or_default();
    if nonce.r#type.is_none() {
        nonce.r#type = Some(if unlock_all {
            fixed_int(3, &format!("{seed}:nonce.type")) as i32
        } else {
            (fixed_int(2, &format!("{seed}:nonce.type")) + 1) as i32
        });
    }
    if nonce.apply_to_all_udp_packet.is_none() {
        nonce.apply_to_all_udp_packet =
            Some(fixed_int(2, &format!("{seed}:nonce.applyToAllUDPPacket")) == 1);
    }
    if nonce.min_len.is_none() {
        nonce.min_len = Some(if unlock_all {
            fixed_int(13, &format!("{seed}:nonce.minLen")) as i32
        } else {
            (fixed_int(7, &format!("{seed}:nonce.minLen")) + 6) as i32
        });
    }
    if nonce.max_len.is_none() {
        let min_len = nonce.min_len.unwrap_or(0).clamp(0, 12) as usize;
        nonce.max_len =
            Some((min_len + fixed_int(13 - min_len, &format!("{seed}:nonce.maxLen"))) as i32);
    }

    TrafficPattern {
        tcp_fragment: TcpFragment {
            enable: tcp_fragment.enable.unwrap_or(false),
            max_sleep_ms: tcp_fragment.max_sleep_ms.unwrap_or(0).max(0) as u32,
        },
        nonce: NoncePattern {
            kind: match nonce.r#type.unwrap_or(0) {
                1 => NoncePatternKind::Printable,
                2 => NoncePatternKind::PrintableSubset,
                3 => NoncePatternKind::Fixed,
                _ => NoncePatternKind::Random,
            },
            apply_to_all_udp_packets: nonce.apply_to_all_udp_packet.unwrap_or(false),
            min_len: nonce.min_len.unwrap_or(0).clamp(0, 12) as u32,
            max_len: nonce.max_len.unwrap_or(0).clamp(0, 12) as u32,
            custom_prefixes: nonce
                .custom_hex_strings
                .into_iter()
                .filter_map(|entry| hex::decode(entry).ok())
                .collect(),
        },
    }
}

fn fixed_int_version_host(n: usize) -> usize {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    fixed_int(n, &format!("{host} {}", env!("CARGO_PKG_VERSION")))
}

fn fixed_int(n: usize, hint: &str) -> usize {
    if n == 0 {
        return 0;
    }
    let digest = sha2::Sha256::digest(hint.as_bytes());
    let value = u32::from_be_bytes([digest[0] & 0x7f, digest[1], digest[2], digest[3]]) as usize;
    value % n
}

mod proto {
    use prost::Enumeration;
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct TrafficPattern {
        #[prost(int32, optional, tag = "1")]
        pub seed: Option<i32>,
        #[prost(bool, optional, tag = "2")]
        pub unlock_all: Option<bool>,
        #[prost(message, optional, tag = "3")]
        pub tcp_fragment: Option<TcpFragment>,
        #[prost(message, optional, tag = "4")]
        pub nonce: Option<NoncePattern>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct TcpFragment {
        #[prost(bool, optional, tag = "1")]
        pub enable: Option<bool>,
        #[prost(int32, optional, tag = "2")]
        pub max_sleep_ms: Option<i32>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct NoncePattern {
        #[prost(enumeration = "NonceType", optional, tag = "1")]
        pub r#type: Option<i32>,
        #[prost(bool, optional, tag = "2")]
        pub apply_to_all_udp_packet: Option<bool>,
        #[prost(int32, optional, tag = "3")]
        pub min_len: Option<i32>,
        #[prost(int32, optional, tag = "4")]
        pub max_len: Option<i32>,
        #[prost(string, repeated, tag = "5")]
        pub custom_hex_strings: Vec<String>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
    #[repr(i32)]
    pub enum NonceType {
        Random = 0,
        Printable = 1,
        PrintableSubset = 2,
        Fixed = 3,
    }
}

#[cfg(test)]
pub(crate) fn build_pattern_bytes_for_test() -> Vec<u8> {
    proto::TrafficPattern {
        seed: Some(12345),
        unlock_all: Some(true),
        tcp_fragment: Some(proto::TcpFragment {
            enable: Some(true),
            max_sleep_ms: Some(50),
        }),
        nonce: Some(proto::NoncePattern {
            r#type: Some(proto::NonceType::PrintableSubset as i32),
            apply_to_all_udp_packet: Some(true),
            min_len: Some(5),
            max_len: Some(10),
            custom_hex_strings: Vec::new(),
        }),
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(pattern: proto::TrafficPattern) -> String {
        base64::engine::general_purpose::STANDARD.encode(pattern.encode_to_vec())
    }

    #[test]
    fn decodes_empty_pattern_as_default() {
        let config = TrafficPatternConfig::decode("").expect("decode");
        assert!(config.effective().nonce.max_len >= config.effective().nonce.min_len);
        assert!(config.effective().nonce.max_len <= 12);
    }

    #[test]
    fn preserves_explicit_values() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(build_pattern_bytes_for_test());

        let config = TrafficPatternConfig::decode(&encoded).expect("decode");
        assert_eq!(config.effective().tcp_fragment.max_sleep_ms, 50);
        assert!(config.effective().tcp_fragment.enable);
        assert_eq!(
            config.effective().nonce.kind,
            NoncePatternKind::PrintableSubset
        );
        assert_eq!(config.effective().nonce.min_len, 5);
        assert_eq!(config.effective().nonce.max_len, 10);
    }

    #[test]
    fn rejects_invalid_nonce_ranges() {
        let encoded = encode(proto::TrafficPattern {
            nonce: Some(proto::NoncePattern {
                r#type: Some(proto::NonceType::Printable as i32),
                apply_to_all_udp_packet: None,
                min_len: Some(8),
                max_len: Some(4),
                custom_hex_strings: Vec::new(),
            }),
            ..proto::TrafficPattern {
                seed: None,
                unlock_all: None,
                tcp_fragment: None,
                nonce: None,
            }
        });
        let error = TrafficPatternConfig::decode(&encoded).expect_err("invalid ranges");
        assert!(error.to_string().contains("greater than maxLen"));
    }

    #[test]
    fn rewrites_nonce_with_fixed_prefix() {
        let state = NoncePatternState::new(NoncePattern {
            kind: NoncePatternKind::Fixed,
            custom_prefixes: vec![vec![0, 1, 2, 3]],
            ..Default::default()
        });
        let mut nonce = [0xff; 24];
        state.rewrite_nonce(&mut nonce, false);
        assert_eq!(&nonce[..4], &[0, 1, 2, 3]);
    }

    #[test]
    fn printable_subset_rewrite_uses_expected_charset() {
        let state = NoncePatternState::new(NoncePattern {
            kind: NoncePatternKind::PrintableSubset,
            min_len: 4,
            max_len: 4,
            ..Default::default()
        });
        let mut nonce = [0xff; 24];
        state.rewrite_nonce(&mut nonce, true);
        assert!(nonce[..4].iter().all(|byte| COMMON64_SET.contains(byte)));
    }
}
