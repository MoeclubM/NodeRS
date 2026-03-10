use anyhow::Error;
use md5::{Digest as Md5Digest, Md5};
use std::collections::HashMap;

pub(super) const CMD_WASTE: u8 = 0;
pub(super) const CMD_SYN: u8 = 1;
pub(super) const CMD_PSH: u8 = 2;
pub(super) const CMD_FIN: u8 = 3;
pub(super) const CMD_SETTINGS: u8 = 4;
pub(super) const CMD_ALERT: u8 = 5;
pub(super) const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub(super) const CMD_SYNACK: u8 = 7;
pub(super) const CMD_HEART_REQUEST: u8 = 8;
pub(super) const CMD_HEART_RESPONSE: u8 = 9;
pub(super) const CMD_SERVER_SETTINGS: u8 = 10;
pub(super) const MAX_FRAME_PAYLOAD_LEN: usize = u16::MAX as usize;
pub(super) const SMALL_DATA_FRAME_FLUSH_THRESHOLD: usize = 4 * 1024;
pub(super) const DOWNLOAD_COALESCE_TRIGGER: usize = 4 * 1024;
pub(super) const DOWNLOAD_COALESCE_TARGET: usize = 16 * 1024;
pub(super) const UPLOAD_BATCH_SIZE: usize = 128 * 1024;
pub(super) const UPLOAD_BATCH_IOVECS: usize = 32;
pub(super) const STREAM_INBOUND_QUEUE_CAPACITY: usize = 2048;

#[derive(Debug, Clone, Copy)]
pub(super) struct FrameHeader {
    pub(super) cmd: u8,
    pub(super) stream_id: u32,
    pub(super) length: u16,
}

pub(super) fn should_flush_frame(cmd: u8, payload_len: usize) -> bool {
    !matches!(cmd, CMD_PSH) || payload_len <= SMALL_DATA_FRAME_FLUSH_THRESHOLD
}

pub(super) fn parse_settings(bytes: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

pub(super) fn padding_md5(lines: &[String]) -> String {
    let mut hasher = Md5::new();
    hasher.update(lines.join("\n").as_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn is_eof(error: &Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
}
