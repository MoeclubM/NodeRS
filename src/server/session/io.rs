use anyhow::{Context, ensure};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::accounting::SessionControl;
use crate::limiter::SharedRateLimiter;

use super::super::activity::ActivityTracker;
use super::super::traffic::TrafficRecorder;
use super::channel::InboundMessage;
use super::frame::{
    CMD_FIN, CMD_PSH, DOWNLOAD_COALESCE_TARGET, DOWNLOAD_COALESCE_TRIGGER, MAX_FRAME_PAYLOAD_LEN,
    SMALL_DATA_FRAME_FLUSH_THRESHOLD, UPLOAD_BATCH_IOVECS, UPLOAD_BATCH_SIZE,
};
use super::writer::{FrameWriter, write_frame};

pub(super) async fn pump_inbound_to_remote<W>(
    mut pending: Vec<u8>,
    mut rx: mpsc::Receiver<InboundMessage>,
    mut finished: bool,
    writer: &mut W,
    control: Arc<SessionControl>,
    traffic: Option<TrafficRecorder>,
) -> anyhow::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut chunks: VecDeque<Vec<u8>> = VecDeque::with_capacity(UPLOAD_BATCH_IOVECS);
    let mut front_offset = 0usize;
    let mut queued_bytes = 0usize;
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        if !pending.is_empty() {
            queued_bytes += pending.len();
            chunks.push_back(std::mem::take(&mut pending));
            front_offset = 0;
        }
        while queued_bytes < UPLOAD_BATCH_SIZE && chunks.len() < UPLOAD_BATCH_IOVECS && !finished {
            match rx.try_recv() {
                Ok(InboundMessage::Data(chunk)) => {
                    if chunks.is_empty()
                        || (queued_bytes + chunk.len() <= UPLOAD_BATCH_SIZE
                            && chunks.len() < UPLOAD_BATCH_IOVECS)
                    {
                        queued_bytes += chunk.len();
                        chunks.push_back(chunk);
                    } else {
                        pending = chunk;
                        break;
                    }
                }
                Ok(InboundMessage::Fin) => {
                    finished = true;
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        if chunks.is_empty() {
            if finished {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            match tokio::select! {
                _ = control.cancelled() => return Ok(total),
                message = rx.recv() => message,
            } {
                Some(InboundMessage::Data(chunk)) => {
                    pending = chunk;
                    continue;
                }
                Some(InboundMessage::Fin) | None => {
                    let _ = writer.shutdown().await;
                    return Ok(total);
                }
            }
        }
        let written = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = write_chunk_batch(writer, &chunks, front_offset) => result?,
        };
        ensure!(written > 0, "write inbound batch returned zero bytes");
        advance_chunk_batch(&mut chunks, &mut front_offset, written);
        queued_bytes = queued_bytes.saturating_sub(written);
        let transferred = written as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if finished && pending.is_empty() && chunks.is_empty() {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
    }
}

pub(super) async fn pump_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    traffic: Option<TrafficRecorder>,
    activity: Option<Arc<ActivityTracker>>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        let chunk_len = limiter
            .as_ref()
            .map(|limiter| limiter.chunk_size(buffer.len()))
            .unwrap_or(buffer.len());
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer[..chunk_len]) => read.context("read throttled chunk")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => {
                result.context("write throttled chunk")?;
            }
        }
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if let Some(activity) = activity.as_ref() {
            activity.record();
        }
        if let Some(limiter) = &limiter {
            tokio::select! {
                _ = control.cancelled() => return Ok(total),
                _ = limiter.consume(read) => {}
            }
        }
    }
}

pub(super) async fn pump_remote_to_client<R>(
    reader: &mut R,
    writer: FrameWriter,
    stream_id: u32,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    traffic: Option<TrafficRecorder>,
    activity: Option<Arc<ActivityTracker>>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        let chunk_len = limiter
            .as_ref()
            .map(|limiter| limiter.chunk_size(buffer.len()))
            .unwrap_or(buffer.len());
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer[..chunk_len]) => read?,
        };
        if read == 0 {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(total);
        }
        let (read, saw_eof) = if limiter.is_none() && read < DOWNLOAD_COALESCE_TRIGGER {
            coalesce_download_reads(reader, &mut buffer, read).await?
        } else {
            (read, false)
        };
        write_frame(&writer, CMD_PSH, stream_id, &buffer[..read]).await?;
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if let Some(activity) = activity.as_ref() {
            activity.record();
        }
        if let Some(limiter) = &limiter {
            tokio::select! {
                _ = control.cancelled() => return Ok(total),
                _ = limiter.consume(read) => {}
            }
        }
        if saw_eof {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(total);
        }
    }
}

async fn write_chunk_batch<W>(
    writer: &mut W,
    chunks: &VecDeque<Vec<u8>>,
    front_offset: usize,
) -> anyhow::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if chunks.is_empty() {
        return Ok(0);
    }
    if writer.is_write_vectored() {
        let mut slices: [IoSlice<'_>; UPLOAD_BATCH_IOVECS] =
            std::array::from_fn(|_| IoSlice::new(&[]));
        let count = fill_chunk_batch_slices(chunks, front_offset, &mut slices);
        if count == 0 {
            return Ok(0);
        }
        return writer
            .write_vectored(&slices[..count])
            .await
            .context("write inbound chunk batch");
    }

    let Some(front) = chunks.front() else {
        return Ok(0);
    };
    writer
        .write(&front[front_offset..])
        .await
        .context("write inbound chunk")
}

pub(super) async fn coalesce_download_reads<R>(
    reader: &mut R,
    buffer: &mut [u8],
    mut filled: usize,
) -> anyhow::Result<(usize, bool)>
where
    R: AsyncRead + Unpin,
{
    let target = DOWNLOAD_COALESCE_TARGET.min(buffer.len());
    let mut saw_eof = false;
    while filled < target {
        match try_read_available(reader, &mut buffer[filled..target]).await? {
            Some(0) => {
                saw_eof = true;
                break;
            }
            Some(read) => {
                filled += read;
                if read >= SMALL_DATA_FRAME_FLUSH_THRESHOLD {
                    break;
                }
            }
            None => break,
        }
    }
    Ok((filled, saw_eof))
}

async fn try_read_available<R>(reader: &mut R, buffer: &mut [u8]) -> std::io::Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buffer);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

fn fill_chunk_batch_slices<'a>(
    chunks: &'a VecDeque<Vec<u8>>,
    front_offset: usize,
    slices: &mut [IoSlice<'a>],
) -> usize {
    let mut count = 0usize;
    let mut remaining = UPLOAD_BATCH_SIZE;
    for (index, chunk) in chunks.iter().enumerate() {
        if count >= slices.len() || count >= UPLOAD_BATCH_IOVECS || remaining == 0 {
            break;
        }
        let slice = if index == 0 {
            &chunk[front_offset..]
        } else {
            chunk.as_slice()
        };
        if slice.is_empty() {
            continue;
        }
        let used = slice.len().min(remaining);
        slices[count] = IoSlice::new(&slice[..used]);
        count += 1;
        remaining -= used;
    }
    count
}

#[cfg(test)]
pub(super) fn chunk_batch_slices(
    chunks: &VecDeque<Vec<u8>>,
    front_offset: usize,
) -> Vec<IoSlice<'_>> {
    let mut slices: [IoSlice<'_>; UPLOAD_BATCH_IOVECS] = std::array::from_fn(|_| IoSlice::new(&[]));
    let count = fill_chunk_batch_slices(chunks, front_offset, &mut slices);
    slices.into_iter().take(count).collect()
}

pub(super) fn advance_chunk_batch(
    chunks: &mut VecDeque<Vec<u8>>,
    front_offset: &mut usize,
    mut written: usize,
) {
    while written > 0 {
        let Some(front) = chunks.front() else {
            *front_offset = 0;
            break;
        };
        let remaining = front.len().saturating_sub(*front_offset);
        if written < remaining {
            *front_offset += written;
            break;
        }
        written -= remaining;
        chunks.pop_front();
        *front_offset = 0;
    }
}
