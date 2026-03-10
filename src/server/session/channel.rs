use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

pub(super) enum InboundMessage {
    Data(Vec<u8>),
    Fin,
}

pub(super) struct ChannelReader {
    rx: mpsc::Receiver<InboundMessage>,
    current: Vec<u8>,
    offset: usize,
    finished: bool,
}

impl ChannelReader {
    pub(super) fn new(rx: mpsc::Receiver<InboundMessage>) -> Self {
        Self {
            rx,
            current: Vec::new(),
            offset: 0,
            finished: false,
        }
    }

    pub(super) fn into_parts(self) -> (Vec<u8>, mpsc::Receiver<InboundMessage>, bool) {
        let pending = if self.offset < self.current.len() {
            self.current[self.offset..].to_vec()
        } else {
            Vec::new()
        };
        (pending, self.rx, self.finished)
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut wrote_any = false;
        loop {
            if self.offset < self.current.len() {
                let remaining = &self.current[self.offset..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                wrote_any = true;
                self.offset += to_copy;
                if self.offset >= self.current.len() {
                    self.current.clear();
                    self.offset = 0;
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            if self.finished {
                return Poll::Ready(Ok(()));
            }

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(InboundMessage::Data(chunk))) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Poll::Ready(Some(InboundMessage::Fin)) | Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending if wrote_any => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
