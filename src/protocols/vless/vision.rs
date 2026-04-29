use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;
const VISION_HEADER_LEN: usize = 5;

enum ReadState {
    Initial,
    Header,
    Content {
        command: u8,
        remaining_content: usize,
        remaining_padding: usize,
    },
    Padding {
        command: u8,
        remaining_padding: usize,
    },
    Raw,
}

pub struct VisionReader<R> {
    inner: R,
    user: [u8; 16],
    state: ReadState,
    encoded: Vec<u8>,
    decoded: Vec<u8>,
    decoded_offset: usize,
}

impl<R> VisionReader<R> {
    pub fn new(inner: R, user: [u8; 16]) -> Self {
        Self {
            inner,
            user,
            state: ReadState::Initial,
            encoded: Vec::new(),
            decoded: Vec::new(),
            decoded_offset: 0,
        }
    }

    fn poll_decoded(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.decoded_offset >= self.decoded.len() {
            self.decoded.clear();
            self.decoded_offset = 0;
            return false;
        }
        let available = &self.decoded[self.decoded_offset..];
        let take = available.len().min(buf.remaining());
        buf.put_slice(&available[..take]);
        self.decoded_offset += take;
        true
    }

    fn decode_available(&mut self, eof: bool) -> Result<()> {
        loop {
            match self.state {
                ReadState::Initial => {
                    let prefix_len = self.encoded.len().min(self.user.len());
                    if self.encoded[..prefix_len] != self.user[..prefix_len] {
                        self.state = ReadState::Raw;
                        self.decoded.extend_from_slice(&self.encoded);
                        self.encoded.clear();
                        return Ok(());
                    }
                    if self.encoded.len() < self.user.len() + VISION_HEADER_LEN {
                        if eof {
                            self.state = ReadState::Raw;
                            self.decoded.extend_from_slice(&self.encoded);
                            self.encoded.clear();
                        }
                        return Ok(());
                    }
                    self.encoded.drain(..self.user.len());
                    self.state = ReadState::Header;
                }
                ReadState::Header => {
                    if self.encoded.len() < VISION_HEADER_LEN {
                        if eof && !self.encoded.is_empty() {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated VLESS Vision block header",
                            ));
                        }
                        return Ok(());
                    }
                    let command = self.encoded[0];
                    let content_len =
                        u16::from_be_bytes([self.encoded[1], self.encoded[2]]) as usize;
                    let padding_len =
                        u16::from_be_bytes([self.encoded[3], self.encoded[4]]) as usize;
                    self.encoded.drain(..VISION_HEADER_LEN);
                    self.state = ReadState::Content {
                        command,
                        remaining_content: content_len,
                        remaining_padding: padding_len,
                    };
                }
                ReadState::Content {
                    command,
                    remaining_content,
                    remaining_padding,
                } => {
                    if remaining_content == 0 {
                        self.state = ReadState::Padding {
                            command,
                            remaining_padding,
                        };
                        continue;
                    }
                    let take = remaining_content.min(self.encoded.len());
                    if take == 0 {
                        if eof {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated VLESS Vision content",
                            ));
                        }
                        return Ok(());
                    }
                    self.decoded.extend_from_slice(&self.encoded[..take]);
                    self.encoded.drain(..take);
                    self.state = ReadState::Content {
                        command,
                        remaining_content: remaining_content - take,
                        remaining_padding,
                    };
                    if !self.decoded.is_empty() {
                        return Ok(());
                    }
                }
                ReadState::Padding {
                    command,
                    remaining_padding,
                } => {
                    let take = remaining_padding.min(self.encoded.len());
                    if take == 0 && remaining_padding > 0 {
                        if eof {
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated VLESS Vision padding",
                            ));
                        }
                        return Ok(());
                    }
                    self.encoded.drain(..take);
                    let remaining_padding = remaining_padding - take;
                    if remaining_padding > 0 {
                        self.state = ReadState::Padding {
                            command,
                            remaining_padding,
                        };
                        return Ok(());
                    }
                    match command {
                        COMMAND_PADDING_CONTINUE => self.state = ReadState::Header,
                        COMMAND_PADDING_END | COMMAND_PADDING_DIRECT => {
                            self.state = ReadState::Raw;
                            self.decoded.extend_from_slice(&self.encoded);
                            self.encoded.clear();
                            return Ok(());
                        }
                        other => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                format!("unsupported VLESS Vision command {other:#x}"),
                            ));
                        }
                    }
                }
                ReadState::Raw => {
                    if !self.encoded.is_empty() {
                        self.decoded.extend_from_slice(&self.encoded);
                        self.encoded.clear();
                    }
                    return Ok(());
                }
            }
        }
    }
}

impl<R> AsyncRead for VisionReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        if self.poll_decoded(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            if matches!(self.state, ReadState::Raw) && self.encoded.is_empty() {
                return Pin::new(&mut self.inner).poll_read(cx, buf);
            }

            let mut scratch = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled().len();
                    if read == 0 {
                        self.decode_available(true)?;
                        if self.poll_decoded(buf) {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    self.encoded.extend_from_slice(read_buf.filled());
                    self.decode_available(false)?;
                    if self.poll_decoded(buf) {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub fn encode_end_frame(user: &[u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "VLESS Vision payload is too large",
        ));
    }
    let mut encoded = Vec::with_capacity(user.len() + VISION_HEADER_LEN + payload.len());
    encoded.extend_from_slice(user);
    encoded.push(COMMAND_PADDING_END);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&0u16.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

#[cfg(test)]
fn encode_direct_frame(user: &[u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "VLESS Vision payload is too large",
        ));
    }
    let mut encoded = Vec::with_capacity(user.len() + VISION_HEADER_LEN + payload.len());
    encoded.extend_from_slice(user);
    encoded.push(2);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&0u16.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn decodes_vision_frame_and_raw_tail() {
        let user = [7u8; 16];
        let mut bytes = encode_end_frame(&user, b"hello").expect("encode vision frame");
        bytes.extend_from_slice(b" world");

        let mut reader = VisionReader::new(bytes.as_slice(), user);
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .await
            .expect("decode vision body");

        assert_eq!(decoded, b"hello world");
    }

    #[tokio::test]
    async fn passes_plain_body_without_vision_prefix() {
        let user = [7u8; 16];
        let mut reader = VisionReader::new(b"plain".as_slice(), user);
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .await
            .expect("plain body should pass through");

        assert_eq!(decoded, b"plain");
    }

    #[tokio::test]
    async fn decodes_direct_command_and_raw_tail() {
        let user = [7u8; 16];
        let mut bytes = encode_direct_frame(&user, b"hello").expect("encode vision direct frame");
        bytes.extend_from_slice(b" world");

        let mut reader = VisionReader::new(bytes.as_slice(), user);
        let mut decoded = Vec::new();
        reader
            .read_to_end(&mut decoded)
            .await
            .expect("decode vision direct body");

        assert_eq!(decoded, b"hello world");
    }
}
