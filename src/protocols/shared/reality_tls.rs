use anyhow::{Context, anyhow, bail, ensure};
use boring::aead::{AeadCtx, Algorithm as AeadAlgorithm};
use boring::derive::Deriver;
use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPublicKey};
use boring::pkey::{Id, PKey, Private, Public};
use boring::rand::rand_bytes;
use boring::sign::Signer;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;

use super::reality::{
    AuthenticatedClientHello, ClientHelloDetails, ClientKeyShare, RawClientHello,
    RealityCertificateState, build_server_certificate,
};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_MAX_PLAINTEXT_LEN: usize = 16 * 1024;
const TLS_ALERT_CLOSE_NOTIFY: u8 = 0;
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const TLS_CONTENT_TYPE_ALERT: u8 = 21;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
const TLS_HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
const TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
const TLS_HANDSHAKE_TYPE_FINISHED: u8 = 20;
const TLS_HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
const TLS_SIGNATURE_SCHEME_ED25519: u16 = 0x0807;
const TLS_ALERT_WARNING: u8 = 1;
const TLS_GROUP_X25519: u16 = 29;
const TLS_GROUP_X25519_KYBER768_DRAFT00: u16 = 0x6399;
const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const TLS_KYBER768_PUBLIC_KEY_BYTES: usize = 1184;
const TLS_KYBER768_CIPHERTEXT_BYTES: usize = 1088;
const TLS_MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
const TLS_MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
const REALITY_PIPE_CAPACITY: usize = 64 * 1024;
const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
const TLS13_SERVER_CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityTlsProfile {
    pub cipher_suite: u16,
    pub key_share_group: u16,
}

pub struct RealityTlsStream {
    local_addr: SocketAddr,
    server_name: String,
    reader: DuplexStream,
    writer: DuplexStream,
    read_task: JoinHandle<anyhow::Result<()>>,
    write_task: JoinHandle<anyhow::Result<()>>,
}

pub struct RealityTlsAcceptError {
    stream: TcpStream,
    sent_server_flight: bool,
    error: anyhow::Error,
}

impl RealityTlsAcceptError {
    fn new(stream: TcpStream, sent_server_flight: bool, error: anyhow::Error) -> Self {
        Self {
            stream,
            sent_server_flight,
            error,
        }
    }

    pub fn sent_server_flight(&self) -> bool {
        self.sent_server_flight
    }

    pub fn into_parts(self) -> (TcpStream, anyhow::Error) {
        (self.stream, self.error)
    }
}

impl RealityTlsStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn server_name(&self) -> Option<&str> {
        Some(self.server_name.as_str())
    }

    pub fn selected_alpn_protocol(&self) -> Option<&[u8]> {
        None
    }

    pub fn fallback_alpn_protocol(&self) -> Option<&[u8]> {
        None
    }
}

impl Drop for RealityTlsStream {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

impl AsyncRead for RealityTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

pub async fn accept(
    mut stream: TcpStream,
    client_hello: &RawClientHello,
    client_details: &ClientHelloDetails,
    authenticated: &AuthenticatedClientHello,
    cert_state: &RealityCertificateState,
    profile: RealityTlsProfile,
    handshake_timeout: Duration,
) -> Result<RealityTlsStream, RealityTlsAcceptError> {
    let prepared = (|| -> anyhow::Result<_> {
        let suite = CipherSuite::from_id(profile.cipher_suite)?;
        let server_share =
            ServerKeyShare::generate(profile.key_share_group, &client_details.key_shares)
                .context("generate REALITY server key share")?;
        let certificate_der = build_server_certificate(cert_state, &authenticated.auth_key)
            .context("build REALITY certificate")?
            .to_der()
            .context("encode REALITY certificate")?;

        let server_hello = build_server_hello(
            client_details.session_id.as_slice(),
            profile.cipher_suite,
            profile.key_share_group,
            server_share.server_share(),
        )
        .context("build REALITY ServerHello")?;
        let encrypted_extensions =
            build_encrypted_extensions().context("build REALITY EncryptedExtensions")?;
        let certificate =
            build_certificate_message(&certificate_der).context("build REALITY Certificate")?;

        let mut transcript = TranscriptHash::new(suite.hash_kind());
        transcript.update(&client_hello.handshake);
        transcript.update(&server_hello);

        let mut key_schedule = Tls13KeySchedule::new(suite.hash_kind());
        key_schedule.input_secret(server_share.shared_secret());
        let server_hello_hash = transcript.finish();
        let client_handshake_secret =
            key_schedule.derive_secret(b"c hs traffic", &server_hello_hash)?;
        let server_handshake_secret =
            key_schedule.derive_secret(b"s hs traffic", &server_hello_hash)?;

        let handshake_writer = RecordCipher::new(suite, &server_handshake_secret)
            .context("create REALITY handshake writer")?;
        let handshake_reader = RecordCipher::new(suite, &client_handshake_secret)
            .context("create REALITY handshake reader")?;

        transcript.update(&encrypted_extensions);
        transcript.update(&certificate);
        let certificate_verify = build_certificate_verify(
            cert_state.private_key(),
            suite.hash_kind(),
            &transcript.finish(),
        )
        .context("build REALITY CertificateVerify")?;
        transcript.update(&certificate_verify);

        let finished = build_finished(
            suite.hash_kind(),
            &server_handshake_secret,
            &transcript.finish(),
        )
        .context("build REALITY Finished")?;
        transcript.update(&finished);
        let after_server_finished_hash = transcript.finish();

        key_schedule.input_empty();
        let client_application_secret = key_schedule
            .derive_secret(b"c ap traffic", &after_server_finished_hash)
            .context("derive REALITY client application secret")?;
        let server_application_secret = key_schedule
            .derive_secret(b"s ap traffic", &after_server_finished_hash)
            .context("derive REALITY server application secret")?;

        Ok((
            suite,
            server_hello,
            encrypted_extensions,
            certificate,
            certificate_verify,
            finished,
            client_handshake_secret,
            after_server_finished_hash,
            client_application_secret,
            server_application_secret,
            handshake_writer,
            handshake_reader,
        ))
    })();

    let (
        suite,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
        finished,
        client_handshake_secret,
        after_server_finished_hash,
        client_application_secret,
        server_application_secret,
        mut handshake_writer,
        mut handshake_reader,
    ) = match prepared {
        Ok(value) => value,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
    };

    let server_hello_record =
        match encode_tls_plaintext_record(TLS_CONTENT_TYPE_HANDSHAKE, &server_hello) {
            Ok(record) => record,
            Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
        };
    let change_cipher_spec_record =
        match encode_tls_plaintext_record(TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1]) {
            Ok(record) => record,
            Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
        };
    let encrypted_extensions_record = match handshake_writer
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &encrypted_extensions)
        .context("encrypt REALITY EncryptedExtensions")
    {
        Ok(record) => record,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
    };
    let certificate_record = match handshake_writer
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &certificate)
        .context("encrypt REALITY Certificate")
    {
        Ok(record) => record,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
    };
    let certificate_verify_record = match handshake_writer
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &certificate_verify)
        .context("encrypt REALITY CertificateVerify")
    {
        Ok(record) => record,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
    };
    let finished_record = match handshake_writer
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &finished)
        .context("encrypt REALITY Finished")
    {
        Ok(record) => record,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, false, error)),
    };

    if let Err(error) = stream.write_all(&server_hello_record).await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }
    if let Err(error) = stream.write_all(&change_cipher_spec_record).await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }
    if let Err(error) = stream.write_all(&encrypted_extensions_record).await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }
    if let Err(error) = stream.write_all(&certificate_record).await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }
    if let Err(error) = stream.write_all(&certificate_verify_record).await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }
    if let Err(error) = stream.write_all(&finished_record).await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }
    if let Err(error) = stream.flush().await {
        return Err(RealityTlsAcceptError::new(stream, true, error.into()));
    }

    let client_finished = match tokio::time::timeout(
        handshake_timeout,
        read_finished_message(&mut stream, &mut handshake_reader),
    )
    .await
    {
        Ok(Ok(finished)) => finished,
        Ok(Err(error)) => return Err(RealityTlsAcceptError::new(stream, true, error)),
        Err(_) => {
            return Err(RealityTlsAcceptError::new(
                stream,
                true,
                anyhow!("REALITY TLS handshake timed out"),
            ));
        }
    };
    if let Err(error) = verify_finished(
        suite.hash_kind(),
        &client_handshake_secret,
        &after_server_finished_hash,
        &client_finished,
    ) {
        return Err(RealityTlsAcceptError::new(stream, true, error));
    }

    let reader_cipher = match RecordCipher::new(suite, &client_application_secret)
        .context("create REALITY application reader")
    {
        Ok(cipher) => cipher,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, true, error)),
    };
    let writer_cipher = match RecordCipher::new(suite, &server_application_secret)
        .context("create REALITY application writer")
    {
        Ok(cipher) => cipher,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, true, error)),
    };
    let local_addr = match stream.local_addr().context("read REALITY local address") {
        Ok(local_addr) => local_addr,
        Err(error) => return Err(RealityTlsAcceptError::new(stream, true, error)),
    };
    Ok(spawn_reality_stream(
        stream,
        local_addr,
        authenticated.server_name.clone(),
        reader_cipher,
        writer_cipher,
    ))
}

fn spawn_reality_stream(
    stream: TcpStream,
    local_addr: SocketAddr,
    server_name: String,
    reader_cipher: RecordCipher,
    writer_cipher: RecordCipher,
) -> RealityTlsStream {
    let (inbound_sink, reader) = duplex(REALITY_PIPE_CAPACITY);
    let (writer, outbound_source) = duplex(REALITY_PIPE_CAPACITY);
    let (stream_reader, stream_writer) = stream.into_split();
    let (control_tx, control_rx) = unbounded_channel();

    let read_task = tokio::spawn(async move {
        pump_inbound(stream_reader, inbound_sink, reader_cipher, control_tx).await
    });
    let write_task = tokio::spawn(async move {
        pump_outbound(stream_writer, outbound_source, writer_cipher, control_rx).await
    });

    RealityTlsStream {
        local_addr,
        server_name,
        reader,
        writer,
        read_task,
        write_task,
    }
}

async fn pump_inbound(
    mut stream: tokio::net::tcp::OwnedReadHalf,
    mut sink: DuplexStream,
    mut cipher: RecordCipher,
    control: UnboundedSender<OutboundControl>,
) -> anyhow::Result<()> {
    loop {
        let Some(record) = read_tls_record(&mut stream).await? else {
            let _ = control.send(OutboundControl::CloseNotify);
            sink.shutdown().await.ok();
            return Ok(());
        };
        match record.content_type {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                ensure!(
                    record.payload == [1],
                    "invalid REALITY ChangeCipherSpec payload"
                );
            }
            TLS_CONTENT_TYPE_ALERT => {
                if record.payload.len() == 2 && record.payload[1] == TLS_ALERT_CLOSE_NOTIFY {
                    let _ = control.send(OutboundControl::CloseNotify);
                    sink.shutdown().await.ok();
                    return Ok(());
                }
                bail!("REALITY peer sent alert {:?}", record.payload);
            }
            TLS_CONTENT_TYPE_APPLICATION_DATA => {
                let decrypted = cipher
                    .decrypt_record(record.content_type, &record.payload)
                    .context("decrypt REALITY application record")?;
                match decrypted.content_type {
                    TLS_CONTENT_TYPE_APPLICATION_DATA => {
                        sink.write_all(&decrypted.payload)
                            .await
                            .context("write REALITY plaintext into pipe")?;
                    }
                    TLS_CONTENT_TYPE_ALERT => {
                        if decrypted.payload.len() == 2
                            && decrypted.payload[1] == TLS_ALERT_CLOSE_NOTIFY
                        {
                            let _ = control.send(OutboundControl::CloseNotify);
                            sink.shutdown().await.ok();
                            return Ok(());
                        }
                        bail!("REALITY peer sent encrypted alert {:?}", decrypted.payload);
                    }
                    TLS_CONTENT_TYPE_HANDSHAKE => {
                        let mut handshake_messages = decrypted.payload.as_slice();
                        while !handshake_messages.is_empty() {
                            let consumed = handle_post_handshake_message(
                                &mut cipher,
                                handshake_messages,
                                &control,
                            )?;
                            handshake_messages = &handshake_messages[consumed..];
                        }
                    }
                    other => {
                        bail!("unexpected REALITY inner content type {other}");
                    }
                }
            }
            other => {
                bail!("unexpected REALITY record type {other}");
            }
        }
    }
}

async fn pump_outbound(
    mut stream: tokio::net::tcp::OwnedWriteHalf,
    mut source: DuplexStream,
    mut cipher: RecordCipher,
    mut control: UnboundedReceiver<OutboundControl>,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; TLS_MAX_PLAINTEXT_LEN];
    let mut control_closed = false;
    loop {
        tokio::select! {
            biased;
            command = control.recv(), if !control_closed => {
                match command {
                    Some(OutboundControl::KeyUpdate) => {
                        send_key_update(&mut stream, &mut cipher).await?;
                    }
                    Some(OutboundControl::CloseNotify) => {
                        send_close_notify(&mut stream, &mut cipher).await.ok();
                        stream.shutdown().await.ok();
                        return Ok(());
                    }
                    None => {
                        control_closed = true;
                    }
                }
            }
            read = source.read(&mut buffer) => {
                let read = read.context("read REALITY plaintext from pipe")?;
                if read == 0 {
                    send_close_notify(&mut stream, &mut cipher).await.ok();
                    stream.shutdown().await.ok();
                    return Ok(());
                }
                let record = cipher
                    .encrypt_record(TLS_CONTENT_TYPE_APPLICATION_DATA, &buffer[..read])
                    .context("encrypt REALITY application record")?;
                stream
                    .write_all(&record)
                    .await
                    .context("write REALITY application record")?;
                stream.flush().await.ok();
            }
        }
    }
}

fn handle_post_handshake_message(
    cipher: &mut RecordCipher,
    bytes: &[u8],
    control: &UnboundedSender<OutboundControl>,
) -> anyhow::Result<usize> {
    ensure!(
        bytes.len() >= 4,
        "truncated REALITY post-handshake message header"
    );
    let message_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    let total_len = 4 + message_len;
    ensure!(
        bytes.len() >= total_len,
        "truncated REALITY post-handshake message body"
    );
    match bytes[0] {
        TLS_HANDSHAKE_TYPE_KEY_UPDATE => {
            ensure!(message_len == 1, "REALITY KeyUpdate payload must be 1 byte");
            let request_update = bytes[4];
            ensure!(
                request_update <= 1,
                "REALITY KeyUpdate request_update must be 0 or 1"
            );
            cipher
                .update_key()
                .context("update REALITY application traffic key")?;
            if request_update == 1 {
                let _ = control.send(OutboundControl::KeyUpdate);
            }
        }
        other => bail!("unsupported REALITY post-handshake message type {other}"),
    }
    Ok(total_len)
}

async fn send_close_notify(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    cipher: &mut RecordCipher,
) -> anyhow::Result<()> {
    let record = cipher
        .encrypt_record(
            TLS_CONTENT_TYPE_ALERT,
            &[TLS_ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY],
        )
        .context("encrypt REALITY close_notify")?;
    stream
        .write_all(&record)
        .await
        .context("write REALITY close_notify")?;
    stream.flush().await.context("flush REALITY close_notify")
}

async fn send_key_update(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    cipher: &mut RecordCipher,
) -> anyhow::Result<()> {
    let message = build_handshake_message(TLS_HANDSHAKE_TYPE_KEY_UPDATE, &[0])
        .context("build REALITY KeyUpdate")?;
    let record = cipher
        .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &message)
        .context("encrypt REALITY KeyUpdate")?;
    stream
        .write_all(&record)
        .await
        .context("write REALITY KeyUpdate")?;
    stream.flush().await.context("flush REALITY KeyUpdate")?;
    cipher
        .update_key()
        .context("update REALITY send traffic key")
}

async fn read_finished_message(
    stream: &mut TcpStream,
    cipher: &mut RecordCipher,
) -> anyhow::Result<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut expected = None;
    loop {
        let Some(record) = read_tls_record(stream).await? else {
            bail!("unexpected EOF before REALITY client Finished");
        };
        match record.content_type {
            TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                ensure!(
                    record.payload == [1],
                    "invalid REALITY ChangeCipherSpec payload"
                );
            }
            TLS_CONTENT_TYPE_APPLICATION_DATA => {
                let decrypted = cipher
                    .decrypt_record(record.content_type, &record.payload)
                    .context("decrypt REALITY client handshake record")?;
                ensure!(
                    decrypted.content_type == TLS_CONTENT_TYPE_HANDSHAKE,
                    "REALITY expected encrypted handshake record during client Finished"
                );
                handshake.extend_from_slice(&decrypted.payload);
                if handshake.len() >= 4 && expected.is_none() {
                    ensure!(
                        handshake[0] == TLS_HANDSHAKE_TYPE_FINISHED,
                        "REALITY expected client Finished handshake message"
                    );
                    let declared_len = ((handshake[1] as usize) << 16)
                        | ((handshake[2] as usize) << 8)
                        | handshake[3] as usize;
                    expected = Some(4 + declared_len);
                }
                if let Some(expected) = expected {
                    if handshake.len() >= expected {
                        ensure!(
                            handshake.len() == expected,
                            "REALITY client Finished contained trailing handshake bytes"
                        );
                        return Ok(handshake);
                    }
                }
            }
            TLS_CONTENT_TYPE_ALERT => {
                bail!("REALITY peer sent plaintext alert before Finished");
            }
            other => {
                bail!("unexpected REALITY record type {other} before client Finished");
            }
        }
    }
}

fn verify_finished(
    hash_kind: HashKind,
    base_key: &[u8],
    transcript_hash: &[u8],
    finished: &[u8],
) -> anyhow::Result<()> {
    ensure!(
        finished.len() >= 4 && finished[0] == TLS_HANDSHAKE_TYPE_FINISHED,
        "REALITY client Finished is malformed"
    );
    let declared_len =
        ((finished[1] as usize) << 16) | ((finished[2] as usize) << 8) | finished[3] as usize;
    ensure!(
        finished.len() == 4 + declared_len,
        "REALITY client Finished length mismatch"
    );
    let expected = finished_verify_data(hash_kind, base_key, transcript_hash)?;
    ensure!(
        finished[4..] == expected,
        "REALITY client Finished verify_data mismatch"
    );
    Ok(())
}

fn build_finished(
    hash_kind: HashKind,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let verify_data = finished_verify_data(hash_kind, base_key, transcript_hash)?;
    build_handshake_message(TLS_HANDSHAKE_TYPE_FINISHED, &verify_data)
}

fn finished_verify_data(
    hash_kind: HashKind,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let finished_key = hkdf_expand_label(
        hash_kind,
        base_key,
        b"finished",
        &[],
        hash_kind.output_len(),
    )?;
    Ok(hash_kind.hmac(&finished_key, transcript_hash))
}

fn build_certificate_verify(
    private_key: &PKey<Private>,
    hash_kind: HashKind,
    transcript_hash: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut signed = vec![0x20; 64];
    signed.extend_from_slice(TLS13_SERVER_CERT_VERIFY_CONTEXT);
    signed.push(0);
    signed.extend_from_slice(transcript_hash);

    let mut signer =
        Signer::new_without_digest(private_key).context("initialize REALITY Ed25519 signer")?;
    let signature = signer
        .sign_oneshot_to_vec(&signed)
        .context("sign REALITY CertificateVerify")?;
    let mut body = Vec::with_capacity(4 + signature.len());
    body.extend_from_slice(&TLS_SIGNATURE_SCHEME_ED25519.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&signature);
    let _ = hash_kind;
    build_handshake_message(TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, &body)
}

fn build_certificate_message(certificate_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + certificate_der.len());
    body.push(0);

    let mut entry = Vec::with_capacity(5 + certificate_der.len());
    entry.extend_from_slice(&encode_u24(certificate_der.len())?);
    entry.extend_from_slice(certificate_der);
    entry.extend_from_slice(&0u16.to_be_bytes());

    body.extend_from_slice(&encode_u24(entry.len())?);
    body.extend_from_slice(&entry);
    build_handshake_message(TLS_HANDSHAKE_TYPE_CERTIFICATE, &body)
}

fn build_encrypted_extensions() -> anyhow::Result<Vec<u8>> {
    let body = [0u8, 0u8];
    let mut handshake = Vec::with_capacity(6);
    handshake.push(TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);
    handshake.extend_from_slice(&encode_u24(body.len())?);
    handshake.extend_from_slice(&body);
    Ok(handshake)
}

fn build_server_hello(
    session_id: &[u8],
    cipher_suite: u16,
    group: u16,
    key_share: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut random = [0u8; 32];
    rand_bytes(&mut random).context("generate REALITY ServerHello random")?;

    let mut extensions = Vec::with_capacity(16 + key_share.len());
    extensions.extend_from_slice(&43u16.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes());
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());

    let mut key_share_extension = Vec::with_capacity(4 + key_share.len());
    key_share_extension.extend_from_slice(&group.to_be_bytes());
    key_share_extension.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_extension.extend_from_slice(key_share);
    extensions.extend_from_slice(&51u16.to_be_bytes());
    extensions.extend_from_slice(&(key_share_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share_extension);

    let mut body = Vec::with_capacity(42 + session_id.len() + extensions.len());
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    build_handshake_message(2, &body)
}

fn build_handshake_message(handshake_type: u8, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(handshake_type);
    message.extend_from_slice(&encode_u24(body.len())?);
    message.extend_from_slice(body);
    Ok(message)
}

fn encode_tls_plaintext_record(content_type: u8, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "REALITY plaintext record is too large"
    );
    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    record.push(content_type);
    record.extend_from_slice(&0x0303u16.to_be_bytes());
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    Ok(record)
}

async fn read_tls_record<R>(reader: &mut R) -> anyhow::Result<Option<TlsRecord>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    let Some(()) = read_exact_or_eof(reader, &mut header).await? else {
        return Ok(None);
    };
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read REALITY TLS record payload")?;
    Ok(Some(TlsRecord {
        content_type: header[0],
        payload,
    }))
}

async fn read_exact_or_eof<R>(reader: &mut R, buffer: &mut [u8]) -> anyhow::Result<Option<()>>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0;
    while offset < buffer.len() {
        let read = reader
            .read(&mut buffer[offset..])
            .await
            .context("read REALITY TLS record header")?;
        if read == 0 {
            ensure!(offset == 0, "unexpected EOF in REALITY TLS record header");
            return Ok(None);
        }
        offset += read;
    }
    Ok(Some(()))
}

#[derive(Debug)]
struct TlsRecord {
    content_type: u8,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct DecryptedRecord {
    content_type: u8,
    payload: Vec<u8>,
}

struct RecordCipher {
    suite: CipherSuite,
    traffic_secret: Vec<u8>,
    context: AeadCtx,
    iv: [u8; 12],
    sequence: u64,
}

enum OutboundControl {
    KeyUpdate,
    CloseNotify,
}

impl RecordCipher {
    fn new(suite: CipherSuite, secret: &[u8]) -> anyhow::Result<Self> {
        let key = hkdf_expand_label(suite.hash_kind(), secret, b"key", &[], suite.key_len())?;
        let iv = hkdf_expand_label(suite.hash_kind(), secret, b"iv", &[], 12)?;
        let context = AeadCtx::new_default_tag(&suite.aead_algorithm(), &key)
            .context("create REALITY AEAD context")?;
        let mut nonce_iv = [0u8; 12];
        nonce_iv.copy_from_slice(&iv);
        Ok(Self {
            suite,
            traffic_secret: secret.to_vec(),
            context,
            iv: nonce_iv,
            sequence: 0,
        })
    }

    fn encrypt_record(
        &mut self,
        inner_content_type: u8,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        ensure!(
            plaintext.len() < TLS_MAX_PLAINTEXT_LEN,
            "REALITY plaintext chunk exceeds TLS record limit"
        );
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(inner_content_type);
        let mut tag = vec![0u8; self.suite.tag_len()];
        let header = build_encrypted_record_header(inner.len() + tag.len())?;
        let nonce = build_nonce(self.iv, self.sequence);
        let written_tag = self
            .context
            .seal_in_place(&nonce, &mut inner, &mut tag, &header)
            .context("seal REALITY TLS record")?;
        self.sequence += 1;

        let mut record = header;
        record.extend_from_slice(&inner);
        record.extend_from_slice(written_tag);
        Ok(record)
    }

    fn decrypt_record(
        &mut self,
        record_type: u8,
        payload: &[u8],
    ) -> anyhow::Result<DecryptedRecord> {
        ensure!(
            record_type == TLS_CONTENT_TYPE_APPLICATION_DATA,
            "REALITY expected encrypted application_data record"
        );
        ensure!(
            payload.len() >= self.suite.tag_len(),
            "REALITY encrypted record is too short"
        );
        let header = build_encrypted_record_header(payload.len())?;
        let nonce = build_nonce(self.iv, self.sequence);
        let ciphertext_len = payload.len() - self.suite.tag_len();
        let mut ciphertext = payload[..ciphertext_len].to_vec();
        self.context
            .open_in_place(&nonce, &mut ciphertext, &payload[ciphertext_len..], &header)
            .context("open REALITY TLS record")?;
        self.sequence += 1;

        let content_type_offset = ciphertext
            .iter()
            .rposition(|byte| *byte != 0)
            .context("REALITY decrypted record is missing content type")?;
        let content_type = ciphertext[content_type_offset];
        ciphertext.truncate(content_type_offset);
        Ok(DecryptedRecord {
            content_type,
            payload: ciphertext,
        })
    }

    fn update_key(&mut self) -> anyhow::Result<()> {
        let next_secret = hkdf_expand_label(
            self.suite.hash_kind(),
            &self.traffic_secret,
            b"traffic upd",
            &[],
            self.suite.hash_kind().output_len(),
        )?;
        *self = Self::new(self.suite, &next_secret)?;
        Ok(())
    }
}

fn build_encrypted_record_header(payload_len: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(
        payload_len <= u16::MAX as usize,
        "REALITY encrypted record is too large"
    );
    let mut header = Vec::with_capacity(TLS_RECORD_HEADER_LEN);
    header.push(TLS_CONTENT_TYPE_APPLICATION_DATA);
    header.extend_from_slice(&0x0303u16.to_be_bytes());
    header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    Ok(header)
}

fn build_nonce(iv: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = iv;
    let sequence = sequence.to_be_bytes();
    for (index, byte) in sequence.iter().enumerate() {
        nonce[4 + index] ^= *byte;
    }
    nonce
}

#[derive(Clone, Copy)]
struct CipherSuite {
    cipher_suite: u16,
}

impl CipherSuite {
    fn from_id(cipher_suite: u16) -> anyhow::Result<Self> {
        ensure!(
            matches!(cipher_suite, 0x1301 | 0x1302 | 0x1303),
            "unsupported REALITY cipher suite 0x{cipher_suite:04x}"
        );
        Ok(Self { cipher_suite })
    }

    fn hash_kind(self) -> HashKind {
        match self.cipher_suite {
            0x1302 => HashKind::Sha384,
            _ => HashKind::Sha256,
        }
    }

    fn key_len(self) -> usize {
        match self.cipher_suite {
            0x1301 => 16,
            0x1302 | 0x1303 => 32,
            _ => unreachable!(),
        }
    }

    fn tag_len(self) -> usize {
        16
    }

    fn aead_algorithm(self) -> AeadAlgorithm {
        match self.cipher_suite {
            0x1301 => AeadAlgorithm::aes_128_gcm(),
            0x1302 => AeadAlgorithm::aes_256_gcm(),
            0x1303 => AeadAlgorithm::chacha20_poly1305(),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn empty_hash(self) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest([]).to_vec(),
            Self::Sha384 => Sha384::digest([]).to_vec(),
        }
    }

    fn hkdf_extract(self, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => hkdf_extract_sha256(salt, ikm),
            Self::Sha384 => hkdf_extract_sha384(salt, ikm),
        }
    }

    fn hkdf_expand(self, prk: &[u8], info: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Sha256 => hkdf_expand_sha256(prk, info, len),
            Self::Sha384 => hkdf_expand_sha384(prk, info, len),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => hmac_sha256(key, data),
            Self::Sha384 => hmac_sha384(key, data),
        }
    }
}

#[derive(Clone)]
enum TranscriptHash {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHash {
    fn new(kind: HashKind) -> Self {
        match kind {
            HashKind::Sha256 => Self::Sha256(Sha256::new()),
            HashKind::Sha384 => Self::Sha384(Sha384::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hash) => hash.update(bytes),
            Self::Sha384(hash) => hash.update(bytes),
        }
    }

    fn finish(&self) -> Vec<u8> {
        match self {
            Self::Sha256(hash) => hash.clone().finalize().to_vec(),
            Self::Sha384(hash) => hash.clone().finalize().to_vec(),
        }
    }
}

struct Tls13KeySchedule {
    hash_kind: HashKind,
    current_secret: Vec<u8>,
}

impl Tls13KeySchedule {
    fn new(hash_kind: HashKind) -> Self {
        Self {
            hash_kind,
            current_secret: hash_kind.hkdf_extract(None, &[]),
        }
    }

    fn input_secret(&mut self, secret: &[u8]) {
        let salt = self
            .derive_secret_for_empty_hash(b"derived")
            .expect("derive REALITY empty hash secret");
        self.current_secret = self.hash_kind.hkdf_extract(Some(&salt), secret);
    }

    fn derive_secret(&self, label: &[u8], transcript_hash: &[u8]) -> anyhow::Result<Vec<u8>> {
        hkdf_expand_label(
            self.hash_kind,
            &self.current_secret,
            label,
            transcript_hash,
            self.hash_kind.output_len(),
        )
    }

    fn input_empty(&mut self) {
        let salt = self
            .derive_secret_for_empty_hash(b"derived")
            .expect("derive REALITY empty hash secret");
        self.current_secret = self.hash_kind.hkdf_extract(Some(&salt), &[]);
    }

    fn derive_secret_for_empty_hash(&self, label: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.derive_secret(label, &self.hash_kind.empty_hash())
    }
}

fn hkdf_expand_label(
    hash_kind: HashKind,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(len <= u16::MAX as usize, "REALITY HKDF output is too large");
    ensure!(
        TLS13_LABEL_PREFIX.len() + label.len() <= u8::MAX as usize,
        "REALITY HKDF label is too long"
    );
    ensure!(
        context.len() <= u8::MAX as usize,
        "REALITY HKDF context is too long"
    );

    let mut info = Vec::with_capacity(4 + TLS13_LABEL_PREFIX.len() + label.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((TLS13_LABEL_PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(TLS13_LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hash_kind.hkdf_expand(secret, &info, len)
}

fn hkdf_extract_sha256(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zero_salt = [0u8; 32];
    let mut mac = Hmac::<Sha256>::new_from_slice(salt.unwrap_or(&zero_salt))
        .expect("initialize HKDF extract HMAC");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_extract_sha384(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zero_salt = [0u8; 48];
    let mut mac = Hmac::<Sha384>::new_from_slice(salt.unwrap_or(&zero_salt))
        .expect("initialize HKDF extract HMAC");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
    hkdf_expand_sha256_impl(prk, info, len)
}

fn hkdf_expand_sha384(prk: &[u8], info: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
    hkdf_expand_sha384_impl(prk, info, len)
}

fn hkdf_expand_sha256_impl(prk: &[u8], info: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
    let hash_len = 32;
    let blocks = len.div_ceil(hash_len);
    ensure!(blocks <= 255, "REALITY HKDF output exceeds RFC 5869 limits");

    let mut okm = Vec::with_capacity(blocks * hash_len);
    let mut previous = Vec::new();
    for counter in 1..=blocks {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("initialize HKDF expand HMAC");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter as u8]);
        previous = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
    }
    okm.truncate(len);
    Ok(okm)
}

fn hkdf_expand_sha384_impl(prk: &[u8], info: &[u8], len: usize) -> anyhow::Result<Vec<u8>> {
    let hash_len = 48;
    let blocks = len.div_ceil(hash_len);
    ensure!(blocks <= 255, "REALITY HKDF output exceeds RFC 5869 limits");

    let mut okm = Vec::with_capacity(blocks * hash_len);
    let mut previous = Vec::new();
    for counter in 1..=blocks {
        let mut mac = Hmac::<Sha384>::new_from_slice(prk).expect("initialize HKDF expand HMAC");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter as u8]);
        previous = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
    }
    okm.truncate(len);
    Ok(okm)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("initialize HMAC");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("initialize HMAC");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Debug)]
struct ServerKeyShare {
    shared_secret: Vec<u8>,
    server_share: Vec<u8>,
}

impl ServerKeyShare {
    fn generate(group: u16, client_key_shares: &[ClientKeyShare]) -> anyhow::Result<Self> {
        match group {
            TLS_GROUP_X25519 => Self::generate_x25519(client_key_shares),
            TLS_GROUP_X25519_KYBER768_DRAFT00 => Self::generate_x25519_kyber(client_key_shares),
            TLS_GROUP_X25519_MLKEM768 => Self::generate_x25519_mlkem(client_key_shares),
            _ => bail!("unsupported REALITY key share group 0x{group:04x}"),
        }
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    fn server_share(&self) -> &[u8] {
        &self.server_share
    }

    fn generate_x25519(client_key_shares: &[ClientKeyShare]) -> anyhow::Result<Self> {
        let client_key_share = client_key_shares
            .iter()
            .find(|key_share| key_share.group == TLS_GROUP_X25519)
            .context("REALITY client did not offer X25519 key share")?;
        ensure!(
            client_key_share.data.len() == 32,
            "REALITY X25519 key share must be 32 bytes"
        );

        let server_key = PKey::generate(Id::X25519).context("generate REALITY X25519 key")?;
        let shared_secret = x25519_shared_secret(&server_key, &client_key_share.data)?;
        let server_public = raw_public_key(&server_key)?;
        Ok(Self {
            shared_secret,
            server_share: server_public,
        })
    }

    fn generate_x25519_mlkem(client_key_shares: &[ClientKeyShare]) -> anyhow::Result<Self> {
        let client_key_share = client_key_shares
            .iter()
            .find(|key_share| key_share.group == TLS_GROUP_X25519_MLKEM768)
            .context("REALITY client did not offer X25519MLKEM768 key share")?;
        ensure!(
            client_key_share.data.len() == TLS_MLKEM768_PUBLIC_KEY_BYTES + 32,
            "REALITY X25519MLKEM768 key share length mismatch"
        );

        let (mlkem_public_key, x25519_public_key) = client_key_share
            .data
            .split_at(TLS_MLKEM768_PUBLIC_KEY_BYTES);
        let server_key = PKey::generate(Id::X25519).context("generate REALITY X25519 key")?;
        let x25519_shared_secret = x25519_shared_secret(&server_key, x25519_public_key)?;
        let server_public = raw_public_key(&server_key)?;

        let mlkem_public = MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, mlkem_public_key)
            .context("parse REALITY ML-KEM public key")?;
        let (ciphertext, mlkem_shared_secret) = mlkem_public
            .encapsulate()
            .context("encapsulate REALITY ML-KEM shared secret")?;
        ensure!(
            ciphertext.len() == TLS_MLKEM768_CIPHERTEXT_BYTES,
            "REALITY ML-KEM ciphertext length mismatch"
        );

        let mut shared_secret = mlkem_shared_secret.to_vec();
        shared_secret.extend_from_slice(&x25519_shared_secret);
        let mut server_share = ciphertext;
        server_share.extend_from_slice(&server_public);
        Ok(Self {
            shared_secret,
            server_share,
        })
    }

    fn generate_x25519_kyber(client_key_shares: &[ClientKeyShare]) -> anyhow::Result<Self> {
        let client_key_share = client_key_shares
            .iter()
            .find(|key_share| key_share.group == TLS_GROUP_X25519_KYBER768_DRAFT00)
            .context("REALITY client did not offer X25519Kyber768Draft00 key share")?;
        ensure!(
            client_key_share.data.len() == 32 + TLS_KYBER768_PUBLIC_KEY_BYTES,
            "REALITY X25519Kyber768Draft00 key share length mismatch"
        );

        let (x25519_public_key, kyber_public_key) = client_key_share.data.split_at(32);
        let server_key = PKey::generate(Id::X25519).context("generate REALITY X25519 key")?;
        let x25519_shared_secret = x25519_shared_secret(&server_key, x25519_public_key)?;
        let server_public = raw_public_key(&server_key)?;

        let (kyber_ciphertext, kyber_shared_secret) = kyber_encapsulate(kyber_public_key)
            .context("encapsulate REALITY Kyber shared secret")?;
        ensure!(
            kyber_ciphertext.len() == TLS_KYBER768_CIPHERTEXT_BYTES,
            "REALITY Kyber ciphertext length mismatch"
        );

        let mut shared_secret = x25519_shared_secret;
        shared_secret.extend_from_slice(&kyber_shared_secret);
        let mut server_share = server_public;
        server_share.extend_from_slice(&kyber_ciphertext);
        Ok(Self {
            shared_secret,
            server_share,
        })
    }
}

fn kyber_encapsulate(public_key: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    ensure!(
        public_key.len() == pqc_kyber::KYBER_PUBLICKEYBYTES,
        "REALITY Kyber public key length mismatch"
    );
    let mut rng = KyberRng;
    let (ciphertext, shared_secret) =
        pqc_kyber::encapsulate(public_key, &mut rng).map_err(|error| anyhow!(error.to_string()))?;
    Ok((ciphertext.to_vec(), shared_secret.to_vec()))
}

struct KyberRng;

impl pqc_kyber::CryptoRng for KyberRng {}

impl pqc_kyber::RngCore for KyberRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        rand_bytes(&mut bytes).expect("generate Kyber random bytes");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        rand_bytes(&mut bytes).expect("generate Kyber random bytes");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_bytes(dest).expect("generate Kyber random bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn x25519_shared_secret(
    server_key: &PKey<Private>,
    client_public_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let peer_key = x25519_public_key_from_raw(client_public_key)?;
    let mut deriver = Deriver::new(server_key).context("initialize REALITY X25519 deriver")?;
    deriver
        .set_peer(&peer_key)
        .context("set REALITY X25519 peer key")?;
    deriver
        .derive_to_vec()
        .context("derive REALITY X25519 shared secret")
}

fn raw_public_key(key: &PKey<Private>) -> anyhow::Result<Vec<u8>> {
    let mut bytes = vec![
        0u8;
        key.raw_public_key_len()
            .context("read REALITY public key length")?
    ];
    let public_key = key
        .raw_public_key(&mut bytes)
        .context("read REALITY public key bytes")?;
    Ok(public_key.to_vec())
}

fn x25519_public_key_from_raw(raw: &[u8]) -> anyhow::Result<PKey<Public>> {
    ensure!(
        raw.len() == 32,
        "REALITY X25519 public key must be 32 bytes"
    );
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ]);
    der.extend_from_slice(raw);
    PKey::public_key_from_der(&der).context("decode REALITY X25519 public key DER")
}

fn encode_u24(value: usize) -> anyhow::Result<[u8; 3]> {
    ensure!(value <= 0x00ff_ffff, "REALITY u24 value is too large");
    Ok([
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts_tls13_application_record() {
        let suite = CipherSuite::from_id(0x1301).expect("suite");
        let secret = vec![0x11; 32];
        let mut writer = RecordCipher::new(suite, &secret).expect("writer");
        let mut reader = RecordCipher::new(suite, &secret).expect("reader");

        let record = writer
            .encrypt_record(TLS_CONTENT_TYPE_APPLICATION_DATA, b"hello")
            .expect("encrypt");
        let decrypted = reader
            .decrypt_record(record[0], &record[TLS_RECORD_HEADER_LEN..])
            .expect("decrypt");
        assert_eq!(decrypted.content_type, TLS_CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(decrypted.payload, b"hello");
    }

    #[test]
    fn updates_tls13_application_traffic_keys_after_key_update() {
        let suite = CipherSuite::from_id(0x1301).expect("suite");
        let secret = vec![0x11; 32];
        let mut writer = RecordCipher::new(suite, &secret).expect("writer");
        let mut reader = RecordCipher::new(suite, &secret).expect("reader");

        let key_update =
            build_handshake_message(TLS_HANDSHAKE_TYPE_KEY_UPDATE, &[0]).expect("build key update");
        let key_update_record = writer
            .encrypt_record(TLS_CONTENT_TYPE_HANDSHAKE, &key_update)
            .expect("encrypt key update");
        let decrypted = reader
            .decrypt_record(
                key_update_record[0],
                &key_update_record[TLS_RECORD_HEADER_LEN..],
            )
            .expect("decrypt key update");
        assert_eq!(decrypted.content_type, TLS_CONTENT_TYPE_HANDSHAKE);
        let control = unbounded_channel().0;
        handle_post_handshake_message(&mut reader, &decrypted.payload, &control)
            .expect("handle key update");
        writer.update_key().expect("update writer key");

        let record = writer
            .encrypt_record(TLS_CONTENT_TYPE_APPLICATION_DATA, b"hello")
            .expect("encrypt application record");
        let decrypted = reader
            .decrypt_record(record[0], &record[TLS_RECORD_HEADER_LEN..])
            .expect("decrypt application record");
        assert_eq!(decrypted.content_type, TLS_CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(decrypted.payload, b"hello");
    }

    #[test]
    fn builds_empty_encrypted_extensions_for_reality() {
        let encrypted_extensions = build_encrypted_extensions().expect("encrypted extensions");
        assert_eq!(
            encrypted_extensions,
            [TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0]
        );
    }

    #[test]
    fn generates_x25519_mlkem_server_share() {
        let client_share = ClientKeyShare {
            group: TLS_GROUP_X25519_MLKEM768,
            data: vec![0x22; TLS_MLKEM768_PUBLIC_KEY_BYTES + 32],
        };
        let server_share = ServerKeyShare::generate(TLS_GROUP_X25519_MLKEM768, &[client_share])
            .expect("generate ML-KEM server share");
        assert_eq!(server_share.shared_secret.len(), 64);
        assert_eq!(
            server_share.server_share.len(),
            TLS_MLKEM768_CIPHERTEXT_BYTES + 32
        );
    }
}
