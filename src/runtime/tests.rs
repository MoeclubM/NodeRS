use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn wait_for_listener(port: u16) -> anyhow::Result<TcpStream> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => return Ok(stream),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await?
}

#[tokio::test]
async fn identical_config_replay_preserves_live_sudoku_connection() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let panel = MachinePanelClient::new(&crate::config::PanelConfig {
        api: "http://127.0.0.1:1".into(),
        key: "unused-local-test-key".into(),
        machine_id: 1,
    })?;
    let node = ManagedNode::new(1, ProtocolKind::Sudoku, panel.node_client(1), None);
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let port = reservation.local_addr()?.port();
    drop(reservation);
    let remote = NodeConfigResponse {
        protocol: "sudoku".into(),
        listen_ip: "127.0.0.1".into(),
        server_port: port,
        sudoku: Some(serde_json::json!({
            "aead":"aes-128-gcm", "padding_min":0, "padding_max":0
        })),
        ..Default::default()
    };
    node.apply_remote_config(&remote).await?;
    node.replace_users(&[PanelUser {
        id: 1,
        uuid: "config-replay-user".into(),
        ..Default::default()
    }])
    .await?;
    drop(wait_for_listener(port).await?);
    let destination = TcpListener::bind("127.0.0.1:0").await?;
    let target = aerion::protocol::ProxyTarget::Ip(destination.local_addr()?);
    let echo = tokio::spawn(async move {
        let (mut stream, _) = destination.accept().await?;
        let (mut read, mut write) = stream.split();
        tokio::io::copy(&mut read, &mut write).await
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_address = listener.local_addr()?;
    let client = tokio::spawn(aerion::run_sudoku_client_listener(
        listener,
        aerion::SudokuClientConfig {
            listen: socks_address,
            server_host: "127.0.0.1".into(),
            server_port: port,
            key: "config-replay-user".into(),
            options: aerion::SudokuOptions {
                aead: "aes-128-gcm".into(),
                padding_min: 0,
                padding_max: 0,
                ..Default::default()
            },
        },
    ));
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = aerion::socks::connect_tcp(socks_address, &target)
            .await
            .context("connect initial Sudoku stream")?;
        for iteration in 0..4 {
            if iteration > 0 {
                // Polling and websocket replay must share successful config state.
                let (left, right) = tokio::join!(
                    node.apply_remote_config(&remote),
                    node.apply_remote_config(&remote)
                );
                left?;
                right?;
            }
            let payload = vec![iteration as u8; 32_769];
            stream.write_all(&payload).await?;
            let mut response = vec![0; payload.len()];
            stream
                .read_exact(&mut response)
                .await
                .with_context(|| format!("read echo after config replay iteration={iteration}"))?;
            assert!(response == payload, "config replay changed stream data");
        }
        let replacement = TcpListener::bind("127.0.0.1:0").await?;
        let new_port = replacement.local_addr()?.port();
        drop(replacement);
        let changed = NodeConfigResponse {
            server_port: new_port,
            ..remote.clone()
        };
        node.apply_remote_config(&changed).await?;
        let _new_listener = wait_for_listener(new_port).await?;
        assert_eq!(node.sync_state.lock().await.config.as_ref(), Some(&changed));
        let mut byte = [0];
        let closed = stream.read(&mut byte).await;
        assert!(matches!(closed, Ok(0) | Err(_)));
        Ok::<(), anyhow::Error>(())
    })
    .await;
    node.shutdown().await;
    client.abort();
    echo.abort();
    result??;
    Ok(())
}
