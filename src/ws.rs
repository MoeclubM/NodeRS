use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::panel::{MachinePanelClient, NodeConfigResponse, PanelUser};
use crate::runtime::MachineRuntime;

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    event: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Debug, Deserialize, Default)]
struct SyncNodesData {
    #[serde(default)]
    nodes: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ConfigSyncData {
    node_id: i64,
    config: NodeConfigResponse,
}

#[derive(Debug, Deserialize, Default)]
struct UsersSyncData {
    node_id: i64,
    #[serde(default)]
    users: Vec<PanelUser>,
}

#[derive(Debug, Deserialize, Default)]
struct UserDeltaSyncData {
    node_id: i64,
}

#[derive(Debug, Deserialize, Default)]
struct DevicesSyncData {
    node_id: i64,
    #[serde(default)]
    users: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct ErrorData {
    #[serde(default)]
    message: String,
}

pub fn spawn_machine_websocket(
    panel: MachinePanelClient,
    ws_url: String,
    runtime: Arc<MachineRuntime>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let ws_url = match panel.websocket_url(&ws_url) {
            Ok(ws_url) => ws_url,
            Err(error) => {
                error!(%error, "build Xboard websocket url failed");
                return;
            }
        };
        let mut reconnect_delay = 1u64;

        loop {
            match connect_async(&ws_url).await {
                Ok((mut socket, _)) => {
                    info!(
                        machine_id = panel.machine_id(),
                        "connected to Xboard websocket"
                    );
                    reconnect_delay = 1;

                    while let Some(message) = socket.next().await {
                        let message = match message {
                            Ok(message) => message,
                            Err(error) => {
                                warn!(%error, "Xboard websocket read failed");
                                break;
                            }
                        };

                        let Some(text) = decode_message(message) else {
                            continue;
                        };

                        let envelope: Envelope = match serde_json::from_str(&text) {
                            Ok(envelope) => envelope,
                            Err(error) => {
                                warn!(%error, "decode Xboard websocket event failed");
                                continue;
                            }
                        };

                        match envelope.event.as_str() {
                            "ping" => {
                                if let Err(error) = socket
                                    .send(Message::Text(r#"{"event":"pong"}"#.into()))
                                    .await
                                {
                                    warn!(%error, "reply Xboard websocket pong failed");
                                    break;
                                }
                            }
                            "auth.success" => {
                                debug!(
                                    machine_id = panel.machine_id(),
                                    "Xboard websocket authenticated"
                                )
                            }
                            "sync.nodes" => {
                                let data: SyncNodesData =
                                    serde_json::from_value(envelope.data).unwrap_or_default();
                                debug!(count = data.nodes.len(), "received sync.nodes");
                                if let Err(error) = runtime.handle_sync_nodes().await {
                                    warn!(%error, "handle websocket sync.nodes failed");
                                }
                            }
                            "sync.config" => {
                                let data: ConfigSyncData =
                                    match serde_json::from_value(envelope.data) {
                                        Ok(data) => data,
                                        Err(error) => {
                                            warn!(%error, "decode websocket sync.config failed");
                                            continue;
                                        }
                                    };
                                if let Err(error) =
                                    runtime.handle_sync_config(data.node_id, data.config).await
                                {
                                    warn!(
                                        node_id = data.node_id,
                                        %error,
                                        "apply websocket sync.config failed"
                                    );
                                }
                            }
                            "sync.users" => {
                                let data: UsersSyncData =
                                    match serde_json::from_value(envelope.data) {
                                        Ok(data) => data,
                                        Err(error) => {
                                            warn!(%error, "decode websocket sync.users failed");
                                            continue;
                                        }
                                    };
                                if let Err(error) =
                                    runtime.handle_sync_users(data.node_id, data.users).await
                                {
                                    warn!(
                                        node_id = data.node_id,
                                        %error,
                                        "apply websocket sync.users failed"
                                    );
                                }
                            }
                            "sync.user.delta" => {
                                let data: UserDeltaSyncData =
                                    serde_json::from_value(envelope.data).unwrap_or_default();
                                if data.node_id == 0 {
                                    warn!("websocket sync.user.delta missing node_id");
                                    continue;
                                }
                                if let Err(error) = runtime.refresh_node_users(data.node_id).await {
                                    warn!(
                                        node_id = data.node_id,
                                        %error,
                                        "refresh users after websocket sync.user.delta failed"
                                    );
                                }
                            }
                            "sync.devices" => {
                                let data: DevicesSyncData =
                                    match serde_json::from_value(envelope.data) {
                                        Ok(data) => data,
                                        Err(error) => {
                                            warn!(%error, "decode websocket sync.devices failed");
                                            continue;
                                        }
                                    };
                                if let Err(error) =
                                    runtime.handle_sync_devices(data.node_id, data.users).await
                                {
                                    warn!(
                                        node_id = data.node_id,
                                        %error,
                                        "apply websocket sync.devices failed"
                                    );
                                }
                            }
                            "error" => {
                                let data: ErrorData =
                                    serde_json::from_value(envelope.data).unwrap_or_default();
                                warn!(message = %data.message, "Xboard websocket returned an error");
                            }
                            other => {
                                debug!(event = other, "ignoring unsupported Xboard websocket event")
                            }
                        }
                    }
                }
                Err(error) => warn!(%error, "connect Xboard websocket failed"),
            }

            tokio::time::sleep(Duration::from_secs(reconnect_delay)).await;
            reconnect_delay = reconnect_delay.saturating_mul(2).min(30);
        }
    })
}

fn decode_message(message: Message) -> Option<String> {
    match message {
        Message::Text(text) => Some(text.to_string()),
        Message::Binary(bytes) => String::from_utf8(bytes.to_vec()).ok(),
        Message::Close(_) => None,
        Message::Ping(_) | Message::Pong(_) => None,
        _ => None,
    }
}
