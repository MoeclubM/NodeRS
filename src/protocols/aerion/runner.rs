use anyhow::Context;
use std::future::Future;
use tokio::task::JoinHandle;
use tracing::error;

use crate::protocols::ProtocolKind;
use crate::protocols::shared::{bind_listeners, bind_udp_sockets};

use super::BuiltServerConfig;

pub(super) struct RunningServer {
    pub(super) handles: Vec<JoinHandle<()>>,
}

pub(super) fn spawn_running_server(
    protocol: ProtocolKind,
    config: BuiltServerConfig,
    core: ::aerion::core::ProxyCore,
) -> anyhow::Result<RunningServer> {
    let handles = match config {
        BuiltServerConfig::Anytls(config) => {
            let listeners =
                bind_listeners(&config.listen.ip().to_string(), config.listen.port())
                    .with_context(|| format!("bind Aerion AnyTLS server on {}", config.listen))?;
            listeners
                .into_iter()
                .map(|listener| {
                    let config = config.clone();
                    let core = core.clone();
                    spawn_aerion_task(protocol, async move {
                        ::aerion::run_server_listener_with_core(listener, config, core).await
                    })
                })
                .collect()
        }
        BuiltServerConfig::Hysteria2(config) => {
            let sockets = bind_udp_sockets(&config.listen.ip().to_string(), config.listen.port())
                .with_context(|| {
                format!("bind Aerion Hysteria2 server on {}", config.listen)
            })?;
            let mut handles = Vec::new();
            for socket in sockets {
                let socket = socket
                    .into_std()
                    .context("convert Hysteria2 UDP socket to std")?;
                let config = config.clone();
                let core = core.clone();
                handles.push(spawn_aerion_task(protocol, async move {
                    ::aerion::run_hysteria2_server_socket_with_core(socket, config, core).await
                }));
            }
            handles
        }
        BuiltServerConfig::Mieru(config) => {
            if config.transport == ::aerion::MieruTransport::Udp {
                let sockets =
                    bind_udp_sockets(&config.listen.ip().to_string(), config.listen.port())
                        .with_context(|| {
                            format!("bind Aerion Mieru UDP server on {}", config.listen)
                        })?;
                sockets
                    .into_iter()
                    .map(|socket| {
                        let config = config.clone();
                        let core = core.clone();
                        spawn_aerion_task(protocol, async move {
                            ::aerion::run_mieru_packet_server_socket_with_core(socket, config, core)
                                .await
                        })
                    })
                    .collect()
            } else {
                let listeners =
                    bind_listeners(&config.listen.ip().to_string(), config.listen.port())
                        .with_context(|| {
                            format!("bind Aerion Mieru server on {}", config.listen)
                        })?;
                listeners
                    .into_iter()
                    .map(|listener| {
                        let config = config.clone();
                        let core = core.clone();
                        spawn_aerion_task(protocol, async move {
                            ::aerion::run_mieru_server_listener_with_core(listener, config, core)
                                .await
                        })
                    })
                    .collect()
            }
        }
        BuiltServerConfig::Naive(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_naive_server_with_core(config, core).await
        })],
        BuiltServerConfig::Trojan(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_trojan_server_with_core(config, core).await
        })],
        BuiltServerConfig::Tuic(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_tuic_server_with_core(config, core).await
        })],
        BuiltServerConfig::Vless(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_vless_server_with_core(config, core).await
        })],
        BuiltServerConfig::Vmess(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_vmess_server_with_core(config, core).await
        })],
    };
    Ok(RunningServer { handles })
}

fn spawn_aerion_task<F>(protocol: ProtocolKind, future: F) -> JoinHandle<()>
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = future.await {
            error!(protocol = protocol.as_str(), %error, "Aerion server exited");
        }
    })
}
