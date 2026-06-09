use std::future::Future;
use tokio::task::JoinHandle;
use tracing::error;

use crate::protocols::ProtocolKind;

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
            vec![spawn_aerion_task(protocol, async move {
                ::aerion::run_server_with_core(config, core).await
            })]
        }
        BuiltServerConfig::Hysteria2(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_hysteria2_server_with_core(config, core).await
        })],
        BuiltServerConfig::Mieru(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_mieru_server_with_core(config, core).await
        })],
        BuiltServerConfig::Naive(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_naive_server_with_core(config, core).await
        })],
        BuiltServerConfig::Shadowsocks(config) => vec![spawn_aerion_task(protocol, async move {
            ::aerion::run_shadowsocks_server_with_core(config, core).await
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
