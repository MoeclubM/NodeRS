use crate::panel::NodeConfigResponse;

const DEFAULT_LISTEN_IP: &str = "::";

pub(crate) fn effective_listen_ip(remote: &NodeConfigResponse) -> String {
    let listen_ip = remote.listen_ip.trim();
    if listen_ip.is_empty() {
        DEFAULT_LISTEN_IP.to_string()
    } else {
        listen_ip.to_string()
    }
}
