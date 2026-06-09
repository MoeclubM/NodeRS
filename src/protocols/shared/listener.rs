use crate::panel::NodeConfigResponse;

const DEFAULT_LISTEN_IP: &str = "::";

pub(crate) fn effective_listen_ip(_remote: &NodeConfigResponse) -> String {
    DEFAULT_LISTEN_IP.to_string()
}
