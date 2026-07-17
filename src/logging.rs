//! Tracing setup, overridable via `RUST_LOG`.

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::{EnvFilter, Registry, fmt, prelude::*};

/// Default filter when `RUST_LOG` is unset.
pub const DEFAULT_ENV_FILTER: &str = "info";

pub fn init() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_ENV_FILTER));

    Registry::default()
        .with(env_filter)
        .with(SuppressRoutineAerion)
        .with(fmt::layer())
        .init();
}

struct SuppressRoutineAerion;

impl<S> Layer<S> for SuppressRoutineAerion
where
    S: Subscriber,
{
    fn event_enabled(&self, event: &Event<'_>, _ctx: Context<'_, S>) -> bool {
        if *event.metadata().level() != Level::WARN {
            return true;
        }
        let target = event.metadata().target();
        if !target.starts_with("aerion") {
            return true;
        }
        let mut visitor = WarnFieldsVisitor::default();
        event.record(&mut visitor);
        !is_routine_aerion_warn(&visitor.text())
    }
}

#[derive(Default)]
struct WarnFieldsVisitor {
    parts: Vec<String>,
}

impl WarnFieldsVisitor {
    fn text(&self) -> String {
        self.parts.join(" ")
    }
}

impl Visit for WarnFieldsVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.parts.push(format!("{}={value:?}", field.name()));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.parts.push(format!("{}={value}", field.name()));
    }
}

fn is_routine_aerion_warn(text: &str) -> bool {
    const MARKERS: &[&str] = &[
        "Broken pipe",
        "early eof",
        "Connection reset",
        "Connection aborted",
        "BadCertificate",
        "EncryptedClientHelloRequired",
        "UOT request is empty",
    ];
    MARKERS.iter().any(|marker| text.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::is_routine_aerion_warn;

    #[test]
    fn suppresses_common_disconnect_and_probe_warnings() {
        assert!(is_routine_aerion_warn(
            "message=client 1.2.3.4:1 failed: write Aerion frame error=Broken pipe (os error 32)"
        ));
        assert!(is_routine_aerion_warn(
            "message=open stream failed: UOT request is empty"
        ));
        assert!(is_routine_aerion_warn(
            "message=client 1.2.3.4:1 failed: accept TLS client error=received fatal alert: BadCertificate"
        ));
    }

    #[test]
    fn keeps_unexpected_aerion_warnings() {
        assert!(!is_routine_aerion_warn(
            "message=client 1.2.3.4:1 failed: client did not send settings before SYN"
        ));
    }
}
