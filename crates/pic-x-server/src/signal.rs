//! What a process shutdown is, when nobody says otherwise — and what a reload is.
//!
//! The contracts take an opaque future, so the question "what counts as a shutdown" has exactly one
//! answer per build and it lives here. For a server in a container the answer is SIGTERM — that is
//! what an orchestrator sends before it eventually sends SIGKILL — with SIGINT for the operator who
//! is watching it in a terminal.
//!
//! SIGHUP is the other half of that vocabulary and means the opposite: re-read what can be re-read,
//! and keep running. It is what `certbot`, `cert-manager` hooks and every operator who has ever
//! renewed a certificate already expect to work — so it works, and *what* gets re-read is decided by
//! the binary rather than here.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{info, warn};

use pic_x_core::BoxFuture;

/// What a build does when it is asked to re-read what it can.
pub type ReloadHandler = Arc<dyn Fn() + Send + Sync>;

/// Resolves when the process is asked to stop.
///
/// The signal that arrived is recorded, because "why did it go away" is the first question asked
/// about a process that went away, and an orchestrator's SIGTERM and an operator's Ctrl-C are very
/// different answers.
pub fn process_shutdown() -> BoxFuture<'static, ()> {
    Box::pin(async {
        let received = wait_for_signal().await;

        info!(
            event.name = "server.signal",
            signal = received,
            "asked to stop"
        );
    })
}

/// Runs `handler` every time the process is sent SIGHUP, until the returned task is dropped.
///
/// A failure to register the handler is recorded and does not stop the server. A build that cannot
/// be told to reload still serves; one that refused to start because of it would be strictly worse.
#[cfg(unix)]
pub fn on_hangup(handler: ReloadHandler) -> JoinHandle<()> {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(hangup) => hangup,
            Err(error) => {
                warn!(
                    event.name = "server.reload_unavailable",
                    error = %error,
                    "this process cannot be asked to re-read its material without restarting"
                );

                return;
            }
        };

        while hangup.recv().await.is_some() {
            info!(
                event.name = "server.reload",
                signal = "SIGHUP",
                "asked to re-read what can be re-read"
            );

            handler();
        }
    })
}

/// Registers nothing, on a platform with no such signal.
#[cfg(not(unix))]
pub fn on_hangup(_handler: ReloadHandler) -> JoinHandle<()> {
    tokio::spawn(async {})
}

#[cfg(unix)]
async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        // Without SIGTERM there is still SIGINT, and a server that refused to start because it could
        // not register a handler would be worse than one that can only be interrupted.
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;

            return "SIGINT";
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;

    "SIGINT"
}
