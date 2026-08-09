//! One listener: bound before it serves, and drained before it stops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use tokio::task::JoinHandle;

use pic_x_core::TlsSettings;

use crate::identity::PeerAcceptor;
use crate::material::server_config;
use crate::reload;

/// A listener that is up, and the things needed to take it down again.
pub struct Surface {
    address: SocketAddr,
    handle: Handle<SocketAddr>,
    task: JoinHandle<()>,
    /// Kept alive for as long as the surface is: the registry that SIGHUP walks holds only a weak
    /// reference, so dropping this is what takes the surface out of it.
    material: Option<Arc<reload::Reloadable>>,
    watcher: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Surface {
    /// Says what a listener is, which is the address it got. The rest is machinery.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Surface")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Surface {
    /// Binds `address` and serves `router` on it, over TLS when `tls` says so.
    ///
    /// Returns once the socket is bound and the server is running, so a caller that got a `Surface`
    /// back knows the port is genuinely theirs.
    pub async fn start(address: &str, router: Router, tls: Option<&TlsSettings>) -> Result<Self> {
        let parsed: SocketAddr = address
            .parse()
            .with_context(|| format!("reading the listen address `{address}`"))?;

        // Bound here, synchronously, so "the port is taken" is an error from `start`.
        let listener =
            std::net::TcpListener::bind(parsed).with_context(|| format!("binding {parsed}"))?;
        listener
            .set_nonblocking(true)
            .with_context(|| format!("preparing the listener on {parsed}"))?;
        let bound = listener
            .local_addr()
            .with_context(|| format!("reading back the address of {parsed}"))?;

        let secured = match tls {
            Some(settings) => Some((
                settings,
                RustlsConfig::from_config(server_config(settings)?),
            )),
            None => None,
        };

        let handle = Handle::new();
        let serving = handle.clone();
        let accepting = secured.as_ref().map(|(_, config)| config.clone());

        let task = tokio::spawn(async move {
            let service = router.into_make_service();

            let served = match accepting {
                Some(config) => match axum_server::from_tcp(listener) {
                    Ok(server) => {
                        server
                            .acceptor(PeerAcceptor::new(RustlsAcceptor::new(config)))
                            .handle(serving)
                            .serve(service)
                            .await
                    }
                    Err(error) => Err(error),
                },
                None => match axum_server::from_tcp(listener) {
                    Ok(server) => server.handle(serving).serve(service).await,
                    Err(error) => Err(error),
                },
            };

            if let Err(error) = served {
                tracing::warn!(
                    event.name = "surface.failed",
                    address = %bound,
                    error = %error,
                    "the listener stopped on its own"
                );
            }
        });

        let (material, watcher) = match secured {
            Some((settings, config)) => {
                let material = Arc::new(reload::Reloadable::new(bound, settings.clone(), config));
                reload::register(&material);

                let watcher = settings.reload().map(|interval| {
                    let watched = Arc::downgrade(&material);

                    tokio::spawn(reload::watch(watched, interval))
                });

                (Some(material), watcher)
            }
            None => (None, None),
        };

        Ok(Self {
            address: bound,
            handle,
            task,
            material,
            watcher,
        })
    }

    /// Returns the address actually bound, which is what to log.
    ///
    /// Not the address that was asked for: port zero is a real configuration, and reporting `:0` back
    /// to an operator would be useless.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting, lets what is in flight finish within `grace`, and waits for it to be over.
    ///
    /// Waiting is the point. Asking a server to stop and returning immediately reports a shutdown
    /// that has not happened, and the process exits underneath the requests it promised to finish.
    pub async fn stop(self, grace: Duration) -> Result<SocketAddr> {
        if let Some(watcher) = self.watcher {
            watcher.abort();
        }

        // Dropping the last strong reference is what removes this surface from the set SIGHUP walks.
        drop(self.material);

        self.handle.graceful_shutdown(Some(grace));
        self.task
            .await
            .with_context(|| format!("waiting for the listener on {} to finish", self.address))?;

        Ok(self.address)
    }
}
