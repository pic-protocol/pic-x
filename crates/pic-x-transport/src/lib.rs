//! One listener for every PIC-X surface.
//!
//! The public surface, the administrative surface and telemetry all end up serving an `axum::Router`
//! — gRPC included, because `tonic` can hand its routes over as one. So the part that is easy to get
//! wrong is written once, here, instead of three times: binding, TLS, mutual TLS, revocation,
//! re-reading material that changed, and a shutdown that lets connections in flight finish.
//!
//! # Binding happens before serving
//!
//! The listener is bound synchronously, before any task is spawned. A port that is already taken is
//! then a failure to *start*, reported by the service that could not start — not something a client
//! discovers later by failing to connect.
//!
//! # What TLS means here
//!
//! * a certificate and key make the listener authenticate **itself**;
//! * adding a client authority makes it demand a certificate **back**, and a client that presents
//!   none — or one that authority did not sign — never reaches the application at all;
//! * adding a revocation list makes that authority able to take a certificate back before it
//!   expires, which is the difference between a compromised client being cut off today and being
//!   cut off whenever its certificate happened to run out;
//! * the protocol floor defaults to 1.3, and 1.2 has to be asked for by name.
//!
//! # What revocation is checked against
//!
//! The **client certificate**, and not the authority above it. Revoking an authority is not
//! something a list expresses usefully — it is done by taking the authority out of the bundle this
//! listener trusts, which is a configuration change and takes effect on the next reload. Checking
//! the whole chain instead would mean every issuer in it needs a published, current list, and the
//! failure when one is missing is that every client is refused. That is a worse failure than the one
//! it prevents.
//!
//! # Who the client is
//!
//! A mutual handshake knows exactly which certificate was presented; a request handler, by default,
//! does not. Every connection here carries what it learned into each request as an
//! [`Arc<PeerIdentity>`](pic_x_core::PeerIdentity) extension — which is what makes authorisation, as
//! opposed to authentication, possible at all.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

mod identity;
mod reload;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

use pic_x_core::{TlsSettings, TlsVersion};

pub use identity::{PeerAcceptor, WithPeer, fingerprint, identity_of};
pub use reload::{Reloaded, reload_all};

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

/// Builds the TLS configuration a listener serves with.
pub fn server_config(settings: &TlsSettings) -> Result<Arc<ServerConfig>> {
    Ok(build(settings)?.0)
}

/// Builds the configuration and says which certificate it ended up with.
///
/// The fingerprint is what makes a reload verifiable: a log record saying material was re-read, with
/// no way to tell whether it is the same material, is a record that answers nothing.
fn build(settings: &TlsSettings) -> Result<(Arc<ServerConfig>, String)> {
    // rustls asks for a process-wide provider; installing it more than once is not an error worth
    // reporting, because the second caller wanted exactly what the first one installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certificates = load_certificates(settings.certificate())?;
    let key = load_key(settings.key())?;

    let leaf = certificates
        .first()
        .map(|certificate| identity::fingerprint(certificate))
        .unwrap_or_default();

    let versions: &[&'static rustls::SupportedProtocolVersion] = match settings.min_version() {
        TlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13],
        TlsVersion::V1_3 => &[&rustls::version::TLS13],
    };

    let builder = ServerConfig::builder_with_protocol_versions(versions);

    let mut config = match settings.client_ca() {
        Some(client_ca) => {
            let mut roots = RootCertStore::empty();
            for certificate in load_certificates(client_ca)? {
                roots.add(certificate).with_context(|| {
                    format!("adding {} to the client authorities", client_ca.display())
                })?;
            }

            let mut verifier = WebPkiClientVerifier::builder(Arc::new(roots));

            if let Some(path) = settings.crl() {
                let revoked = load_revocations(path)?;

                // See the crate documentation: the client certificate is checked, the authority
                // above it is trusted by configuration rather than by a list.
                verifier = verifier
                    .with_crls(revoked)
                    .only_check_end_entity_revocation();
            }

            let verifier = verifier.build().with_context(|| {
                format!("building the client verifier from {}", client_ca.display())
            })?;

            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificates, key)
        }
        None => builder
            .with_no_client_auth()
            .with_single_cert(certificates, key),
    }
    .with_context(|| {
        format!(
            "using the certificate {} with the key {}",
            settings.certificate().display(),
            settings.key().display()
        )
    })?;

    // Without this a client speaking HTTP/2 — which every gRPC client does — cannot negotiate it.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((Arc::new(config), leaf))
}

/// Reads a PEM file of certificates.
///
/// Public because a build that verifies a peer, or a test that acts as a client, needs the same
/// reader the listener uses — and two readers of the same format eventually disagree.
pub fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certificates: Vec<_> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("opening {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))?;

    if certificates.is_empty() {
        bail!("{} contains no certificate", path.display());
    }

    Ok(certificates)
}

/// Reads a PEM private key, in whichever of the three encodings it was written.
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading a private key from {}", path.display()))
}

/// Reads a PEM file of certificate revocation lists.
///
/// A file with no list in it is refused rather than treated as "nothing is revoked". The two look
/// identical to a listener and mean opposite things to an operator, and the one that silently
/// accepts every revoked certificate is not the one to guess.
pub fn load_revocations(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let revocations: Vec<_> = CertificateRevocationListDer::pem_file_iter(path)
        .with_context(|| format!("opening {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading revocation lists from {}", path.display()))?;

    if revocations.is_empty() {
        bail!(
            "{} contains no revocation list: an empty file and a file that revokes nothing are \
             indistinguishable here, and only one of them is safe to assume",
            path.display()
        );
    }

    Ok(revocations)
}

/// Returns the SHA-256 of some bytes, lowercase hex.
///
/// Public because the audit trail chains its records with the same digest, and two implementations
/// of "the fingerprint of this" eventually disagree about padding or case.
pub fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write;

    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");

            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_digest_is_the_one_every_other_tool_prints() {
        // The SHA-256 of the empty input, which is the most published digest there is.
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
