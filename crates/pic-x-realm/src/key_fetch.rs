//! The transport behind an attester's `jwks_uri`.
//!
//! A small HTTP(S) GET, deliberately not a general-purpose HTTP client: it fetches one JSON document
//! from a URL that configuration named, and everything it does is bounded — one connection, one
//! request, no redirects, a response-size cap and a deadline.
//!
//! Redirects are not followed on purpose. The `jwks_uri` is trust-establishing infrastructure: if it
//! moves, that belongs in configuration, not in a `Location` header the fetch would silently obey.
//!
//! TLS verification uses the **system trust store**, so a deployment whose attester sits behind a
//! corporate CA works without rebuilding PIC-X.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Buf;
use http_body_util::BodyExt;
use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use pic_x_core::BoxFuture;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::attester_keys::KeySetFetcher;

/// Caps on one key-set response. The URL is configured, the response is not.
const MAX_KEY_SET_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Fetches attester key sets over HTTP and HTTPS.
pub(crate) struct HttpKeySetFetcher {
    http: Client<HttpConnector, String>,
    tls: OnceLock<Result<TlsConnector, String>>,
}

impl HttpKeySetFetcher {
    pub(crate) fn new() -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(REQUEST_TIMEOUT));
        connector.enforce_http(false);

        Self {
            http: Client::builder(TokioExecutor::new()).build(connector),
            tls: OnceLock::new(),
        }
    }

    /// The TLS connector, built once from the system trust store.
    ///
    /// A machine with no readable trust store is a deployment error, not a per-request failure, so
    /// the outcome is remembered rather than retried on every fetch.
    fn tls(&self) -> Result<&TlsConnector> {
        match self.tls.get_or_init(build_tls_connector) {
            Ok(connector) => Ok(connector),
            Err(error) => bail!("{error}"),
        }
    }
}

fn build_tls_connector() -> Result<TlsConnector, String> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(format!(
            "the system trust store yielded no certificates ({} error(s) while reading it)",
            loaded.errors.len()
        ));
    }
    for error in &loaded.errors {
        tracing::warn!(
            event.name = "attester.trust_store_partial",
            component = crate::COMPONENT,
            error = %error,
            "a system trust store entry could not be read"
        );
    }

    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        return Err(format!(
            "no usable root certificate in the system trust store ({ignored} ignored)"
        ));
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

impl KeySetFetcher for HttpKeySetFetcher {
    fn fetch<'a>(&'a self, jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let uri: Uri = jwks_uri
                .parse()
                .with_context(|| format!("`{jwks_uri}` is not a URL"))?;
            match uri.scheme_str() {
                Some("https") => self.get_https(&uri).await,
                Some("http") => self.get_http(&uri).await,
                other => bail!(
                    "a jwks_uri must be http or https, got `{}`",
                    other.unwrap_or("no scheme")
                ),
            }
        })
    }
}

impl HttpKeySetFetcher {
    async fn get_http(&self, uri: &Uri) -> Result<Vec<u8>> {
        let request = Request::get(uri.clone())
            .header(hyper::header::ACCEPT, "application/json")
            .body(String::new())
            .context("building the key-set request")?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.http.request(request))
            .await
            .map_err(|_| anyhow!("the key-set request timed out"))?
            .context("requesting the key set")?;

        let status = response.status();
        if !status.is_success() {
            bail!("the key-set endpoint answered {status}");
        }

        collect_bounded(response.into_body()).await
    }

    /// HTTPS through a rustls connection verified against the system trust store.
    async fn get_https(&self, uri: &Uri) -> Result<Vec<u8>> {
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("the jwks_uri has no host"))?;
        let port = uri.port_u16().unwrap_or(443);
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .with_context(|| format!("`{host}` is not a valid TLS server name"))?;

        let connect = async {
            let stream = tokio::net::TcpStream::connect((host, port))
                .await
                .with_context(|| format!("connecting to {host}:{port}"))?;
            let stream = self
                .tls()?
                .connect(server_name, stream)
                .await
                .context("the TLS handshake with the attester failed")?;

            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .context("the HTTP handshake with the attester failed")?;
            // The connection task ends when the response has been read; a dropped sender closes it.
            tokio::spawn(async move {
                let _ = connection.await;
            });

            let authority = uri
                .authority()
                .map(|value| value.as_str().to_owned())
                .unwrap_or_else(|| host.to_owned());
            let path = uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/");
            let request = Request::get(path)
                .header(hyper::header::HOST, authority)
                .header(hyper::header::ACCEPT, "application/json")
                .body(String::new())
                .context("building the key-set request")?;

            let response = sender
                .send_request(request)
                .await
                .context("requesting the key set")?;
            let status = response.status();
            if !status.is_success() {
                bail!("the key-set endpoint answered {status}");
            }

            collect_bounded(response.into_body()).await
        };

        tokio::time::timeout(REQUEST_TIMEOUT, connect)
            .await
            .map_err(|_| anyhow!("the key-set request timed out"))?
    }
}

/// Reads a response body, refusing anything past the cap rather than buffering it.
async fn collect_bounded<B>(body: B) -> Result<Vec<u8>>
where
    B: hyper::body::Body,
    B::Data: bytes::Buf,
    B::Error: std::fmt::Display,
{
    let mut body = std::pin::pin!(body);
    let mut collected = Vec::new();

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| anyhow!("reading the key set: {error}"))?;
        if let Some(chunk) = frame.data_ref() {
            let chunk = chunk.chunk();
            if collected.len() + chunk.len() > MAX_KEY_SET_BYTES {
                bail!("the key set is larger than {MAX_KEY_SET_BYTES} bytes");
            }
            collected.extend_from_slice(chunk);
        }
    }

    Ok(collected)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_jwks_uri_must_be_http_or_https() {
        let fetcher = HttpKeySetFetcher::new();

        for uri in ["file:///etc/passwd", "ftp://example.com/keys", "not a url"] {
            assert!(
                fetcher.fetch(uri).await.is_err(),
                "`{uri}` should not be fetched"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_attester_is_an_error_rather_than_an_empty_body() {
        let fetcher = HttpKeySetFetcher::new();
        // Nothing listens here; the cache treats this as "keep the previous set".
        let error = fetcher
            .fetch("http://127.0.0.1:1/jwks.json")
            .await
            .expect_err("an unreachable attester fails");
        assert!(!format!("{error}").is_empty());
    }
}
