// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The administrative RPCs PIC-X itself defines.
//!
//! Two of them, and deliberately dull: what this build is, and whether it is willing to be sent work.
//! Everything that changes the state of a deployment is added by registering services — see
//! [`ServiceProvider`](crate::ServiceProvider) — so the vocabulary can grow without this file being
//! the place it grows in.

use tonic::{Request, Response, Status};

use pic_x_core::Health;

use crate::v1::admin_server::Admin;
use crate::v1::{GetHealthRequest, GetHealthResponse, GetVersionRequest, GetVersionResponse};

/// The implementation of the administrative RPCs PIC-X itself defines.
pub(crate) struct AdminApi {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: Health,
}

#[tonic::async_trait]
impl Admin for AdminApi {
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            product: self.product.clone(),
            version: self.version.clone(),
            commit: self.commit.clone(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<GetHealthRequest>,
    ) -> Result<Response<GetHealthResponse>, Status> {
        Ok(Response::new(GetHealthResponse {
            live: self.health.is_live(),
            ready: self.health.is_ready(),
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use pic_x_core::{Config, ProductIdentity, ServerContext};
    use pic_x_std::audit::RecordingAuditSink;
    use pic_x_std::storage::MemoryStorage;

    use crate::v1::{GetHealthRequest, GetVersionRequest};

    fn identity() -> ProductIdentity {
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
    }

    #[tokio::test]
    async fn test_the_rpcs_answer_what_the_context_says() {
        let config = Config::default();
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let context = ServerContext::new(identity(), &config, &storage, &audit);
        context.health().set_ready(true);

        let api = AdminApi {
            product: context.identity().product_name().to_owned(),
            version: context.config().version().to_owned(),
            commit: context.config().commit().to_owned(),
            health: context.health().clone(),
        };

        let version = api
            .get_version(Request::new(GetVersionRequest {}))
            .await
            .expect("the version answers")
            .into_inner();
        assert_eq!(version.product, "Demo X");
        assert_eq!(version.version, config.version());

        let health = api
            .get_health(Request::new(GetHealthRequest {}))
            .await
            .expect("the health answers")
            .into_inner();
        assert!(health.live);
        assert!(health.ready);
    }

    #[tokio::test]
    async fn test_health_follows_the_state_the_host_flips() {
        let config = Config::default();
        let storage = MemoryStorage::new();
        let audit = RecordingAuditSink::new();
        let context = ServerContext::new(identity(), &config, &storage, &audit);

        let api = AdminApi {
            product: "Demo X".to_owned(),
            version: "9.9.9".to_owned(),
            commit: "abc123".to_owned(),
            health: context.health().clone(),
        };

        // Not ready before the host says so, which is what a probe during startup must see.
        let before = api
            .get_health(Request::new(GetHealthRequest {}))
            .await
            .expect("the health answers")
            .into_inner();
        assert!(!before.ready);

        context.health().set_ready(true);

        let after = api
            .get_health(Request::new(GetHealthRequest {}))
            .await
            .expect("the health answers")
            .into_inner();
        assert!(after.ready);
    }
}
