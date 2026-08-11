use std::env;
use std::error::Error;

use axum::Json;
use axum::Router;
use axum::routing::get;
use serde::Serialize;

const SERVICE: &str = "trust-lab";

#[derive(Debug, Serialize)]
struct BaseResponse {
    service: &'static str,
    status: &'static str,
    message: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind = env::var("TRUST_LAB_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:7080".to_string());

    let router = Router::new().route("/", get(index));

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("{SERVICE} listening on {bind}");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn index() -> Json<BaseResponse> {
    Json(base_response())
}

fn base_response() -> BaseResponse {
    BaseResponse {
        service: SERVICE,
        status: "ok",
        message: "public trust lab API",
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_response_names_the_public_lab_api() {
        let response = base_response();

        assert_eq!(response.service, "trust-lab");
        assert_eq!(response.status, "ok");
        assert_eq!(response.message, "public trust lab API");
    }
}
