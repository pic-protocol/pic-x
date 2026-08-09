//! What a listener refuses, proved against a running one.
//!
//! Each of these is a way to take a server down without sending it a single valid request, so each is
//! written as the attack rather than as a call to a getter: a body larger than the limit, a request
//! that never finishes, more sockets than the surface will hold. A limit that is configured but not
//! wired reads exactly like a limit that works, right up to the day it matters.
//!
//! Plain HTTP throughout. Whether the bytes arrived over TLS makes no difference to any of these, and
//! doing it in the clear means the request can be written by hand and the answer read back literally.

use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use pic_x_core::Limits;
use pic_x_transport::Surface;

/// A handler that reads its whole body, and one that takes longer than any timeout under test.
fn router() -> Router {
    Router::new()
        .route("/", get(|| async { "served\n" }))
        .route(
            "/echo",
            post(|body: String| async move { body.len().to_string() }),
        )
        .route("/panic", get(panicking))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;

                "eventually\n"
            }),
        )
}

/// A handler that does not survive its own arithmetic.
///
/// A named function rather than a closure because a body that only diverges leaves axum nothing to
/// infer a response type from, and the return type is the whole of what it needs.
async fn panicking() -> &'static str {
    panic!("a handler that did not survive its own arithmetic")
}

/// Sends `request` verbatim and reads back whatever the surface says, to the end of the connection.
///
/// Written by hand rather than with a client library because two of these tests are about malformed
/// or oversized requests, and a client library's job is to stop those from being sent.
async fn exchange(address: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("the surface accepts a connection");
    stream
        .write_all(request)
        .await
        .expect("the request is sent");
    stream.flush().await.expect("the request is flushed");

    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;

    String::from_utf8_lossy(&answer).into_owned()
}

/// The first line of an answer, which is the status.
fn status(answer: &str) -> &str {
    answer.lines().next().unwrap_or_default()
}

/// The value of `header` in an answer, if it is there.
fn header<'a>(answer: &'a str, header: &str) -> Option<&'a str> {
    answer
        .lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;

            name.eq_ignore_ascii_case(header).then(|| value.trim())
        })
}

#[tokio::test]
async fn test_a_body_over_the_limit_is_refused_rather_than_read() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .limits(Limits::default().with_body_bytes(64))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    let oversized = "x".repeat(4096);
    let answer = exchange(
        address,
        format!(
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{oversized}",
            oversized.len()
        )
        .as_bytes(),
    )
    .await;

    assert!(
        status(&answer).contains("413"),
        "a body sixty-four times the limit was not refused: {}",
        status(&answer)
    );

    // And the limit is a limit, not a ban: something under it still goes through.
    let small = "x".repeat(16);
    let answer = exchange(
        address,
        format!(
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{small}",
            small.len()
        )
        .as_bytes(),
    )
    .await;

    assert!(
        status(&answer).contains("200"),
        "a body well under the limit was refused: {}",
        status(&answer)
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_request_that_outlasts_the_timeout_is_given_up_on() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .limits(Limits::default().with_request_timeout(Duration::from_millis(200)))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // The handler sleeps for thirty seconds. Without the timeout this test would take thirty seconds
    // and pass; with it, the answer arrives in a fraction of one and says so.
    let started = std::time::Instant::now();
    let answer = exchange(
        address,
        b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        status(&answer).contains("408"),
        "a request that ran long was not cut off: {}",
        status(&answer)
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the answer took {:?}, which is the handler finishing rather than the timeout firing",
        started.elapsed()
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_handler_that_panics_answers_and_the_connection_survives() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // Keep-alive on purpose: the claim is not only that the panic becomes an answer, but that the
    // connection it happened on is still usable afterwards. A panic that silently costs a connection
    // is a client that reconnects and an operator who sees a network fault.
    let mut stream = TcpStream::connect(address)
        .await
        .expect("the surface accepts a connection");
    stream
        .write_all(b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("the request is sent");

    let mut buffer = [0_u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .expect("the surface answers rather than hanging up")
        .expect("the answer is readable");
    let answer = String::from_utf8_lossy(&buffer[..read]).into_owned();

    assert!(
        status(&answer).contains("500"),
        "a panic did not become an answer: {}",
        status(&answer)
    );
    // The panic message names internals. The client is not the audience for those.
    assert!(
        !answer.contains("arithmetic"),
        "the panic message was sent to the client: {answer}"
    );

    // And the same connection still serves.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("the connection is still open");
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(
        String::from_utf8_lossy(&rest).contains("200"),
        "the connection did not survive the panic: {}",
        String::from_utf8_lossy(&rest)
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_client_that_never_finishes_its_request_head_is_hung_up_on() {
    // Slowloris. Not an idle connection — a busy one, sending a valid header every fifty milliseconds
    // and never the blank line that ends the head. Nothing a request is wrapped in ever sees it,
    // because there is no request yet: the timeout, the body limit and the concurrency ceiling all
    // begin once the protocol has something to hand over. Only this stops it.
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .limits(Limits::default().with_header_timeout(Duration::from_millis(300)))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    let stream = TcpStream::connect(address)
        .await
        .expect("the surface accepts a connection");
    let (mut reader, mut writer) = stream.into_split();

    let dribbling = tokio::spawn(async move {
        if writer
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .is_err()
        {
            return;
        }

        while writer.write_all(b"X-Padding: x\r\n").await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let started = std::time::Instant::now();
    let mut answer = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut answer)).await;
    dribbling.abort();

    assert!(
        ended.is_ok(),
        "the connection was still open after five seconds of an unfinished request head"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the head was tolerated for {:?}, which is not the configured 300ms",
        started.elapsed()
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_sockets_beyond_the_limit_are_refused_and_a_released_one_is_reusable() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .limits(Limits::default().with_connections(2))
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // Two connections opened and left idle — the attack this bounds is exactly this, at scale: sockets
    // held open with nothing sent on them, costing the server everything and the client nothing.
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(
            TcpStream::connect(address)
                .await
                .expect("a connection under the limit is accepted"),
        );
    }

    // The kernel completes a third TCP handshake regardless — the backlog is not ours to refuse from.
    // What we control is whether it is ever served, so the proof is that a request on it gets nothing
    // back rather than that connecting fails.
    let refused = tokio::time::timeout(
        Duration::from_secs(3),
        exchange(
            address,
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ),
    )
    .await;

    assert!(
        matches!(&refused, Ok(answer) if answer.is_empty()),
        "a connection over the limit was served: {refused:?}"
    );

    // Releasing one lets the next in. This is the half that matters in production: a limit that never
    // recovers is an outage with extra steps.
    held.pop();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let answer = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status(&answer).contains("200"),
        "the slot freed by a closed connection was not reused: {}",
        status(&answer)
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_every_answer_names_the_request_it_answers() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // Nothing sent: the surface names it.
    let answer = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let generated = header(&answer, "x-request-id").expect("the answer names the request");
    assert_eq!(
        generated.len(),
        16,
        "a generated name reads oddly: {generated}"
    );

    // A second request gets a different one, or the name is not a name.
    let answer = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_ne!(
        header(&answer, "x-request-id"),
        Some(generated),
        "two requests were given the same name"
    );

    // A name the client brought is kept, so a trace that started upstream stays one trace.
    let answer = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: upstream-42\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        header(&answer, "x-request-id"),
        Some("upstream-42"),
        "a client-supplied name was discarded"
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_name_a_client_could_forge_a_log_line_with_is_replaced() {
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .start()
        .await
        .expect("the listener binds");
    let address = surface.address();

    // Not rejected — replaced. A request is not worth failing over a bad label, but the label must not
    // survive into the log or into the header, which is what this proves.
    let answer = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: forged\" event.name=\"audit.appended\r\nConnection: close\r\n\r\n",
    )
    .await;

    let named = header(&answer, "x-request-id").expect("the answer still names the request");
    assert_ne!(named, "forged\" event.name=\"audit.appended");
    assert_eq!(named.len(), 16, "the forged name was not replaced: {named}");

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}
