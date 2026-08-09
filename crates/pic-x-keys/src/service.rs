//! The part of the key ring that has to keep happening.
//!
//! Rotation is a schedule, and a schedule nobody runs is a comment. This is the thing that runs it:
//! one pass at startup, and one every tick after that.
//!
//! Startup is deliberately not "best effort". A deployment whose key ring cannot be read or written
//! is a deployment that will fail to sign later, at a moment nobody chose, and it is far better to
//! fail while somebody is watching the server start.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use pic_x_core::{BoxFuture, KeyManager, ServerContext, Service, ready};

// The manager is taken from the context rather than from a constructor, because which manager
// exists is a question the configuration answers and this service is registered before any
// configuration has been read.

/// The `component` every record of the key ring carries.
const COMPONENT: &str = "keys";

/// How often the lifecycle is advanced.
///
/// A minute, regardless of how long the windows are: the pass is a small file read that changes
/// nothing almost every time, and a cadence tied to the policy would mean a deployment with a
/// one-hour `publish_ahead` could be up to an hour late to honour it.
const TICK: Duration = Duration::from_secs(60);

/// Advances the key lifecycle, at startup and on a timer.
pub struct KeyService {
    tick: Duration,
    running: Mutex<Option<Running>>,
}

/// The ticking task, and the way to ask it to stop.
struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for KeyService {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyService {
    /// Builds the service that maintains whichever key ring the context carries.
    pub fn new() -> Self {
        Self {
            tick: TICK,
            running: Mutex::new(None),
        }
    }

    /// Advances the lifecycle at a different cadence, which is what a test wants.
    pub fn every(mut self, tick: Duration) -> Self {
        self.tick = tick;

        self
    }

    /// Runs one pass, recording only what it actually changed.
    ///
    /// Silence when nothing happened is the point: a rotation is rare and worth noticing, and a
    /// record every minute saying that nothing rotated is how the one that mattered gets missed.
    fn pass(keys: &dyn KeyManager) -> Result<()> {
        let report = keys.maintain().context("advancing the key lifecycle")?;

        if report.is_empty() {
            return Ok(());
        }

        info!(
            event.name = "keys.maintained",
            component = COMPONENT,
            keys.published = report.published,
            keys.activated = report.activated,
            keys.retired = report.retired,
            keys.forgotten = report.forgotten,
            "the key ring changed"
        );

        Ok(())
    }
}

impl Service for KeyService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(keys) = context.keys().map(Arc::clone) else {
                info!(
                    event.name = "keys.disabled",
                    component = COMPONENT,
                    "this deployment publishes no signing keys"
                );

                return Ok(());
            };

            Self::pass(keys.as_ref())?;

            let active = keys
                .active_key_id()
                .context("reading back the key that will sign")?;

            let (stop, mut stopped) = watch::channel(false);
            let manager = keys.name();
            let tick = self.tick;

            let task = tokio::spawn(async move {
                let mut timer = tokio::time::interval(tick);
                // The first tick of an interval fires immediately, and the pass it would run has
                // just been run by `start`.
                timer.tick().await;

                loop {
                    tokio::select! {
                        _ = timer.tick() => {
                            if let Err(error) = Self::pass(keys.as_ref()) {
                                // A pass that fails is not fatal: the ring on disk is unchanged, the
                                // active key still signs, and the next pass may well succeed. What
                                // is not acceptable is failing quietly.
                                warn!(
                                    event.name = "keys.maintenance_failed",
                                    component = COMPONENT,
                                    error = %format!("{error:#}"),
                                    "the key lifecycle did not advance"
                                );
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the key service lock is poisoned"))? =
                Some(Running { task, stop });

            info!(
                event.name = "keys.ready",
                component = COMPONENT,
                keys.manager = manager,
                keys.active = %active,
                "signing"
            );

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the key service lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };

            // The receiver lives in the task, so this only fails if the task is already gone.
            let _ = running.stop.send(true);

            match running.task.await {
                Ok(()) => debug!(
                    event.name = "keys.stopped",
                    component = COMPONENT,
                    "no longer maintaining the key ring"
                ),
                Err(error) => warn!(
                    event.name = "keys.stop_failed",
                    component = COMPONENT,
                    error = %error,
                    "the key maintenance task did not finish"
                ),
            }

            Ok(())
        })
    }
}
