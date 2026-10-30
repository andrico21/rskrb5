//! Background renewal task ownership.

use tokio::task::JoinHandle;

/// Handle for a background Tokio TGT auto-renewal task.
///
/// Keep the handle alive for as long as renewal is needed. Dropping it cancels
/// the task, including when a spawn call's result is discarded immediately.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use std::sync::Arc;
/// use rskrb5_ng::client::Tokio;
/// use tokio::sync::Mutex;
/// fn spawn(client: Arc<Mutex<Tokio>>) {
///     Tokio::spawn_auto_renewal(client);
/// }
/// ```
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use std::{sync::Arc, time::Duration};
/// use rskrb5_ng::client::Tokio;
/// use tokio::sync::Mutex;
/// fn spawn(client: Arc<Mutex<Tokio>>) {
///     Tokio::spawn_auto_renewal_with_retry(client, Duration::from_secs(60));
/// }
/// ```
///
/// ```no_run
/// #![deny(unused_must_use)]
/// use std::sync::Arc;
/// use rskrb5_ng::client::{Tokio, TokioClientAutoRenewal};
/// use tokio::sync::Mutex;
/// fn spawn(client: Arc<Mutex<Tokio>>) -> TokioClientAutoRenewal {
///     let renewal = Tokio::spawn_auto_renewal(client);
///     renewal
/// }
/// ```
#[derive(Debug)]
#[must_use = "dropping the handle cancels the renewal task"]
pub struct Handle {
    /// The spawned renewal task.
    handle: JoinHandle<()>,
}

impl Handle {
    /// Attach cancellation ownership to the spawned task.
    pub(super) const fn new(handle: JoinHandle<()>) -> Self {
        Self { handle }
    }

    /// Request cancellation of the background renewal task.
    #[inline]
    pub fn abort(&self) {
        self.handle.abort();
    }
    #[must_use]
    /// Whether the background task has finished.
    #[inline]
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

// Drop audit: `JoinHandle::abort` only signals the task, never blocks or panics;
// the task stops at its next await point and owns only an `Arc` of the client.
impl Drop for Handle {
    #[inline]
    fn drop(&mut self) {
        self.handle.abort();
    }
}
