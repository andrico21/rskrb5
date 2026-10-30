//! Background renewal task ownership.

use tokio::task::JoinHandle;

/// Handle for a background Tokio TGT auto-renewal task.
#[derive(Debug)]
pub struct TokioClientAutoRenewal {
    /// The spawned renewal task.
    handle: JoinHandle<()>,
}

impl TokioClientAutoRenewal {
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
impl Drop for TokioClientAutoRenewal {
    #[inline]
    fn drop(&mut self) {
        self.handle.abort();
    }
}
