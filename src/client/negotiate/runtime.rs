//! Owns the synchronous client's execution-context and shutdown boundary.

use tokio::runtime::{Builder, Handle, Runtime};

use super::Error;

/// Private runtime owner; only destruction takes the runtime out of its slot.
pub(super) struct BlockingRuntime {
    /// Present until `Drop` consumes it for nonblocking shutdown.
    inner: Option<Runtime>,
}

impl BlockingRuntime {
    /// Create a runtime only outside an entered Tokio context.
    ///
    /// # Errors
    /// Returns a context rejection or the runtime builder's I/O error.
    pub(super) fn new() -> Result<Self, Error> {
        require_sync_context()?;
        Ok(Self {
            inner: Some(
                Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()?,
            ),
        })
    }

    /// Execute a client future only outside an entered Tokio context.
    ///
    /// # Errors
    /// Returns a runtime rejection before polling, or the client future's error.
    pub(super) fn block_on<F, T>(&self, future: F) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        require_sync_context()?;
        self.inner
            .as_ref()
            .ok_or(Error::BlockingRuntimeUnavailable)?
            .block_on(future)
    }
}

// Drop audit: shutdown_background consumes the runtime without waiting for blocking
// jobs; pending async tasks are cancelled and running DNS work finishes independently.
impl Drop for BlockingRuntime {
    fn drop(&mut self) {
        let Self { inner } = self;
        if let Some(runtime) = inner.take() {
            // Tokio's zero-timeout shutdown never waits for its blocking pool.
            // Async tasks are dropped; any running system DNS job finishes independently.
            runtime.shutdown_background();
        }
    }
}

/// Reject entered runtimes, including synchronous enter guards and blocking workers.
///
/// # Errors
/// Returns [`Error::BlockingRuntimeUnavailable`] if a Tokio handle is current.
fn require_sync_context() -> Result<(), Error> {
    Handle::try_current()
        .is_err()
        .ok_or(Error::BlockingRuntimeUnavailable)
}
