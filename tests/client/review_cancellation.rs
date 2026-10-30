//! Auto-renewal task cancellation regressions.

use super::*;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;

    use tokio::{sync::Mutex, task::yield_now, time::timeout};

    use super::*;

    /// Observe cancellation without assuming one yield is enough for the scheduler.
    ///
    /// cancel-safe: only observes task state; dropping this future mutates nothing.
    async fn await_cleanup<F>(finished: F) -> Result<(), TestError>
    where
        F: Fn() -> bool + Send + Sync,
    {
        timeout(Duration::from_secs(2), async {
            while !finished() {
                yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    /// Pins that the auto-renewal handle aborts its task.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_auto_renewal_handle_aborts() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given: a live owner blocked by our mutex, unable to exit normally.
            let client = Arc::new(Mutex::new(Tokio::from_tgt_session(
                Config::new(),
                KdcProtocol::Tcp,
                current_tgt_session(10, 50)?,
            )));
            let guard = client.lock().await;
            let owner = Arc::downgrade(&client);
            let renewal = Tokio::spawn_auto_renewal_with_retry(
                Arc::clone(&client),
                Duration::from_millis(10),
            );

            assert!(!renewal.is_finished());
            assert_eq!(owner.strong_count(), 2);
            // When: explicit abort requests cancellation while the handle remains alive.
            renewal.abort();
            // Then: task completion and captured-owner release precede handle/runtime drop.
            await_cleanup(|| renewal.is_finished() && owner.strong_count() == 1).await?;
            assert!(renewal.is_finished());
            assert_eq!(owner.strong_count(), 1);
            drop(guard);
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }

    /// Dropping the handle must release the captured client without runtime teardown.
    #[test]
    fn tokio_client_auto_renewal_drop_releases_owner() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given: a task that cannot complete while the test holds the client lock.
            let client = Arc::new(Mutex::new(Tokio::from_tgt_session(
                Config::new(),
                KdcProtocol::Tcp,
                current_tgt_session(10, 50)?,
            )));
            let guard = client.lock().await;
            let owner = Arc::downgrade(&client);
            let renewal = Tokio::spawn_auto_renewal(Arc::clone(&client));
            assert_eq!(owner.strong_count(), 2);

            // When: the cancellation owner is dropped, without explicitly aborting.
            drop(renewal);

            // Then: the background task releases its client while the runtime is alive.
            await_cleanup(|| owner.strong_count() == 1).await?;
            assert_eq!(owner.strong_count(), 1);
            drop(guard);
            Ok::<(), TestError>(())
        })
    }
}
