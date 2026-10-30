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

    use tokio::{sync::Mutex, task::yield_now};

    use super::*;

    /// Pins that the auto-renewal handle aborts its task.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_auto_renewal_handle_aborts() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let client = Arc::new(Mutex::new(Tokio::from_tgt_session(
                Config::new(),
                KdcProtocol::Tcp,
                current_tgt_session(10, 50)?,
            )));
            let renewal = Tokio::spawn_auto_renewal_with_retry(client, Duration::from_millis(10));

            assert!(!renewal.is_finished());
            renewal.abort();
            yield_now().await;
            Ok::<(), TestError>(())
        })?;
        Ok(())
    }
}
