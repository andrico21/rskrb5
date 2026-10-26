//! Turns `Option` and `Result` failures into test errors that name what failed.

use core::{error, fmt::Display};

/// The error type the tests return.
pub(crate) type TestError = Box<dyn error::Error>;

/// Attaches a description to a failure, as `expect` would, but as an error
/// that `?` propagates.
pub(crate) trait Context<T> {
    /// Returns the value, or an error that names `what`.
    ///
    /// # Errors
    ///
    /// Returns a [`TestError`] that names `what` (and the cause, when there is
    /// one) if `self` holds no value.
    fn context(self, what: &str) -> Result<T, TestError>;
}

impl<T, E: Display> Context<T> for Result<T, E> {
    fn context(self, what: &str) -> Result<T, TestError> {
        self.map_err(|cause| format!("{what}: {cause}").into())
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, what: &str) -> Result<T, TestError> {
        self.ok_or_else(|| what.into())
    }
}
