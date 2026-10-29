//! Result code interpretation.

use super::{ChangePasswordResult, Error, KPASSWD_SUCCESS};

impl ChangePasswordResult {
    /// Parse a cleartext password-change response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ResponseTooShort`] when `bytes` is shorter than the
    /// two-byte result code.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let [code_high, code_low, text @ ..] = bytes else {
            return Err(Error::ResponseTooShort {
                actual: bytes.len(),
            });
        };
        let text_raw = text.to_vec();
        Ok(Self {
            code: u16::from_be_bytes([*code_high, *code_low]),
            text: String::from_utf8_lossy(&text_raw).into_owned(),
            text_raw,
        })
    }

    #[must_use]
    /// Whether this result indicates a successful password change.
    #[inline]
    pub const fn is_success(&self) -> bool {
        self.code == KPASSWD_SUCCESS
    }

    /// Return success or an error carrying the kpasswd failure code and text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PasswordChangeFailed`] carrying the code and text when
    /// the code is not [`KPASSWD_SUCCESS`].
    #[inline]
    pub fn ensure_success(&self) -> Result<(), Error> {
        if self.is_success() {
            Ok(())
        } else {
            Err(Error::PasswordChangeFailed {
                code: self.code,
                text: self.text.clone(),
                text_raw: self.text_raw.clone(),
            })
        }
    }
}
