//! Password payload ownership and encoding.

use core::fmt;

use super::{
    ChangePasswdData, Error,
    codec::{decode, encode, kerberos_string, principal_name},
};

impl fmt::Debug for ChangePasswdData {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            new_passwd: _,
            targ_name,
            targ_realm,
        } = self;
        f.debug_struct("ChangePasswdData")
            .field("new_passwd", &"[REDACTED]")
            .field("targ_name", targ_name)
            .field("targ_realm", targ_realm)
            .finish()
    }
}

impl ChangePasswdData {
    /// Create password-change data for the authenticated principal.
    #[inline]
    pub fn new<P>(new_passwd: P) -> Self
    where
        P: AsRef<[u8]>,
    {
        Self {
            new_passwd: new_passwd.as_ref().to_vec().into(),
            targ_name: None,
            targ_realm: None,
        }
    }

    /// Create password-change data for an explicit target principal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKerberosString`] when a name component or the
    /// realm is not a valid Kerberos string.
    #[inline]
    pub fn for_target<I, S, P>(
        new_passwd: P,
        name_type: i32,
        components: I,
        realm: &str,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        P: AsRef<[u8]>,
    {
        Ok(Self {
            new_passwd: new_passwd.as_ref().to_vec().into(),
            targ_name: Some(principal_name(name_type, components)?),
            targ_realm: Some(kerberos_string(realm)?),
        })
    }

    /// Decode DER-encoded password-change data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not DER `ChangePasswdData`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode("ChangePasswdData", bytes)
    }

    /// Encode password-change data using DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode("ChangePasswdData", self)
    }
}
