use super::{CONTEXT_FLAG_DELEG, Error, GSSAPI_CHECKSUM_TYPE};
use crate::krb_cred;

/// Check RFC 4121 section 4.1.1 without imposing GSS rules on generic Kerberos.
///
/// # Errors
///
/// Returns a missing-field error or [`Error::InvalidAuthenticatorChecksum`].
pub(super) fn validate(authenticator: &rasn_kerberos::Authenticator) -> Result<(), Error> {
    let checksum = authenticator
        .cksum
        .as_ref()
        .ok_or(Error::MissingAuthenticatorChecksum)?;
    if checksum.r#type != GSSAPI_CHECKSUM_TYPE {
        return Err(Error::InvalidAuthenticatorChecksum);
    }
    let (length, binding_fields) = checksum
        .checksum
        .split_first_chunk::<4>()
        .ok_or(Error::InvalidAuthenticatorChecksum)?;
    if u32::from_le_bytes(*length) != 16 {
        return Err(Error::InvalidAuthenticatorChecksum);
    }
    let (_bindings, flag_fields) = binding_fields
        .split_first_chunk::<16>()
        .ok_or(Error::InvalidAuthenticatorChecksum)?;
    let (flags, trailing_fields) = flag_fields
        .split_first_chunk::<4>()
        .ok_or(Error::InvalidAuthenticatorChecksum)?;
    if u32::from_le_bytes(*flags) & CONTEXT_FLAG_DELEG != 0 {
        let (option, length_fields) = trailing_fields
            .split_first_chunk::<2>()
            .ok_or(Error::InvalidAuthenticatorChecksum)?;
        let (delegation_length, credential_fields) = length_fields
            .split_first_chunk::<2>()
            .ok_or(Error::InvalidAuthenticatorChecksum)?;
        if u16::from_le_bytes(*option) != 1 {
            return Err(Error::InvalidAuthenticatorChecksum);
        }
        let (credential, _extensions) = credential_fields
            .split_at_checked(usize::from(u16::from_le_bytes(*delegation_length)))
            .ok_or(Error::InvalidAuthenticatorChecksum)?;
        // Validate only the KRB-CRED envelope, not delegated credential semantics.
        drop(
            krb_cred::decode(credential)
                .map_err(|_malformed| Error::InvalidAuthenticatorChecksum)?,
        );
    }
    let _sequence = authenticator
        .seq_number
        .ok_or(Error::MissingAuthenticatorSequence)?;
    Ok(())
}
