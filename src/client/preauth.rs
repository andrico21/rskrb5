//! Preauthentication challenge request construction.

use super::{
    AsReq, BuiltAsReq, EncryptionKey, Error, KDC_ERR_PREAUTH_REQUIRED, Keytab, Principal,
    build_preauthenticated_as_req, derive_password_reply_key, preauth_retry_options,
    process_kdc_error, select_keytab_reply_key, select_preauth_key_info,
};

/// Answer a `KDC_ERR_PREAUTH_REQUIRED` error with a preauthenticated AS-REQ
/// keyed from `password`.
///
/// # Errors
///
/// Returns [`Error::Kdc`] for any other KDC error, and errors from key-info
/// selection, password key derivation and request building.
pub(super) fn password_preauth_request(
    client: Principal,
    service: Principal,
    password: &[u8],
    requested: AsReq,
    kdc_error_bytes: &[u8],
) -> Result<(BuiltAsReq, EncryptionKey), Error> {
    let error = process_kdc_error(kdc_error_bytes)?;
    if error.error_code != KDC_ERR_PREAUTH_REQUIRED {
        return Err(Error::Kdc(Box::new(error)));
    }
    let key_info = select_preauth_key_info(&error, &requested.etypes)?;
    let reply_key = derive_password_reply_key(&client, password, &key_info)?;
    let options = preauth_retry_options(requested, &error.method_data);
    let request = build_preauthenticated_as_req(client, service, options, &reply_key, None)?;
    Ok((request, reply_key))
}

/// Answer a `KDC_ERR_PREAUTH_REQUIRED` error with a preauthenticated AS-REQ
/// keyed from the keytab.
///
/// # Errors
///
/// Returns [`Error::Kdc`] for any other KDC error, and errors from key-info
/// selection, keytab lookup and request building.
pub(super) fn keytab_preauth_request(
    client: Principal,
    service: Principal,
    keytab: &Keytab,
    requested: AsReq,
    kdc_error_bytes: &[u8],
) -> Result<(BuiltAsReq, EncryptionKey), Error> {
    let error = process_kdc_error(kdc_error_bytes)?;
    if error.error_code != KDC_ERR_PREAUTH_REQUIRED {
        return Err(Error::Kdc(Box::new(error)));
    }
    let key_info = select_preauth_key_info(&error, &requested.etypes)?;
    let (reply_key, kvno) = select_keytab_reply_key(keytab, &client, &key_info)?;
    let options = preauth_retry_options(requested, &error.method_data);
    let request = build_preauthenticated_as_req(client, service, options, &reply_key, Some(kvno))?;
    Ok((request, reply_key))
}
