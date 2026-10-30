//! Preauthentication challenge request construction.

use super::{
    AsReq, BuiltAsReq, EncryptionKey, Error, KDC_ERR_PREAUTH_REQUIRED, KdcError, KerberosEtype,
    Keytab, PA_FX_COOKIE, Principal, build_as_req, build_preauthenticated_as_req,
    derive_password_reply_key, preauth_retry_options, process_kdc_error, select_keytab_reply_key,
    select_preauth_key_info,
};

/// RFC 4120 `KDC_ERR_PREAUTH_FAILED`.
const PREAUTH_FAILED: i32 = 24;

/// Whether the KDC supplied an implemented hint from the original enctype list.
fn usable_hints(error: &KdcError, requested: &AsReq) -> bool {
    error.preauth_key_info.iter().any(|info| {
        requested.etypes.contains(&info.etype) && KerberosEtype::from_etype_id(info.etype).is_some()
    })
}

/// Build at most one cookie-only discovery request after a hint-free optimistic failure.
///
/// # Errors
/// Returns decoding or request construction errors; malformed hints never trigger discovery.
pub(super) fn discovery_request(
    initial: &BuiltAsReq,
    requested: &AsReq,
    response: &[u8],
) -> Result<Option<BuiltAsReq>, Error> {
    if !requested.assume_preauthentication {
        return Ok(None);
    }
    let error = process_kdc_error(response)?;
    if error.error_code != PREAUTH_FAILED || usable_hints(&error, requested) {
        return Ok(None);
    }
    let mut probe = requested.clone();
    probe.assume_preauthentication = false;
    probe.fast_negotiation = false;
    probe.padata = error
        .method_data
        .into_iter()
        .filter(|pa| pa.r#type == PA_FX_COOKIE)
        .collect();
    build_as_req(initial.client.clone(), initial.service.clone(), probe).map(Some)
}

/// Require a usable error25 after discovery, never another recovery or an unverified AS-REP.
///
/// # Errors
/// Returns the KDC error or decode error when no guided encrypted-timestamp request is possible.
pub(super) fn validate_discovery(response: &[u8], requested: &AsReq) -> Result<(), Error> {
    let error = process_kdc_error(response)?;
    if error.error_code == KDC_ERR_PREAUTH_REQUIRED && usable_hints(&error, requested) {
        Ok(())
    } else {
        Err(Error::Kdc(Box::new(error)))
    }
}

/// Admit error24 only for an optimistic exchange with usable key hints.
///
/// The caller sends this request once, then processes the final reply directly;
/// this helper never loops or changes the encrypted-timestamp mechanism.
/// # Errors
/// Returns the original KDC error for nonoptimistic, hint-free or unusable failures.
fn challenge(bytes: &[u8], requested: &AsReq) -> Result<KdcError, Error> {
    let error = process_kdc_error(bytes)?;
    let guided_failure = error.error_code == PREAUTH_FAILED
        && requested.assume_preauthentication
        && usable_hints(&error, requested);
    if error.error_code == KDC_ERR_PREAUTH_REQUIRED || guided_failure {
        Ok(error)
    } else {
        Err(Error::Kdc(Box::new(error)))
    }
}

/// Answer a required-preauth challenge or hinted optimistic failure with an AS-REQ
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
    let error = challenge(kdc_error_bytes, &requested)?;
    let key_info = select_preauth_key_info(&error, &requested.etypes)?;
    let reply_key = derive_password_reply_key(&client, password, &key_info)?;
    let options = preauth_retry_options(requested, &error.method_data);
    let request = build_preauthenticated_as_req(client, service, options, &reply_key, None)?;
    Ok((request, reply_key))
}

/// Answer a required-preauth challenge or hinted optimistic failure with an AS-REQ
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
    let error = challenge(kdc_error_bytes, &requested)?;
    let key_info = select_preauth_key_info(&error, &requested.etypes)?;
    let (reply_key, kvno) = select_keytab_reply_key(keytab, &client, &key_info)?;
    let options = preauth_retry_options(requested, &error.method_data);
    let request = build_preauthenticated_as_req(client, service, options, &reply_key, Some(kvno))?;
    Ok((request, reply_key))
}
