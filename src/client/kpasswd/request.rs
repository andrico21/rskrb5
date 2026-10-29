//! Request authenticator construction and KRB-PRIV options.

use std::time::UNIX_EPOCH;

use rasn::types::Integer;

use super::RequestOptions;
use crate::{
    client::{
        ApReq, BuiltApReq, Error, TgsRepSession, build_ap_req_with_confounder,
        kerberos_time_from_system_time,
    },
    keytab::EncryptionKey,
    krb_priv::EncKrbPrivPartOptions,
    messages,
};

/// Build the kpasswd AP-REQ that carries `reply_key` as its subkey and the
/// request sequence number.
///
/// # Errors
///
/// Returns an error when the AP-REQ authenticator cannot be built, encrypted
/// or encoded from the service ticket and options.
pub(super) fn build_kpasswd_ap_req_with_confounder(
    service_ticket: &TgsRepSession,
    reply_key: &EncryptionKey,
    options: &RequestOptions,
    ap_req_confounder: &[u8],
) -> Result<BuiltApReq, Error> {
    let _micros = messages::microseconds("request.cusec", &Integer::from(options.cusec))
        .map_err(|_invalid| Error::KpasswdReplyControl("request time range"))?;
    if options.timestamp.duration_since(UNIX_EPOCH).map_or_else(
        |error| error.duration().subsec_nanos() != 0,
        |duration| duration.subsec_nanos() != 0,
    ) {
        return Err(Error::KpasswdReplyControl("request time range"));
    }
    build_ap_req_with_confounder(
        service_ticket,
        ApReq::new()
            .with_subkey(Some(reply_key.clone()))
            .with_sequence_number(Some(options.sequence_number)),
        options.timestamp,
        options.cusec,
        ap_req_confounder,
    )
}

/// Translate kpasswd request options into KRB-PRIV encrypted-part options.
///
/// # Errors
///
/// Returns an error when the request timestamp is outside the Kerberos time
/// range.
pub(super) fn kpasswd_krb_priv_options(
    options: &RequestOptions,
) -> Result<EncKrbPrivPartOptions, Error> {
    let mut krb_priv_options = EncKrbPrivPartOptions::new(options.sender_address.clone())
        .with_timestamp(
            kerberos_time_from_system_time(options.timestamp)?,
            options.cusec,
        )
        .with_sequence_number(options.sequence_number);
    if let Some(recipient_address) = &options.recipient_address {
        krb_priv_options = krb_priv_options.with_recipient_address(recipient_address.clone());
    }
    Ok(krb_priv_options)
}
