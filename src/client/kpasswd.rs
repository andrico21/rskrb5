//! Client-side kpasswd request building and AP-REP verification helpers.

use core::time::Duration;
use std::time::SystemTime;

use super::{
    ApReqOptions, BuiltApReq, Error, TgsRepSession, ap_rep_error, build_ap_req_with_confounder,
    encryption_key_from_rasn, integer_to_u32, kerberos_time_from_system_time,
    system_time_from_kerberos_time,
};
use crate::{
    ap_rep::{decrypt_ap_rep_enc_part, validate_ap_rep},
    crypto::KerberosEtype,
    kadmin,
    keytab::EncryptionKey,
};

/// Options for constructing a kpasswd request from a service ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct KpasswdRequestOptions {
    /// Authenticator and KRB-PRIV timestamp.
    pub timestamp: SystemTime,
    /// Authenticator and KRB-PRIV microseconds.
    pub cusec: u32,
    /// Authenticator and KRB-PRIV sequence number.
    pub sequence_number: u32,
    /// Sender address used in the KRB-PRIV encrypted part.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient address used in the KRB-PRIV encrypted part.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

impl KpasswdRequestOptions {
    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                not(test)
            ),
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                feature = "evaluation",
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                feature = "default",
                feature = "evaluation",
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                not(test)
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                not(feature = "serde"),
                not(feature = "spnego"),
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                not(feature = "serde"),
                not(feature = "spnego"),
                feature = "tokio",
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::missing_const_for_fn,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Construct options with the required timestamp, sequence number, and sender address.
    #[inline]
    pub fn new(
        timestamp: SystemTime,
        cusec: u32,
        sequence_number: u32,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Self {
        Self {
            timestamp,
            cusec,
            sequence_number,
            sender_address,
            recipient_address: None,
        }
    }

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                not(test)
            ),
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                feature = "evaluation",
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                feature = "default",
                feature = "evaluation",
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                not(test)
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                not(feature = "serde"),
                not(feature = "spnego"),
                feature = "tokio",
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                not(feature = "serde"),
                not(feature = "spnego"),
                feature = "tokio",
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::return_self_not_must_use,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Set the optional recipient address.
    #[inline]
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

/// Built kpasswd request plus the key needed to decrypt the reply.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltKpasswdRequest {
    /// Parsed kpasswd request.
    pub request: kadmin::Request,
    /// Encoded kpasswd request frame.
    pub der: Vec<u8>,
    /// Authenticator subkey used to encrypt request KRB-PRIV payloads and reply KRB-PRIV payloads
    /// when the AP-REP does not select a server subkey.
    pub reply_key: EncryptionKey,
    /// Built AP-REQ metadata.
    pub ap_req: BuiltApReq,
}

/// Verified kpasswd AP-REP reply metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerifiedKpasswdApRep {
    /// Reply `ctime` without `cusec`.
    pub ctime: SystemTime,
    /// Reply microsecond field.
    pub cusec: u32,
    /// Reply timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::needless_pass_by_value,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Build a complete kpasswd request with explicit confounders.
///
/// # Errors
///
/// Returns an error when the AP-REQ cannot be built from the service ticket
/// (for example an unsupported session-key encryption type or a confounder of
/// the wrong length), when the request timestamp is outside the Kerberos time
/// range, or when the KRB-PRIV change-password payload cannot be encrypted or
/// encoded.
#[inline]
pub fn build_kpasswd_request_with_confounders(
    service_ticket: &TgsRepSession,
    change_data: &kadmin::ChangePasswdData,
    reply_key: EncryptionKey,
    options: KpasswdRequestOptions,
    ap_req_confounder: &[u8],
    krb_priv_confounder: &[u8],
) -> Result<BuiltKpasswdRequest, Error> {
    let ap_req = build_kpasswd_ap_req_with_confounder(
        service_ticket,
        &reply_key,
        &options,
        ap_req_confounder,
    )?;
    let krb_priv_options = kpasswd_krb_priv_options(&options)?;
    let built_request = kadmin::build_change_password_request_with_confounder(
        ap_req.message.clone(),
        change_data,
        reply_key,
        krb_priv_options,
        krb_priv_confounder,
    )?;

    Ok(BuiltKpasswdRequest {
        request: built_request.request,
        der: built_request.der,
        reply_key: built_request.reply_key,
        ap_req,
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::needless_pass_by_value,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Build a complete kpasswd request with generated reply key and confounders.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] when the service-ticket session key uses
/// an unsupported encryption type, an error when the operating system random
/// source fails, and the errors of [`build_kpasswd_request_with_confounders`]
/// for building, encrypting or encoding the request.
#[inline]
pub fn build_kpasswd_request(
    service_ticket: &TgsRepSession,
    change_data: &kadmin::ChangePasswdData,
    options: KpasswdRequestOptions,
) -> Result<BuiltKpasswdRequest, Error> {
    let etype = KerberosEtype::from_etype_id(service_ticket.session_key.etype)
        .ok_or(Error::UnsupportedEtype(service_ticket.session_key.etype))?;
    let mut reply_key = EncryptionKey {
        etype: service_ticket.session_key.etype,
        value: vec![0; etype.key_len()],
    };
    getrandom::fill(&mut reply_key.value)?;
    let mut ap_req_confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut ap_req_confounder)?;

    let ap_req = build_kpasswd_ap_req_with_confounder(
        service_ticket,
        &reply_key,
        &options,
        &ap_req_confounder,
    )?;
    let krb_priv_options = kpasswd_krb_priv_options(&options)?;
    let built_request = kadmin::build_change_password_request(
        ap_req.message.clone(),
        change_data,
        reply_key,
        krb_priv_options,
    )?;

    Ok(BuiltKpasswdRequest {
        request: built_request.request,
        der: built_request.der,
        reply_key: built_request.reply_key,
        ap_req,
    })
}

/// Build the kpasswd AP-REQ that carries `reply_key` as its subkey and the
/// request sequence number.
///
/// # Errors
///
/// Returns an error when the AP-REQ authenticator cannot be built, encrypted
/// or encoded from the service ticket and options.
fn build_kpasswd_ap_req_with_confounder(
    service_ticket: &TgsRepSession,
    reply_key: &EncryptionKey,
    options: &KpasswdRequestOptions,
    ap_req_confounder: &[u8],
) -> Result<BuiltApReq, Error> {
    build_ap_req_with_confounder(
        service_ticket,
        ApReqOptions::new()
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
fn kpasswd_krb_priv_options(
    options: &KpasswdRequestOptions,
) -> Result<kadmin::EncKrbPrivPartOptions, Error> {
    let mut krb_priv_options = kadmin::EncKrbPrivPartOptions::new(options.sender_address.clone())
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

/// Verify the AP-REP section of a successful kpasswd reply.
///
/// KRB-ERROR replies do not carry AP-REP and return `Ok(None)`. Successful
/// replies must echo the AP-REQ authenticator timestamp and are encrypted with
/// the kpasswd service-ticket session key.
///
/// # Errors
///
/// Returns [`Error::MissingKpasswdApRep`] when a non-error reply carries no
/// AP-REP, an AP-REP validation or decryption error, a time conversion error
/// (including [`Error::TimeOverflow`]) when the reply timestamp is out of
/// range, and [`Error::KpasswdApRepTimestampMismatch`] when the reply does not
/// echo the request authenticator timestamp.
#[inline]
pub fn verify_kpasswd_ap_rep(
    reply: &kadmin::Reply,
    request: &BuiltKpasswdRequest,
) -> Result<Option<VerifiedKpasswdApRep>, Error> {
    if reply.is_krb_error() {
        return Ok(None);
    }

    let ap_rep = reply.ap_rep.as_ref().ok_or(Error::MissingKpasswdApRep)?;
    validate_ap_rep(ap_rep).map_err(ap_rep_error)?;
    let enc_part =
        decrypt_ap_rep_enc_part(ap_rep, &request.ap_req.session_key).map_err(ap_rep_error)?;
    let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
    let cusec = integer_to_u32("ap-rep.cusec", &enc_part.cusec)?;
    let authenticator_time = ctime
        .checked_add(Duration::from_micros(cusec.into()))
        .ok_or(Error::TimeOverflow)?;

    if ctime != request.ap_req.authenticator_ctime || cusec != request.ap_req.authenticator_cusec {
        return Err(Error::KpasswdApRepTimestampMismatch {
            expected: request.ap_req.authenticator_time,
            actual: authenticator_time,
        });
    }

    Ok(Some(VerifiedKpasswdApRep {
        ctime,
        cusec,
        authenticator_time,
        subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
        sequence_number: enc_part.seq_number,
    }))
}
