//! KRB-CRED decoding and encrypted-part helpers.

use alloc::str;
use core::str::Utf8Error;

use rasn::{der, types::Integer};

use crate::{
    ccache,
    crypto::{self, KerberosEtype},
    keytab::EncryptionKey,
    ticket::{Error as TicketError, decode_ticket, encode_ticket},
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// KRB-CRED message type.
pub const KRB_CRED_MSG_TYPE: i32 = 22;

/// Key usage for KRB-CRED encrypted parts.
pub const KRB_CRED_ENCPART_USAGE: u32 = 14;

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
        clippy::module_name_repetitions,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Decode and validate a DER-encoded KRB-CRED message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-CRED, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode_krb_cred(bytes: &[u8]) -> Result<rasn_kerberos::KrbCred, Error> {
    let krb_cred = decode::<rasn_kerberos::KrbCred>("KRB-CRED", bytes)?;
    validate_integer("pvno", &krb_cred.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_cred.msg_type, KRB_CRED_MSG_TYPE)?;
    Ok(krb_cred)
}

/// Decode a DER-encoded `EncKrbCredPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncKrbCredPart`.
#[inline]
pub fn decode_enc_krb_cred_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    decode::<rasn_kerberos::EncKrbCredPart>("EncKrbCredPart", bytes)
}

/// Decrypt and decode a KRB-CRED encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from the
/// encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncKrbCredPart`.
#[inline]
pub fn decrypt_krb_cred_enc_part(
    krb_cred: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbCredPart, Error> {
    if key.etype != krb_cred.enc_part.etype {
        return Err(Error::KeyEtypeMismatch {
            key_etype: key.etype,
            encrypted_data_etype: krb_cred.enc_part.etype,
        });
    }
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let plaintext = etype.decrypt_message(
        &key.value,
        krb_cred.enc_part.cipher.as_ref(),
        KRB_CRED_ENCPART_USAGE,
    )?;
    decode_enc_krb_cred_part(&plaintext)
}

/// Decrypt a KRB-CRED encrypted part and convert its tickets to ccache credentials.
///
/// # Errors
///
/// Returns the errors of [`decrypt_krb_cred_enc_part`] and
/// [`decrypted_krb_cred_to_ccache_credentials`].
#[inline]
pub fn decrypt_krb_cred_to_ccache_credentials(
    krb_cred: &rasn_kerberos::KrbCred,
    key: &EncryptionKey,
) -> Result<Vec<ccache::Credential>, Error> {
    let enc_part = decrypt_krb_cred_enc_part(krb_cred, key)?;
    decrypted_krb_cred_to_ccache_credentials(krb_cred, &enc_part)
}

/// Decode, decrypt, and convert a DER-encoded KRB-CRED to ccache credentials.
///
/// # Errors
///
/// Returns the errors of [`decode_krb_cred`] and
/// [`decrypt_krb_cred_to_ccache_credentials`].
#[inline]
pub fn decode_decrypt_krb_cred_to_ccache_credentials(
    bytes: &[u8],
    key: &EncryptionKey,
) -> Result<Vec<ccache::Credential>, Error> {
    let krb_cred = decode_krb_cred(bytes)?;
    decrypt_krb_cred_to_ccache_credentials(&krb_cred, key)
}

/// Convert ccache credentials into KRB-CRED tickets and a decrypted encrypted part.
///
/// # Errors
///
/// Returns [`Error::UnsupportedCredentialAuthData`] or
/// [`Error::UnsupportedSecondTicket`] for a credential carrying authorization
/// data or a second ticket, [`Error::Decode`] or [`Error::InvalidMessage`] when
/// a credential's ticket is not a valid DER Ticket,
/// [`Error::InvalidKerberosString`] for a realm or name component that is not a
/// Kerberos string, and [`Error::TimeOutOfRange`] for a time that is not a valid
/// Kerberos time.
#[inline]
pub fn ccache_credentials_to_krb_cred_parts(
    credentials: &[ccache::Credential],
) -> Result<(Vec<rasn_kerberos::Ticket>, rasn_kerberos::EncKrbCredPart), Error> {
    let mut tickets = Vec::with_capacity(credentials.len());
    let mut ticket_info = Vec::with_capacity(credentials.len());

    for credential in credentials {
        if !credential.auth_data.is_empty() {
            return Err(Error::UnsupportedCredentialAuthData);
        }
        if !credential.second_ticket.is_empty() {
            return Err(Error::UnsupportedSecondTicket);
        }

        let ticket = decode_ticket(&credential.ticket).map_err(ticket_error)?;
        tickets.push(ticket);
        ticket_info.push(ccache_credential_to_krb_cred_info(credential)?);
    }

    Ok((
        tickets,
        rasn_kerberos::EncKrbCredPart {
            ticket_info,
            nonce: None,
            timestamp: None,
            usec: None,
            sender_address: None,
            recipient_address: None,
        },
    ))
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
        clippy::module_name_repetitions,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Encrypt ccache credentials into a KRB-CRED using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Random`] when the confounder cannot be generated, and
/// the errors of [`encrypt_ccache_credentials_to_krb_cred_with_confounder`].
#[inline]
pub fn encrypt_ccache_credentials_to_krb_cred(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbCred, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let mut confounder = vec![0; etype.confounder_len()];
    getrandom::fill(&mut confounder)?;
    encrypt_ccache_credentials_to_krb_cred_with_confounder(credentials, key, &confounder)
}

/// Encrypt ccache credentials into a KRB-CRED using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of [`ccache_credentials_to_krb_cred_parts`],
/// [`Error::Encode`] when the encrypted part cannot be encoded,
/// [`Error::UnsupportedEtype`] for a key whose enctype is not implemented, and
/// [`Error::Crypto`] when encryption fails.
#[inline]
pub fn encrypt_ccache_credentials_to_krb_cred_with_confounder(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbCred, Error> {
    let (tickets, enc_part) = ccache_credentials_to_krb_cred_parts(credentials)?;
    let plaintext = encode("EncKrbCredPart", &enc_part)?;
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let cipher = etype.encrypt_message_with_confounder(
        &key.value,
        &plaintext,
        KRB_CRED_ENCPART_USAGE,
        confounder,
    )?;
    Ok(rasn_kerberos::KrbCred {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_CRED_MSG_TYPE),
        tickets,
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype,
            kvno: None,
            cipher: cipher.into(),
        },
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
        clippy::module_name_repetitions,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Encode ccache credentials as a DER KRB-CRED using a random confounder.
///
/// # Errors
///
/// Returns the errors of [`encrypt_ccache_credentials_to_krb_cred`] and
/// [`Error::Encode`] when the KRB-CRED cannot be encoded.
#[inline]
pub fn encode_encrypt_ccache_credentials_to_krb_cred(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
) -> Result<Vec<u8>, Error> {
    let krb_cred = encrypt_ccache_credentials_to_krb_cred(credentials, key)?;
    encode("KRB-CRED", &krb_cred)
}

/// Encode ccache credentials as a DER KRB-CRED using an explicit confounder.
///
/// # Errors
///
/// Returns the errors of
/// [`encrypt_ccache_credentials_to_krb_cred_with_confounder`] and
/// [`Error::Encode`] when the KRB-CRED cannot be encoded.
#[inline]
pub fn encode_encrypt_ccache_credentials_to_krb_cred_with_confounder(
    credentials: &[ccache::Credential],
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<Vec<u8>, Error> {
    let krb_cred =
        encrypt_ccache_credentials_to_krb_cred_with_confounder(credentials, key, confounder)?;
    encode("KRB-CRED", &krb_cred)
}

/// Convert decrypted KRB-CRED contents into ccache credentials.
///
/// # Errors
///
/// Returns [`Error::TicketInfoCountMismatch`] when the ticket and ticket-info
/// counts differ, [`Error::MissingKrbCredInfoField`] when a ticket-info entry
/// lacks the client principal or has only half of the server principal,
/// [`Error::InvalidString`] for a name that is not UTF-8,
/// [`Error::TimeOutOfRange`] for a time that does not fit a ccache timestamp,
/// and [`Error::Encode`] when a ticket cannot be re-encoded.
#[inline]
pub fn decrypted_krb_cred_to_ccache_credentials(
    krb_cred: &rasn_kerberos::KrbCred,
    enc_part: &rasn_kerberos::EncKrbCredPart,
) -> Result<Vec<ccache::Credential>, Error> {
    if krb_cred.tickets.len() != enc_part.ticket_info.len() {
        return Err(Error::TicketInfoCountMismatch {
            ticket_count: krb_cred.tickets.len(),
            info_count: enc_part.ticket_info.len(),
        });
    }

    krb_cred
        .tickets
        .iter()
        .zip(enc_part.ticket_info.iter())
        .map(|(ticket, info)| krb_cred_info_to_ccache_credential(ticket, info))
        .collect()
}

/// Build the `KrbCredInfo` entry that describes one ccache credential.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a realm or name component that
/// is not a Kerberos string, and [`Error::TimeOutOfRange`] for a time that is
/// not a valid Kerberos time.
fn ccache_credential_to_krb_cred_info(
    credential: &ccache::Credential,
) -> Result<rasn_kerberos::KrbCredInfo, Error> {
    Ok(rasn_kerberos::KrbCredInfo {
        key: rasn_kerberos::EncryptionKey {
            r#type: credential.key.etype,
            value: credential.key.value.clone().into(),
        },
        prealm: Some(kerberos_string(&credential.client.realm)?),
        pname: Some(principal_name_from_ccache(&credential.client)?),
        flags: Some(rasn_kerberos::TicketFlags(
            rasn_kerberos::KerberosFlags::from_slice(&credential.ticket_flags),
        )),
        auth_time: Some(kerberos_time_from_u32(credential.times.auth_time)?),
        start_time: Some(kerberos_time_from_u32(credential.times.start_time)?),
        end_time: Some(kerberos_time_from_u32(credential.times.end_time)?),
        renew_till: Some(kerberos_time_from_u32(credential.times.renew_till)?),
        srealm: Some(kerberos_string(&credential.server.realm)?),
        sname: Some(principal_name_from_ccache(&credential.server)?),
        caddr: (!credential.addresses.is_empty()).then(|| {
            credential
                .addresses
                .iter()
                .map(host_address_from_ccache)
                .collect()
        }),
    })
}

/// Build a ccache credential from a KRB-CRED ticket and its `KrbCredInfo`.
///
/// A missing server principal falls back to the ticket's realm and name, and a
/// missing start time falls back to the authentication time.
///
/// # Errors
///
/// Returns [`Error::MissingKrbCredInfoField`] when the client principal is
/// missing or the server principal is half present, [`Error::InvalidString`]
/// for a name that is not UTF-8, [`Error::TimeOutOfRange`] for a time that does
/// not fit a ccache timestamp, and [`Error::Encode`] when the ticket cannot be
/// re-encoded.
fn krb_cred_info_to_ccache_credential(
    ticket: &rasn_kerberos::Ticket,
    info: &rasn_kerberos::KrbCredInfo,
) -> Result<ccache::Credential, Error> {
    let client = required_principal(
        "KrbCredInfo.pname",
        info.prealm.as_ref(),
        info.pname.as_ref(),
    )?;
    let server = match optional_principal(info.srealm.as_ref(), info.sname.as_ref())? {
        Some(server) => server,
        None => principal_from_parts(&ticket.realm, &ticket.sname)?,
    };
    Ok(ccache::Credential {
        client,
        server,
        key: ccache::EncryptionKey {
            etype: info.key.r#type,
            value: info.key.value.as_ref().to_vec(),
        },
        times: ccache::CredentialTimes {
            auth_time: optional_kerberos_time_to_u32(info.auth_time.as_ref())?,
            start_time: optional_kerberos_time_to_u32(
                info.start_time.as_ref().or(info.auth_time.as_ref()),
            )?,
            end_time: optional_kerberos_time_to_u32(info.end_time.as_ref())?,
            renew_till: optional_kerberos_time_to_u32(info.renew_till.as_ref())?,
        },
        is_skey: false,
        ticket_flags: info
            .flags
            .as_ref()
            .map(ticket_flags_to_bytes)
            .unwrap_or_default(),
        addresses: info
            .caddr
            .as_ref()
            .map(|addresses| {
                addresses
                    .iter()
                    .map(|address| ccache::HostAddress {
                        addr_type: address.addr_type,
                        address: address.address.as_ref().to_vec(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        auth_data: Vec::new(),
        ticket: encode_ticket(ticket).map_err(ticket_error)?,
        second_ticket: Vec::new(),
    })
}

/// Convert a ccache principal to a Kerberos principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a name component that is not a
/// Kerberos string.
fn principal_name_from_ccache(
    principal: &ccache::Principal,
) -> Result<rasn_kerberos::PrincipalName, Error> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: principal.name_type,
        string: principal
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a ccache host address to a Kerberos host address.
fn host_address_from_ccache(address: &ccache::HostAddress) -> rasn_kerberos::HostAddress {
    rasn_kerberos::HostAddress {
        addr_type: address.addr_type,
        address: address.address.clone().into(),
    }
}

/// Build the principal named by a required realm and name pair.
///
/// # Errors
///
/// Returns [`Error::MissingKrbCredInfoField`] naming `field` when either half is
/// missing, and [`Error::InvalidString`] for a name that is not UTF-8.
fn required_principal(
    field: &'static str,
    realm: Option<&rasn_kerberos::Realm>,
    name: Option<&rasn_kerberos::PrincipalName>,
) -> Result<ccache::Principal, Error> {
    match (realm, name) {
        (Some(realm_value), Some(name_value)) => principal_from_parts(realm_value, name_value),
        _ => Err(Error::MissingKrbCredInfoField(field)),
    }
}

/// Build the principal named by an optional realm and name pair.
///
/// # Errors
///
/// Returns [`Error::MissingKrbCredInfoField`] when only one half is present,
/// and [`Error::InvalidString`] for a name that is not UTF-8.
fn optional_principal(
    realm: Option<&rasn_kerberos::Realm>,
    name: Option<&rasn_kerberos::PrincipalName>,
) -> Result<Option<ccache::Principal>, Error> {
    match (realm, name) {
        (Some(realm_value), Some(name_value)) => {
            principal_from_parts(realm_value, name_value).map(Some)
        }
        (None, None) => Ok(None),
        _ => Err(Error::MissingKrbCredInfoField("KrbCredInfo.srealm/sname")),
    }
}

/// Build a ccache principal from a Kerberos realm and principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a name component is not
/// UTF-8.
fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<ccache::Principal, Error> {
    Ok(ccache::Principal::new(
        kerberos_string_to_string(realm)?,
        name.r#type,
        name.string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

/// Convert a string to a Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] when the value is not a valid
/// Kerberos string.
fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|source| Error::InvalidKerberosString(source.to_string()))
}

/// Convert a Kerberos string to an owned UTF-8 string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the bytes are not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

/// Convert a ccache timestamp to a UTC Kerberos time.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] when the timestamp is not a valid time.
fn kerberos_time_from_u32(seconds: u32) -> Result<rasn_kerberos::KerberosTime, Error> {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds.into(), 0)
        .ok_or(Error::TimeOutOfRange)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOutOfRange)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// Convert an optional Kerberos time to a ccache timestamp; absent is zero.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] when the time does not fit a ccache
/// timestamp.
fn optional_kerberos_time_to_u32(time: Option<&rasn_kerberos::KerberosTime>) -> Result<u32, Error> {
    time.map(kerberos_time_to_u32)
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Convert a Kerberos time to a ccache timestamp.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] when the time is before the Unix epoch or
/// after 2106.
fn kerberos_time_to_u32(time: &rasn_kerberos::KerberosTime) -> Result<u32, Error> {
    u32::try_from(time.0.timestamp())
        .ok()
        .ok_or(Error::TimeOutOfRange)
}

/// Return the first four bytes of the ticket flags, zero-padded.
fn ticket_flags_to_bytes(flags: &rasn_kerberos::TicketFlags) -> [u8; 4] {
    let raw = flags.0.as_raw_slice();
    [
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ]
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Map a Ticket module error to the KRB-CRED error; a key mismatch becomes
/// [`Error::TicketKeyEtypeMismatch`].
fn ticket_error(error: TicketError) -> Error {
    match error {
        TicketError::Decode { target, message } => Error::Decode { target, message },
        TicketError::Encode { target, message } => Error::Encode { target, message },
        TicketError::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        TicketError::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        TicketError::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        TicketError::Random(source) => Error::Random(source),
        TicketError::Crypto(source) => Error::Crypto(source),
    }
}

/// Check that a decoded protocol integer such as `pvno` equals `expected`.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] naming `field` when the value differs.
fn validate_integer(field: &'static str, actual: &Integer, expected: i32) -> Result<(), Error> {
    if actual != &Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
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
        clippy::error_impl_error,
        clippy::exhaustive_enums,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// KRB-CRED helper error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },

    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },

    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),

    /// A string could not be encoded as a Kerberos `GeneralString`.
    #[error("invalid Kerberos string: {0}")]
    InvalidKerberosString(String),

    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },

    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),

    /// A key did not match the encrypted KRB-CRED data etype.
    #[error(
        "key etype {key_etype} does not match KRB-CRED encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Reply key encryption type.
        key_etype: i32,
        /// KRB-CRED encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// A key did not match the encrypted ticket data etype.
    #[error(
        "key etype {key_etype} does not match Ticket encrypted data etype {encrypted_data_etype}"
    )]
    TicketKeyEtypeMismatch {
        /// Key encryption type.
        key_etype: i32,
        /// Ticket encrypted data encryption type.
        encrypted_data_etype: i32,
    },

    /// The KRB-CRED ticket count and ticket-info count differed.
    #[error("KRB-CRED has {ticket_count} tickets but {info_count} ticket-info entries")]
    TicketInfoCountMismatch {
        /// Ticket count.
        ticket_count: usize,
        /// Ticket-info count.
        info_count: usize,
    },

    /// A field required for ccache conversion was absent.
    #[error("KRB-CRED missing required field {0}")]
    MissingKrbCredInfoField(&'static str),

    /// A Kerberos time could not fit in a ccache timestamp.
    #[error("Kerberos time cannot be represented as a ccache timestamp")]
    TimeOutOfRange,

    /// Ccache authorization data cannot be represented in KRB-CRED info.
    #[error("ccache credential authorization data cannot be represented in KRB-CRED")]
    UnsupportedCredentialAuthData,

    /// Ccache second-ticket data cannot be represented in KRB-CRED info.
    #[error("ccache credential second ticket cannot be represented in KRB-CRED")]
    UnsupportedSecondTicket,

    /// Random byte generation failed.
    #[error("random byte generation failed: {0}")]
    Random(#[from] getrandom::Error),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),
}
