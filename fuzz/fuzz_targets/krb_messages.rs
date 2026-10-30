//! Fuzz the Kerberos message decoders.
//!
//! The first input byte selects one decoder and the rest is its input:
//! AP-REQ, Authenticator, AP-REP, `EncAPRepPart`, KRB-CRED, `EncKrbCredPart`,
//! KRB-PRIV, `EncKrbPrivPart`, KRB-SAFE (with its checksum check), Ticket,
//! `EncTicketPart`, KRB-ERROR, `KDC-REQ-BODY`, AS-REQ, TGS-REQ, the PA-DATA
//! messages, the kpasswd `ChangePasswdData` and KRB-PRIV codecs, the
//! decrypt-then-decode paths under a fixed synthetic key, and a sealed mode
//! that encrypts the fuzzed plaintext into a message template under that key
//! so the decoders behind decryption see it. None may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ap_rep, ap_req,
    crypto::{CryptoPolicy, KerberosEtype},
    kadmin, kdc_rep, kdc_req,
    keytab::EncryptionKey,
    krb_cred, krb_error, krb_priv, krb_safe,
    messages::{KrbErrorInfo, PaForUser, PaPacOptions, PaReqEncPaRep},
    ticket,
};

/// The AES256 reply key of the gokrb5 test vectors.
const KEY: [u8; 32] = [
    0x9c, 0xad, 0x00, 0xbb, 0xc7, 0x2d, 0x70, 0x32, 0x58, 0xe9, 0x11, 0xdc, 0x18, 0xe6, 0xd5, 0x48,
    0x7c, 0xf7, 0x37, 0xbf, 0x67, 0xfd, 0x11, 0x1f, 0x0c, 0x24, 0x63, 0xad, 0x60, 0x33, 0xbf, 0x51,
];

/// AES256-CTS-HMAC-SHA1-96.
const AES256: i32 = 18;

/// The AP-REQ authenticator key usage.
const AP_REQ_AUTHENTICATOR_USAGE: u32 = 11;

/// A fixed confounder, so every run encrypts the same bytes.
const CONFOUNDER: [u8; 16] = [0x55; 16];

/// The AP-REQ template of the sealed mode (a gokrb5 test vector, as are the
/// other templates).
const AP_REQ: &[u8] = include_bytes!("../fixtures/valid_ap_req.der");
/// The AP-REP template.
const AP_REP: &[u8] = include_bytes!("../fixtures/ap_rep.der");
/// The Ticket template.
const TICKET: &[u8] = include_bytes!("../fixtures/ticket.der");
/// The KRB-PRIV template.
const KRB_PRIV: &[u8] = include_bytes!("../fixtures/krb_priv.der");
/// The KRB-CRED template.
const KRB_CRED: &[u8] = include_bytes!("../fixtures/krb_cred.der");
/// The AS-REP template.
const AS_REP: &[u8] = include_bytes!("../fixtures/as_rep.der");
/// The TGS-REP template.
const TGS_REP: &[u8] = include_bytes!("../fixtures/tgs_rep.der");

/// The fixed key of the decrypt paths.
fn key() -> EncryptionKey {
    EncryptionKey::new(AES256, KEY.to_vec())
}

/// Decode a message, then decrypt its encrypted part with the fixed key.
fn decrypt(selector: u8, input: &[u8]) {
    let key = key();
    drop(krb_cred::import::decode_decrypt(
        &CryptoPolicy::default(),
        input,
        &key,
    ));
    match selector & 0x07 {
        0 => {
            if let Ok(message) = ap_req::decode(input) {
                drop(ap_req::decrypt_ap_req_authenticator(
                    &message,
                    &key,
                    AP_REQ_AUTHENTICATOR_USAGE,
                ));
            }
        }
        1 => {
            if let Ok(message) = ap_rep::decode(input) {
                drop(ap_rep::decrypt_ap_rep_enc_part(&message, &key));
            }
        }
        2 => {
            if let Ok(message) = ticket::decode(input) {
                drop(ticket::decrypt_ticket_enc_part(&message, &key));
            }
        }
        3 => {
            if let Ok(message) = krb_priv::decode(input) {
                drop(krb_priv::decrypt_krb_priv_enc_part(&message, &key));
            }
        }
        4 => {
            if let Ok(message) = kadmin::decode_krb_priv(input) {
                drop(kadmin::decrypt_krb_priv_enc_part(&message, &key));
            }
        }
        5 => {
            if let Ok(message) = krb_cred::decode(input) {
                drop(krb_cred::decrypt_krb_cred_to_ccache_credentials(
                    &message, &key,
                ));
            }
        }
        6 => drop(krb_cred::decode_decrypt_krb_cred_to_ccache_credentials(
            input, &key,
        )),
        _ => {
            if let Ok(message) = krb_safe::decode(input) {
                drop(krb_safe::verify_krb_safe_checksum(&message, &key));
            }
        }
    }
}

/// Encrypt `plaintext` under the fixed key with `usage`.
fn seal(plaintext: &[u8], usage: u32) -> Option<Vec<u8>> {
    KerberosEtype::from_etype_id(AES256)?
        .encrypt_message_with_confounder(&KEY, plaintext, usage, &CONFOUNDER)
        .ok()
}

/// Encrypt `plaintext` as the encrypted part of the message template
/// `selector` picks, then decrypt and decode it again.
fn sealed(selector: u8, plaintext: &[u8]) -> Option<()> {
    let key = key();
    match selector & 0x07 {
        0 => {
            let mut message = ap_req::decode(AP_REQ).ok()?;
            message.authenticator.etype = AES256;
            message.authenticator.cipher =
                seal(plaintext, ap_req::AP_REQ_AUTHENTICATOR_USAGE)?.into();
            drop(ap_req::decrypt_ap_req_authenticator(
                &message,
                &key,
                ap_req::AP_REQ_AUTHENTICATOR_USAGE,
            ));
        }
        1 => {
            let mut message = ap_rep::decode(AP_REP).ok()?;
            message.enc_part.etype = AES256;
            message.enc_part.cipher = seal(plaintext, ap_rep::AP_REP_ENCPART_USAGE)?.into();
            drop(ap_rep::decrypt_ap_rep_enc_part(&message, &key));
        }
        2 => {
            let mut message = ticket::decode(TICKET).ok()?;
            message.enc_part.etype = AES256;
            message.enc_part.cipher = seal(plaintext, ticket::KDC_REP_TICKET_USAGE)?.into();
            drop(ticket::decrypt_ticket_enc_part(&message, &key));
        }
        3 => {
            let mut message = krb_priv::decode(KRB_PRIV).ok()?;
            message.enc_part.etype = AES256;
            message.enc_part.cipher = seal(plaintext, krb_priv::KRB_PRIV_ENCPART_USAGE)?.into();
            drop(krb_priv::decrypt_krb_priv_enc_part(&message, &key));
            drop(kadmin::decrypt_krb_priv_enc_part(&message, &key));
        }
        4 => {
            let mut message = krb_cred::decode(KRB_CRED).ok()?;
            message.enc_part.etype = AES256;
            message.enc_part.cipher = seal(plaintext, krb_cred::KRB_CRED_ENCPART_USAGE)?.into();
            drop(krb_cred::decrypt_krb_cred_to_ccache_credentials(
                &message, &key,
            ));
        }
        5 => {
            let mut message = kdc_rep::decode_as_rep(AS_REP).ok()?;
            message.0.enc_part.etype = AES256;
            message.0.enc_part.cipher = seal(plaintext, kdc_rep::AS_REP_ENCPART_USAGE)?.into();
            drop(kdc_rep::decrypt_as_rep_enc_part(&message, &key));
        }
        _ => {
            let mut message = kdc_rep::decode_tgs_rep(TGS_REP).ok()?;
            message.0.enc_part.etype = AES256;
            message.0.enc_part.cipher =
                seal(plaintext, kdc_rep::TGS_REP_ENCPART_SESSION_KEY_USAGE)?.into();
            drop(kdc_rep::decrypt_tgs_rep_enc_part(&message, &key));
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x1f {
        0 => drop(ap_req::decode(input)),
        1 => drop(ap_req::decode_authenticator(input)),
        2 => drop(ap_rep::decode(input)),
        3 => drop(ap_rep::decode_enc_ap_rep_part(input)),
        4 => drop(krb_cred::decode(input)),
        5 => drop(krb_cred::decode_enc_krb_cred_part(input)),
        6 => drop(krb_priv::decode(input)),
        7 => drop(krb_priv::decode_enc_krb_priv_part(input)),
        8 => drop(krb_safe::decode(input)),
        9 => drop(ticket::decode(input)),
        10 => drop(ticket::decode_enc_ticket_part(input)),
        11 => drop(krb_error::decode(input)),
        12 => drop(kdc_req::decode_kdc_req_body(input)),
        13 => drop(kdc_req::decode_as_req(input)),
        14 => drop(kdc_req::decode_tgs_req(input)),
        15 => drop(PaForUser::decode_der(input)),
        16 => drop(PaPacOptions::decode_der(input)),
        17 => drop(PaReqEncPaRep::decode_der(input)),
        18 => drop(KrbErrorInfo::decode_der(input)),
        19 => drop(kadmin::ChangePasswdData::decode_der(input)),
        20 => drop(kadmin::decode_krb_priv(input)),
        21 => drop(kadmin::decode_enc_krb_priv_part(input)),
        22 => {
            if let Some((inner, rest)) = input.split_first() {
                decrypt(*inner, rest);
            }
        }
        _ => {
            if let Some((inner, rest)) = input.split_first() {
                sealed(*inner, rest).unwrap_or_default();
            }
        }
    }
});
