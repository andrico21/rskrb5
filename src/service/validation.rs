//! AP-REQ validation before replay admission.

use core::time::Duration;

use sha2::{Digest as _, Sha256};

use super::{
    EncryptionKey, Error, Principal, ReplayKey, ValidatedApReq, Validator, abs_duration,
    ap_req_error, encryption_key_from_rasn, microseconds_to_u32, principal_from_parts,
    system_time_from_kerberos_time, ticket_error, ticket_start_time, validate_authorization_data,
    verified_ticket_pac,
};
use crate::{ap_req, ticket};

impl Validator<'_> {
    /// Apply a protocol-specific authenticator check before committing replay state.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::validate_ap_req`] or the supplied check.
    pub(crate) fn validate_ap_req_with_check<F, E>(
        &mut self,
        bytes: &[u8],
        check: F,
    ) -> Result<ValidatedApReq, E>
    where
        F: FnOnce(&rasn_kerberos::Authenticator, &EncryptionKey) -> Result<(), E>,
        E: From<Error>,
    {
        let ap_req = ap_req::decode(bytes).map_err(ap_req_error)?;

        let ticket_service = principal_from_parts(&ap_req.ticket.realm, &ap_req.ticket.sname)?;
        let ticket_etype = ap_req.ticket.enc_part.etype;
        let ticket_kvno = ap_req.ticket.enc_part.kvno.unwrap_or(0);
        let keytab_components = self
            .keytab_principal
            .clone()
            .unwrap_or_else(|| ticket_service.components.clone());
        let keytab_refs = keytab_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let service_key = self
            .keytab
            .find_key(
                &keytab_refs,
                &ticket_service.realm,
                ticket_kvno,
                ticket_etype,
            )
            .map_err(Error::from)?;

        let enc_ticket =
            ticket::decrypt_ticket_enc_part(&ap_req.ticket, service_key.0).map_err(ticket_error)?;
        self.validate_ticket_times(&ticket_service, &enc_ticket)?;
        self.validate_client_address(&ticket_service, &enc_ticket)?;
        self.validate_transit(&ticket_service, &enc_ticket)?;
        let pac = verified_ticket_pac(enc_ticket.authorization_data.as_ref(), service_key.0)?;

        let session_key = encryption_key_from_rasn(&enc_ticket.key);
        let authenticator_usage = ap_req::authenticator_usage_for_ticket(&ap_req.ticket);
        let authenticator =
            ap_req::decrypt_ap_req_authenticator(&ap_req, &session_key, authenticator_usage)
                .map_err(ap_req_error)?;

        validate_authorization_data(authenticator.authorization_data.as_ref(), false)?;

        let ticket_client = principal_from_parts(&enc_ticket.crealm, &enc_ticket.cname)?;
        let authenticator_client =
            principal_from_parts(&authenticator.crealm, &authenticator.cname)?;
        // RFC 4120 section 3.2.3: compare the client name and realm of the
        // ticket with the same fields in the authenticator and reject
        // KRB_AP_ERR_BADMATCH on any mismatch.
        if authenticator_client.realm != ticket_client.realm
            || authenticator_client.components != ticket_client.components
        {
            return Err(Error::ClientPrincipalMismatch {
                ticket: format!("{}@{}", ticket_client.name(), ticket_client.realm),
                authenticator: format!(
                    "{}@{}",
                    authenticator_client.name(),
                    authenticator_client.realm
                ),
            }
            .into());
        }

        let cusec = microseconds_to_u32("authenticator.cusec", &authenticator.cusec)?;
        let authenticator_ctime = system_time_from_kerberos_time(&authenticator.ctime)?;
        let authenticator_timestamp = authenticator_ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;
        let now = self.now();
        if abs_duration(now, authenticator_timestamp) > self.max_clock_skew {
            return Err(Error::ClockSkew {
                max_clock_skew: self.max_clock_skew,
            }
            .into());
        }

        check(&authenticator, &session_key)?;

        // RFC 4120 section 3.2.3 keys the replay cache on the server name, the
        // client name, the time and the microseconds. Section 6.2 makes the
        // advisory name-type "not significant when checking for equivalence",
        // and the ticket's outer sname is cleartext a peer can rewrite, so the
        // identity is built without it; the service side is the key identity
        // that actually accepted the ticket (the configured override when one
        // is set, otherwise the ticket's own components). Keep that RFC key,
        // and also index the authenticator ciphertext to reject re-presentation
        // under any rewritten cleartext ticket field, including an sname alias
        // whose keytab entry shares the key. Hash only the cipher octets:
        // unauthenticated etype/kvno metadata must not create a fresh digest.
        let authenticator_digest: [u8; 32] =
            Sha256::digest(ap_req.authenticator.cipher.as_ref()).into();
        let replay_key = ReplayKey {
            service: Principal {
                realm: ticket_service.realm.clone(),
                name_type: 0,
                components: keytab_components.clone(),
            },
            client: Principal {
                realm: authenticator_client.realm.clone(),
                name_type: 0,
                components: authenticator_client.components,
            },
            ctime_seconds: authenticator.ctime.0.timestamp(),
            cusec,
        };
        let validated = ValidatedApReq {
            client: ticket_client,
            service: ticket_service,
            session_key,
            subkey: authenticator.subkey.as_ref().map(encryption_key_from_rasn),
            sequence_number: authenticator.seq_number,
            ticket_start: ticket_start_time(&enc_ticket)?,
            ticket_end: system_time_from_kerberos_time(&enc_ticket.end_time)?,
            authenticator_ctime,
            authenticator_cusec: cusec,
            authenticator_time: authenticator_timestamp,
            pac,
        };
        self.record_replay(replay_key, authenticator_digest, now)?;
        Ok(validated)
    }
}
