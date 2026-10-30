//! Ticket address restrictions through the public service validator.

use rskrb5_ng::service::HostAddress;

use super::{
    Error, KDC_REP_TICKET_USAGE_FOR_TEST, PAC_TICKET_CONFOUNDER, TestError, Validator,
    decrypt_ticket_enc_part, der, encrypt_message, http_keytab, timestamp, valid_ap_req_struct,
};

/// Reissue the fixture with an explicit address list, preserving its authenticator.
fn request_with_addresses(addresses: &[(i32, [u8; 4])]) -> Result<Vec<u8>, TestError> {
    let keytab = http_keytab()?;
    let (key, _) = keytab.find_key(&["HTTP", "host.test.gokrb5"], "TEST.GOKRB5", 1, 18)?;
    let mut request = valid_ap_req_struct()?;
    let mut ticket = decrypt_ticket_enc_part(&request.ticket, key)?;
    ticket.caddr = Some(
        addresses
            .iter()
            .map(|(addr_type, bytes)| rasn_kerberos::HostAddress {
                addr_type: *addr_type,
                address: bytes.to_vec().into(),
            })
            .collect(),
    );
    request.ticket.enc_part.cipher = encrypt_message(
        key,
        &der::encode(&ticket)?,
        KDC_REP_TICKET_USAGE_FOR_TEST,
        PAC_TICKET_CONFOUNDER,
    )?
    .into();
    Ok(der::encode(&request)?)
}

/// Any matching list entry permits the observed peer, not just the first one.
#[test]
fn client_address_accepts_matching_entry() -> Result<(), TestError> {
    // Given a ticket whose second address matches the observed peer.
    let keytab = http_keytab()?;
    let request = request_with_addresses(&[(2_i32, [192, 0, 2, 1]), (2_i32, [192, 0, 2, 2])])?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_client_address(HostAddress::ipv4([192, 0, 2, 2]));
    // When the real acceptor validates the encrypted ticket.
    let accepted = validator.validate_ap_req(&request)?;
    // Then the ticket identity is returned and admitted to replay tracking.
    assert_eq!(accepted.client.name(), "testuser1");
    assert_eq!(validator.replay_cache_mut().len(), 1);
    Ok(())
}

/// Matching address types alone do not authorize a different peer address.
#[test]
fn client_address_rejects_different_bytes() -> Result<(), TestError> {
    // Given an IPv4 ticket for another peer.
    let keytab = http_keytab()?;
    let request = request_with_addresses(&[(2_i32, [192, 0, 2, 1])])?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_client_address(HostAddress::ipv4([192, 0, 2, 2]));
    // When the observed peer presents it.
    let result = validator.validate_ap_req(&request);
    // Then address rejection occurs before replay admission.
    assert!(matches!(
        result,
        Err(Error::BadClientAddress {
            service: _,
            realm: _
        })
    ));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}

/// Identical bytes under a different address type do not match an IPv4 peer.
#[test]
fn client_address_rejects_different_type() -> Result<(), TestError> {
    // Given identical bytes tagged with a different address namespace.
    let keytab = http_keytab()?;
    let request = request_with_addresses(&[(99_i32, [192, 0, 2, 2])])?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_client_address(HostAddress::ipv4([192, 0, 2, 2]));
    // When the peer is compared with the ticket restriction.
    let result = validator.validate_ap_req(&request);
    // Then equality of bytes cannot bypass type matching.
    assert!(matches!(
        result,
        Err(Error::BadClientAddress {
            service: _,
            realm: _
        })
    ));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}

/// Address-restricted tickets cannot be accepted without an observed peer.
#[test]
fn client_address_rejects_missing_observed_peer() -> Result<(), TestError> {
    // Given a nonempty ticket address list and no observed peer address.
    let keytab = http_keytab()?;
    let request = request_with_addresses(&[(2_i32, [192, 0, 2, 2])])?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When the restricted ticket is presented.
    let result = validator.validate_ap_req(&request);
    // Then the service fails closed before replay admission.
    assert!(matches!(
        result,
        Err(Error::BadClientAddress {
            service: _,
            realm: _
        })
    ));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}
