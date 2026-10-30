//! Identity-bound cache insertion.

use std::time::SystemTime;

use super::{
    AsRepSession, Error, TgsRepSession, Tokio, preferred_session_at, principal_matches,
    service_cache_key, tgt_realm,
};

/// Insert or replace a service ticket in the cache.
///
/// # Errors
/// Returns [`Error::CacheClientMismatch`] for another client identity.
pub(super) fn service_ticket(client: &mut Tokio, ticket: TgsRepSession) -> Result<(), Error> {
    principal_matches(&ticket.client, &client.client).ok_or(Error::CacheClientMismatch)?;
    let key = service_cache_key(&ticket.service);
    let selected = preferred_session_at(
        client.service_tickets.remove(&key),
        ticket,
        SystemTime::now(),
    );
    drop(client.service_tickets.insert(key, selected));
    Ok(())
}

/// Cache a TGT session at `now`, keeping the better cached session.
///
/// # Errors
/// Returns [`Error::InvalidTgtSession`] for a non-TGT service or
/// [`Error::CacheClientMismatch`] for another client identity.
pub(super) fn tgt_session_at(
    client: &mut Tokio,
    tgt: AsRepSession,
    now: SystemTime,
) -> Result<(), Error> {
    principal_matches(&tgt.client, &client.client).ok_or(Error::CacheClientMismatch)?;
    let realm = tgt_realm(&tgt).ok_or_else(|| Error::InvalidTgtSession {
        service: tgt.service.name(),
    })?;
    let selected = preferred_session_at(client.tgt_sessions.remove(&realm), tgt, now);
    if realm == client.client.realm {
        let primary = preferred_session_at(client.tgt.take(), selected, now);
        client.tgt = Some(primary.clone());
        drop(client.tgt_sessions.insert(realm, primary));
    } else {
        drop(client.tgt_sessions.insert(realm, selected));
    }
    Ok(())
}
