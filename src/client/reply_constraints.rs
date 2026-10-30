//! Authenticated request/reply constraints from RFC 4120 sections 2 and 3.

use core::time::Duration;
use std::time::SystemTime;

use super::{
    Error, KDC_OPTION_RENEW, KDC_OPTION_RENEWABLE, TICKET_FLAG_INVALID,
    system_time_from_kerberos_time, ticket_flags_to_bytes,
};

/// Capabilities granted only on request; informational KDC flags are not included.
const REQUESTED_CAPABILITIES: u32 = 0x5400_0000;
/// Postdated ticket and request bit.
const POSTDATED: u32 = 0x0200_0000;
/// Permit renewable tickets in lieu of the requested full lifetime.
const RENEWABLE_OK: u32 = 0x0000_0010;
/// Ticket validation preserves inherited capabilities like renewal does.
const VALIDATE: u32 = 0x0000_0001;

/// Validate reply lifetimes and request-controlled capabilities, allowing shorter grants.
///
/// # Errors
/// Returns [`Error::ReplyTimeConstraint`] or [`Error::ReplyFlagConstraint`] on mismatch.
pub(super) fn validate(
    request: &rasn_kerberos::KdcReqBody,
    reply: &rasn_kerberos::EncKdcRepPart,
    clock: (SystemTime, Duration),
) -> Result<(), Error> {
    let options = u32::from_be_bytes(ticket_flags_to_bytes(&rasn_kerberos::TicketFlags(
        request.kdc_options.0.clone(),
    )));
    let flags = u32::from_be_bytes(ticket_flags_to_bytes(&reply.flags));
    let start = reply.start_time.as_ref().unwrap_or(&reply.auth_time);
    (reply.auth_time <= *start && *start <= reply.end_time).ok_or(Error::ReplyTimeConstraint)?;
    (request.till.0.timestamp() == 0 || reply.end_time <= request.till)
        .ok_or(Error::ReplyTimeConstraint)?;
    if let Some(from) = &request.from
        && options & POSTDATED != 0
    {
        (start == from).ok_or(Error::ReplyTimeConstraint)?;
    }
    if options & (POSTDATED | VALIDATE) == 0 {
        let actual = system_time_from_kerberos_time(start)?;
        let difference = actual
            .duration_since(clock.0)
            .unwrap_or_else(|error| error.duration());
        (difference <= clock.1).ok_or(Error::ReplyTimeConstraint)?;
    }
    if let Some(renew) = &reply.renew_till {
        (*renew >= reply.end_time).ok_or(Error::ReplyTimeConstraint)?;
        if options & KDC_OPTION_RENEWABLE != 0
            && let Some(bound) = &request.rtime
        {
            (bound.0.timestamp() == 0 || renew <= bound).ok_or(Error::ReplyTimeConstraint)?;
        }
        if options & KDC_OPTION_RENEWABLE == 0 && options & RENEWABLE_OK != 0 {
            (request.till.0.timestamp() == 0 || renew <= &request.till)
                .ok_or(Error::ReplyTimeConstraint)?;
        }
    }
    (flags & KDC_OPTION_RENEWABLE == 0 || reply.renew_till.is_some())
        .ok_or(Error::ReplyTimeConstraint)?;
    if options & (KDC_OPTION_RENEW | VALIDATE) == 0 {
        (flags & REQUESTED_CAPABILITIES & !options == 0).ok_or(Error::ReplyFlagConstraint)?;
        (flags & (POSTDATED | TICKET_FLAG_INVALID) == 0 || options & POSTDATED != 0)
            .ok_or(Error::ReplyFlagConstraint)?;
        (flags & KDC_OPTION_RENEWABLE == 0 || options & (KDC_OPTION_RENEWABLE | RENEWABLE_OK) != 0)
            .ok_or(Error::ReplyFlagConstraint)?;
    }
    Ok(())
}
