//! Request-conforming synthetic KDC reply metadata.

use std::time::SystemTime;

use chrono::{DateTime, Duration, Utc};

use super::{KDC_OPTION_RENEW, KDC_OPTION_RENEWABLE, TestError};

/// Keep fixture snapshots where valid, but never grant unrequested capabilities or times.
///
/// # Errors
/// Returns a fixture error for unrepresentable timestamps or flags.
pub(super) fn conform(
    request: &rasn_kerberos::KdcReqBody,
    reply: &mut rasn_kerberos::EncKdcRepPart,
    now: SystemTime,
) -> Result<(), TestError> {
    let options = u32::from_be_bytes(request.kdc_options.0.as_raw_slice().try_into()?);
    let original = u32::from_be_bytes(reply.flags.0.as_raw_slice().try_into()?);
    let capabilities = 0x7f80_0000;
    let flags = if options & KDC_OPTION_RENEW == 0 {
        (original & !capabilities) | (original & options & capabilities)
    } else {
        original
    };
    reply.flags = rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(
        &flags.to_be_bytes(),
    ));
    let clock: DateTime<Utc> = now.into();
    let start = reply
        .start_time
        .as_ref()
        .unwrap_or(&reply.auth_time)
        .0
        .timestamp();
    let offset = clock.timestamp().saturating_sub(start);
    if offset.unsigned_abs() > 300 {
        let shift = Duration::seconds(offset);
        reply.auth_time.0 = reply
            .auth_time
            .0
            .checked_add_signed(shift)
            .ok_or("auth overflow")?;
        if let Some(time) = &mut reply.start_time {
            time.0 = time.0.checked_add_signed(shift).ok_or("start overflow")?;
        }
        reply.end_time.0 = reply
            .end_time
            .0
            .checked_add_signed(shift)
            .ok_or("end overflow")?;
        if let Some(time) = &mut reply.renew_till {
            time.0 = time.0.checked_add_signed(shift).ok_or("renew overflow")?;
        }
    }
    if reply.end_time > request.till {
        reply.end_time = request.till.clone();
    }
    if flags & KDC_OPTION_RENEWABLE == 0 {
        reply.renew_till = None;
    } else if let Some(bound) = &request.rtime {
        if reply.renew_till.as_ref().is_some_and(|renew| renew > bound) {
            reply.renew_till = Some(bound.clone());
        }
    } else if options & 0x0000_0010 != 0 {
        reply.renew_till = Some(request.till.clone());
    } else {
        // Renewal without rtime retains the original renewable horizon.
    }
    Ok(())
}
