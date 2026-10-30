//! Cached-session renewal eligibility.

use std::time::SystemTime;

use super::{AsRepSession, KDC_OPTION_RENEWABLE, session_valid_at};

/// Renewal requires a valid, flagged ticket before expiry; no expiry grace is supported.
pub(super) fn session_renewable_at(session: &AsRepSession, now: SystemTime) -> bool {
    session_valid_at(session, now)
        && u32::from_be_bytes(session.ticket_flags) & KDC_OPTION_RENEWABLE != 0
        && session.auth_time <= session.start_time
        && session
            .renew_till
            .is_some_and(|renew_till| now < renew_till && session.end_time <= renew_till)
}
