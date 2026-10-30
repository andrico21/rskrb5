//! Cached-session renewal eligibility.

use std::time::SystemTime;

use super::{AsRepSession, TICKET_FLAG_INVALID};

/// Whether a session can still be renewed at `now`.
pub(super) fn session_renewable_at(session: &AsRepSession, now: SystemTime) -> bool {
    u32::from_be_bytes(session.ticket_flags) & TICKET_FLAG_INVALID == 0
        && session
            .renew_till
            .is_some_and(|renew_till| now < renew_till)
}
