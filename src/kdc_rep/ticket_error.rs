//! Mapping of ticket validation errors into reply errors.

use super::{Error, TicketError};

/// Map a Ticket module error to the KDC reply error; a key mismatch becomes
/// [`Error::TicketKeyEtypeMismatch`].
pub(super) fn ticket_error(error: TicketError) -> Error {
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
