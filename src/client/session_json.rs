//! TGT session metadata serialization.

use super::{AsRepSession, Tokio, json_time};

/// JSON shape of one TGT session in [`Tokio::sessions_json`].
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct SessionJsonEntry {
    /// Realm the TGT is issued for.
    realm: String,
    /// Initial authentication time (RFC 3339).
    auth_time: String,
    /// Ticket end time (RFC 3339).
    end_time: String,
    /// Renewable-until time, or the end time when not renewable (RFC 3339).
    renew_till: String,
    /// Session key expiration, or the end time when absent (RFC 3339).
    session_key_expiration: String,
}

/// Serialize public TGT session metadata.
///
/// # Errors
/// Returns the `serde_json` error if the sessions cannot be serialized.
pub(super) fn render(client: &Tokio) -> Result<String, serde_json::Error> {
    let sessions = client
        .tgt_sessions
        .values()
        .map(session_json_entry)
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&sessions)
}

/// JSON entry for one TGT session.
fn session_json_entry(session: &AsRepSession) -> SessionJsonEntry {
    SessionJsonEntry {
        realm: session.service.realm.clone(),
        auth_time: json_time(session.auth_time),
        end_time: json_time(session.end_time),
        renew_till: json_time(session.renew_till.unwrap_or(session.end_time)),
        session_key_expiration: json_time(session.key_expiration.unwrap_or(session.end_time)),
    }
}
