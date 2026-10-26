//! Axum server on `127.0.0.1:3000` whose middleware validates
//! `Authorization: Negotiate` headers against the service keytab named by
//! `KRB5_KTNAME` (default `http.keytab`) and answers with the authenticated client principal.
extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;
use std::{env, fs, path::PathBuf, sync::Mutex};

use axum::{
    Router,
    body::Body,
    extract::{Extension, State},
    http::{HeaderValue, Request, StatusCode, header::WWW_AUTHENTICATE},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use rskrb5_ng::{
    error::Http as HttpError,
    http as krb_http,
    keytab::Keytab,
    service::{ApRepOptions, Validator},
    spnego::AcceptedContext,
};
use tokio::net::TcpListener;

/// Shared state of the example server.
#[derive(Clone)]
struct AppState {
    /// The acceptor shared by every request; its replay cache must see all of them.
    validator: Arc<Mutex<Validator<'static>>>,
}

// cancel-safe: the server future owns every resource; dropping it stops the server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keytab = Box::leak(Box::new(load_keytab()?));
    let state = AppState {
        validator: Arc::new(Mutex::new(Validator::new(keytab))),
    };

    let app = Router::new()
        .route("/", get(index))
        .layer(middleware::from_fn_with_state(state.clone(), negotiate))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Answers with the authenticated client principal.
// cancel-safe: formats a string; there is no await point.
async fn index(Extension(context): Extension<AcceptedContext>) -> String {
    format!(
        "authenticated as {}@{}\n",
        context.ap_req.client.name(),
        context.ap_req.client.realm
    )
}

/// Validates the request's `Authorization: Negotiate` header before the inner
/// handler runs, and adds the mutual-authentication reply header.
///
/// A poisoned validator lock answers `500 Internal Server Error`: the replay
/// cache may be inconsistent, so the request is refused rather than accepted.
// cancel-safe: the ticket is validated before the only await point; dropping
// the future after it only drops the inner handler's response.
async fn negotiate(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let accepted = {
        let Ok(mut validator) = state.validator.lock() else {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return response;
        };
        match krb_http::accept_request(&mut validator, &mut request) {
            Ok(accepted) => accepted,
            Err(HttpError::MissingAuthorization | HttpError::InvalidHeader(_)) => {
                return krb_http::challenge_response();
            }
            Err(HttpError::Spnego(_)) => {
                return krb_http::reject_response()
                    .unwrap_or_else(|_| krb_http::challenge_response());
            }
            Err(_) => return krb_http::challenge_response(),
        }
    };

    let ap_rep_header = accepted
        .ap_rep_response_header(&ApRepOptions::default())
        .ok();
    let mut response = next.run(request).await;
    if let Some(header) = ap_rep_header
        && let Ok(value) = HeaderValue::from_str(&header)
    {
        drop(response.headers_mut().insert(WWW_AUTHENTICATE, value));
    }
    response
}

/// Reads the service keytab named by `KRB5_KTNAME` (an optional `FILE:`
/// prefix is stripped), or `http.keytab` when the variable is unset.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not a valid keytab.
fn load_keytab() -> Result<Keytab, Box<dyn Error>> {
    let configured =
        env::var_os("KRB5_KTNAME").map_or_else(|| PathBuf::from("http.keytab"), PathBuf::from);
    let path = configured
        .to_string_lossy()
        .strip_prefix("FILE:")
        .map_or_else(|| configured.clone(), PathBuf::from);
    Ok(Keytab::parse(&fs::read(path)?)?)
}
