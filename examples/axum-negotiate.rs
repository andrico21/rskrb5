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

/// Runs the example server.
///
/// # Errors
/// Returns keytab loading, listener binding and serving errors.
///
/// # Panics
/// The Tokio entry-point macro panics if its runtime cannot be initialized.
///
/// # Cancel safety
/// The server future owns every resource; dropping it stops the server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keytab = Box::leak(Box::new(load_keytab()?));
    let state = AppState {
        validator: Arc::new(Mutex::new(Validator::new(keytab))),
    };

    let app = Router::new()
        .route("/", get(index))
        .layer(middleware::from_fn_with_state(state.clone(), negotiate))
        .layer(middleware::map_response(security_response))
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
        && let Ok(mut value) = HeaderValue::from_str(&header)
    {
        value.set_sensitive(true);
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

/// Applies the example's response security policy.
fn harden_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for name in [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    ] {
        drop(headers.remove(name));
    }
    for (name, value) in [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "deny"),
        (
            "content-security-policy",
            "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
        ),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "accelerometer=(), camera=(), geolocation=(), microphone=()",
        ),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cache-control", "no-store, max-age=0"),
        ("x-dns-prefetch-control", "off"),
        ("x-permitted-cross-domain-policies", "none"),
    ] {
        drop(headers.insert(name, HeaderValue::from_static(value)));
    }
    response
}

/// Adapts the security policy as the outer response middleware.
// cancel-safe: applies headers synchronously without an await point.
async fn security_response(response: Response) -> Response {
    harden_response(response)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Security headers override insecure values on success, challenge, error and fallback responses.
    #[test]
    fn hardening_covers_all_response_statuses() -> Result<(), Box<dyn Error>> {
        for status in [
            StatusCode::OK,
            StatusCode::UNAUTHORIZED,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::NOT_FOUND,
        ] {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            drop(response.headers_mut().insert(
                "server",
                HeaderValue::from_static("internal-host/build-secret"),
            ));
            drop(
                response
                    .headers_mut()
                    .insert("x-powered-by", HeaderValue::from_static("framework-secret")),
            );
            drop(response.headers_mut().insert(
                "x-aspnet-version",
                HeaderValue::from_static("version-secret"),
            ));
            drop(response.headers_mut().insert(
                "x-aspnetmvc-version",
                HeaderValue::from_static("version-secret"),
            ));
            drop(
                response
                    .headers_mut()
                    .insert("x-content-type-options", HeaderValue::from_static("unsafe")),
            );
            let hardened = harden_response(response);
            assert_eq!(hardened.status(), status);
            for name in [
                "server",
                "x-powered-by",
                "x-aspnet-version",
                "x-aspnetmvc-version",
            ] {
                assert!(hardened.headers().get(name).is_none());
            }
            assert_eq!(
                hardened
                    .headers()
                    .get("x-content-type-options")
                    .ok_or("nosniff missing")?,
                "nosniff"
            );
            for name in [
                "strict-transport-security",
                "x-frame-options",
                "content-security-policy",
                "referrer-policy",
                "permissions-policy",
                "cross-origin-embedder-policy",
                "cross-origin-opener-policy",
                "cross-origin-resource-policy",
                "cache-control",
                "x-dns-prefetch-control",
                "x-permitted-cross-domain-policies",
            ] {
                assert!(hardened.headers().contains_key(name), "missing {name}");
            }
        }
        Ok(())
    }
}
