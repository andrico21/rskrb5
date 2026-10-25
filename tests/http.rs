#![expect(missing_docs, reason = "lint-migration: upstream baseline at ee9cb04")]
#![cfg(feature = "http")]

#[cfg(feature = "tokio")]
extern crate alloc;

#[cfg(feature = "tokio")]
use alloc::rc::Rc;
#[cfg(feature = "tokio")]
use core::cell::{Cell, RefCell};
#[cfg(any(feature = "tokio", feature = "tower"))]
use core::convert::Infallible;
#[cfg(feature = "tower")]
use core::task::{Context, Poll, Waker};
use core::{error, time::Duration};
use std::time::UNIX_EPOCH;

use http_types::{
    Request, Response, StatusCode,
    header::{HeaderValue, WWW_AUTHENTICATE},
};
use pretty_assertions::assert_eq;
#[cfg(feature = "tokio")]
use rskrb5::client::{BlockingNegotiateClient, KdcProtocol, NegotiateClient, TokioClient};
#[cfg(any(feature = "tokio", feature = "tower"))]
use rskrb5::config::Config;
use rskrb5::{
    client::{AsRepSession, Principal},
    http as krb_http,
    keytab::{EncryptionKey, Keytab},
    service::ServiceValidator,
    spnego::{
        self, AcceptedContext, InitiatorContextOptions, Krb5MechToken, NegTokenInit, SpnegoToken,
    },
};
#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::unused_trait_names,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
use tower_layer::Layer;
#[cfg(feature = "tower")]
use tower_service::Service;

#[cfg(feature = "tower")]
#[path = "support/env.rs"]
mod env;

/// Error type of the `Result`-returning tests.
type TestError = Box<dyn error::Error>;

const HTTP_KEYTAB: &str = concat!(
    "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
    "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
    "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
    "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
);
const VALID_AP_REQ: &str = concat!(
    "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
    "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
    "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
    "5e7242bdf5331825046b4692f2f850f62dedee984e72a490ac48fc3375f5bc1a50c07ff766338",
    "cbb1486cd8f9974b0865f3fd3ecb4e72b6dc556bb73a1cea8f4579983e625676b43854ff9910",
    "a0b60996f148ee1b6a49a1896d41afde6e82d2d8ed9f7304ac0ded7a74f88694dc69ab532",
    "ff51f5e7ba7fce87f4ba19885fc915e6d83f11f2152bd64f3fd63cb8b160148fed6fa9b01",
    "d86acd337d20c3b99622b166b6b283cd3704f36147972015c3a750ce9c855ae58ec598929ed",
    "953b4008dbad1ca6f0a715eb07ee19f5124ff7354ded3928fccd6cc7e8a481ab3081a8a0",
    "03020112a103020101a2819b04819882e028aad111ace518b36bd7305f9ff06545036b2214916",
    "00d07509d4e1bbcacb5a6bde72ec8812c2ef087cb64dcd905d7eba708d7a7c1a782e7bc",
    "cc3d46bfc503e5075bd6ca1d2f27b218ebb907483b6b0b8bac5137fa15fb59b1df434371",
    "e041c817d652e3068912e55203ec6ea5ce374a20e5b9b5ed9dfb6bdb06137b90b2db2a",
    "db192d415375581bdf9a2bfe73d19c13ba1d983bf513",
);
const VALID_SESSION_KEY: &str = "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn http_helpers_set_headers_and_challenge() {
    let mut request = Request::new(());
    assert!(matches!(
        krb_http::authorization_header(&request),
        Err(krb_http::Error::MissingAuthorization)
    ));

    krb_http::set_authorization_header(&mut request, "Negotiate token").expect("header sets");
    assert_eq!(
        krb_http::authorization_header(&request).expect("header reads"),
        "Negotiate token"
    );

    let response = krb_http::challenge_response::<()>();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("challenge header exists")
            .to_str()
            .expect("challenge header is a string"),
        "Negotiate"
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn accept_request_validates_spnego_header_and_adds_extension() {
    let keytab = keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let accepted =
        krb_http::accept_request(&mut validator, &mut request).expect("request validates");

    assert_eq!(accepted.ap_req.client.name(), "testuser1");
    assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
    assert!(
        request.extensions().get::<AcceptedContext>().is_some(),
        "accepted context is attached to request extensions"
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn accept_request_validates_raw_krb5_header() {
    let keytab = keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &raw_krb5_authorization_header())
        .expect("authorization header sets");

    let accepted =
        krb_http::accept_request(&mut validator, &mut request).expect("request validates");

    assert_eq!(accepted.ap_req.client.name(), "testuser1");
    assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn http_helpers_scan_www_authenticate_negotiate_challenges() {
    let mut missing = Response::new(());
    assert!(matches!(
        krb_http::www_authenticate_negotiate_header(&missing),
        Err(krb_http::Error::MissingWwwAuthenticate)
    ));

    missing.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test, local\""),
    );
    assert!(matches!(
        krb_http::www_authenticate_negotiate_header(&missing),
        Err(krb_http::Error::MissingNegotiateChallenge)
    ));

    let challenge = krb_http::challenge_response::<()>();
    assert_eq!(
        krb_http::www_authenticate_negotiate_header(&challenge).expect("bare challenge is found"),
        "Negotiate"
    );

    let mut response = Response::new(());
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test, local\""),
    );
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("negotiate response-token"),
    );
    assert_eq!(
        krb_http::www_authenticate_negotiate_header(&response)
            .expect("Negotiate challenge is found"),
        "negotiate response-token"
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
#[test]
fn authorize_request_context_sets_header_and_returns_context() {
    runtime().block_on(async {
        let service_ticket = current_service_ticket_session();
        let service = service_ticket.service.clone();
        let mut client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        client.cache_service_ticket(service_ticket);
        let mut request = Request::new(());

        let context = krb_http::authorize_request_context_with_options(
            &mut client,
            &mut request,
            service,
            InitiatorContextOptions::new().with_sequence_number(Some(42)),
        )
        .await
        .expect("request is authorized");

        assert_eq!(context.sequence_number, Some(42));
        assert_eq!(
            krb_http::authorization_header(&request).expect("Authorization header exists"),
            context.header
        );
    });
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
#[test]
fn authorize_request_context_supports_negotiate_client_wrapper() {
    runtime().block_on(async {
        let mut service_ticket = current_service_ticket_session();
        let service = service_ticket.service.clone();
        let mut tokio_client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        tokio_client.cache_service_ticket(service_ticket.clone());
        let mut client = NegotiateClient::from_tokio_client(tokio_client);
        let mut request = Request::new(());

        let context = krb_http::authorize_request_context_with_negotiate_client_options(
            &mut client,
            &mut request,
            service,
            InitiatorContextOptions::new().with_sequence_number(Some(7)),
        )
        .await
        .expect("request is authorized");

        assert_eq!(context.sequence_number, Some(7));
        assert_eq!(
            krb_http::authorization_header(&request).expect("Authorization header exists"),
            context.header
        );

        service_ticket.session_key.value = vec![0x55; 32];
        assert_ne!(context.session_key, service_ticket.session_key);
    });
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::shadow_reuse,
        clippy::shadow_unrelated,
        clippy::std_instead_of_core,
        clippy::tests_outside_test_module,
        clippy::unseparated_literal_suffix,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
#[test]
fn negotiate_http_client_retries_challenge_with_replayable_request() {
    runtime().block_on(async {
        let service_ticket = current_service_ticket_session();
        let service = service_ticket.service.clone();
        let mut tokio_client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        tokio_client.cache_service_ticket(service_ticket);
        let mut client = NegotiateClient::from_tokio_client(tokio_client);
        let make_calls = Rc::new(Cell::new(0usize));
        let make_calls_for_factory = Rc::clone(&make_calls);
        let sent = Rc::new(RefCell::new(Vec::<(Option<String>, Vec<u8>)>::new()));
        let sent_for_sender = Rc::clone(&sent);

        let result = krb_http::send_with_negotiate_options(
            &mut client,
            service,
            InitiatorContextOptions::new().with_sequence_number(Some(99)),
            move || {
                let call = make_calls_for_factory.get() + 1;
                make_calls_for_factory.set(call);
                Request::builder()
                    .method("POST")
                    .uri("/protected")
                    .body(format!("payload-{call}").into_bytes())
                    .expect("request builds")
            },
            move |request: Request<Vec<u8>>| {
                let authorization = krb_http::authorization_header(&request)
                    .ok()
                    .map(str::to_owned);
                let body = request.body().clone();
                let call = {
                    let mut sent = sent_for_sender.borrow_mut();
                    sent.push((authorization.clone(), body));
                    sent.len()
                };
                let response = if call == 1 {
                    krb_http::challenge_response::<Vec<u8>>()
                } else {
                    let header = authorization.expect("retry request has authorization");
                    assert!(
                        header.starts_with("Negotiate "),
                        "retry Authorization uses Negotiate"
                    );
                    response_with_www_authenticate_body(
                        &spnego::accept_completed_header().expect("accept-completed header"),
                        b"ok".to_vec(),
                    )
                };
                std::future::ready(Ok::<_, Infallible>(response))
            },
        )
        .await
        .expect("Negotiate send succeeds");

        assert!(result.did_negotiate());
        assert_eq!(
            result
                .context
                .as_ref()
                .expect("context is retained")
                .sequence_number,
            Some(99)
        );
        assert!(matches!(
            result.negotiation,
            Some(krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
        ));
        assert_eq!(result.response.status(), StatusCode::OK);
        assert_eq!(result.response.body().as_slice(), b"ok");
        assert_eq!(make_calls.get(), 2);

        let sent = sent.borrow();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].0.is_none(), "initial request is unauthenticated");
        assert_eq!(sent[0].1.as_slice(), b"payload-1");
        assert!(
            sent[1]
                .0
                .as_deref()
                .expect("retry has Authorization")
                .starts_with("Negotiate ")
        );
        assert_eq!(sent[1].1.as_slice(), b"payload-2");
    });
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::std_instead_of_core,
        clippy::tests_outside_test_module,
        clippy::unseparated_literal_suffix,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
#[test]
fn negotiate_http_client_returns_first_response_without_challenge() {
    runtime().block_on(async {
        let mut client = NegotiateClient::with_password(
            Config::new(),
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        let make_calls = Cell::new(0usize);
        let send_calls = Cell::new(0usize);

        let result = krb_http::send_with_negotiate(
            &mut client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            || {
                make_calls.set(make_calls.get() + 1);
                Request::new(())
            },
            |request| {
                assert!(
                    krb_http::authorization_header(&request).is_err(),
                    "unchallenged request should not be preauthenticated"
                );
                send_calls.set(send_calls.get() + 1);
                std::future::ready(Ok::<_, Infallible>(Response::new("public")))
            },
        )
        .await
        .expect("send succeeds");

        assert!(!result.did_negotiate());
        assert!(result.context.is_none());
        assert!(result.negotiation.is_none());
        assert_eq!(*result.response.body(), "public");
        assert_eq!(make_calls.get(), 1);
        assert_eq!(send_calls.get(), 1);
    });
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        clippy::unseparated_literal_suffix,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
#[test]
fn blocking_negotiate_http_client_returns_first_response_without_challenge() {
    let mut client = BlockingNegotiateClient::with_password(
        Config::new(),
        Principal::user("TEST.GOKRB5", "testuser1"),
        b"unused".to_vec(),
    )
    .expect("blocking client builds");
    let make_calls = Cell::new(0usize);
    let send_calls = Cell::new(0usize);

    let result = krb_http::send_with_blocking_negotiate(
        &mut client,
        Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
        || {
            make_calls.set(make_calls.get() + 1);
            Request::new(())
        },
        |request| {
            assert!(
                krb_http::authorization_header(&request).is_err(),
                "unchallenged request should not be preauthenticated"
            );
            send_calls.set(send_calls.get() + 1);
            Ok::<_, Infallible>(Response::new("public"))
        },
    )
    .expect("send succeeds");

    assert!(!result.did_negotiate());
    assert!(result.context.is_none());
    assert!(result.negotiation.is_none());
    assert_eq!(*result.response.body(), "public");
    assert_eq!(make_calls.get(), 1);
    assert_eq!(send_calls.get(), 1);
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn verify_ap_rep_response_uses_negotiate_www_authenticate_header() {
    let context = initiator_context();
    let response_header = ap_rep_response_header(&context);
    let mut response = Response::new(());
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test\""),
    );
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&response_header).expect("AP-REP header value"),
    );

    let verified = krb_http::verify_ap_rep_response(&context, &response).expect("AP-REP verifies");

    assert_eq!(verified.ctime, context.authenticator_ctime);
    assert_eq!(verified.cusec, context.authenticator_cusec);
    assert_eq!(verified.authenticator_time, context.authenticator_time);
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::panic,
        clippy::rest_pattern_accessible_field,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn classify_negotiate_response_reports_client_state() {
    let context = initiator_context();
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &Response::new(())),
        krb_http::ClientNegotiateResponse::NoAuthenticateHeader
    );

    let mut basic = Response::new(());
    basic.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test\""),
    );
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &basic),
        krb_http::ClientNegotiateResponse::NoNegotiateChallenge
    );

    assert_eq!(
        krb_http::classify_negotiate_response(&context, &krb_http::challenge_response::<()>()),
        krb_http::ClientNegotiateResponse::Challenge
    );

    let mut later_challenge = Response::new(());
    later_challenge.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"test\""),
    );
    later_challenge
        .headers_mut()
        .append(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &later_challenge),
        krb_http::ClientNegotiateResponse::Challenge
    );

    let accepted_without_ap_rep = response_with_www_authenticate(
        &spnego::accept_completed_header().expect("accept-completed header"),
    );
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &accepted_without_ap_rep),
        krb_http::ClientNegotiateResponse::Accepted { ap_rep: None }
    );

    let rejected = response_with_www_authenticate(&spnego::reject_header().expect("reject header"));
    assert_eq!(
        krb_http::classify_negotiate_response(&context, &rejected),
        krb_http::ClientNegotiateResponse::Rejected
    );

    let ap_rep = response_with_www_authenticate(&ap_rep_response_header(&context));
    let classified = krb_http::classify_negotiate_response(&context, &ap_rep);
    let krb_http::ClientNegotiateResponse::Accepted {
        ap_rep: Some(verified),
    } = classified
    else {
        panic!("expected verified AP-REP, got {classified:?}");
    };
    assert_eq!(verified.ctime, context.authenticator_ctime);
    assert_eq!(verified.cusec, context.authenticator_cusec);

    let malformed = response_with_www_authenticate("Negotiate not-base64");
    assert!(matches!(
        krb_http::classify_negotiate_response(&context, &malformed),
        krb_http::ClientNegotiateResponse::InvalidToken { .. }
    ));

    let wrong_mechanism = response_with_www_authenticate(&valid_authorization_header());
    assert!(matches!(
        krb_http::classify_negotiate_response(&context, &wrong_mechanism),
        krb_http::ClientNegotiateResponse::InvalidToken { .. }
    ));
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::assertions_on_result_states,
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn verify_ap_rep_response_rejects_malformed_and_wrong_tokens() {
    let context = initiator_context();
    let mut malformed = Response::new(());
    malformed.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Negotiate not-base64"),
    );
    assert!(krb_http::verify_ap_rep_response(&context, &malformed).is_err());

    let mut wrong_mechanism = Response::new(());
    wrong_mechanism.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&valid_authorization_header()).expect("SPNEGO init header value"),
    );
    assert!(krb_http::verify_ap_rep_response(&context, &wrong_mechanism).is_err());
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_challenges_missing_authorization() {
    let keytab = keytab();
    let mut service = krb_http::NegotiateLayer::new(&keytab).layer(PanicService);

    let response = run_ready(service.call(Request::new(()))).expect("challenge response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("challenge header exists")
            .to_str()
            .expect("challenge header is a string"),
        "Negotiate"
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_validates_request_and_adds_ap_rep_response_header() {
    let keytab = keytab();
    let mut service = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let ap_rep_header = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .expect("AP-REP response header exists")
        .to_str()
        .expect("AP-REP header is a string");
    assert!(matches!(
        spnego::parse_negotiate_header(ap_rep_header).expect("AP-REP header parses"),
        SpnegoToken::Resp(_)
    ));
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_forwards_authenticated_post_body() {
    let keytab = keytab();
    let payload = b"authenticated upload payload".to_vec();
    let mut service = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .layer(AssertBodyService {
            expected: payload.clone(),
        });
    let mut request = Request::builder()
        .method("POST")
        .uri("/upload")
        .body(payload)
        .expect("request builds");
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(*response.body(), b"authenticated upload payload".len());
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_loads_owned_keytab_name() {
    let path = temp_file("http-keytab-name");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");

    let layer = krb_http::NegotiateLayer::from_keytab_name(&name)
        .expect("layer loads keytab name")
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let _ = std::fs::remove_file(&path);

    let mut service = layer.layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(WWW_AUTHENTICATE).is_none(),
        "AP-REP header is disabled"
    );
}

/// Child-process tests of the tower service and layer `KRB5_KTNAME` loaders.
#[cfg(test)]
#[cfg(feature = "tower")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tower_keytab_env {
    use std::{env::var, path::PathBuf};

    use pretty_assertions::assert_eq;

    use super::*;

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::let_underscore_must_use,
            clippy::let_underscore_untyped,
            let_underscore_drop,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(feature = "tower")]
    /// Pins that `NegotiateService::from_keytab_env` loads the `KRB5_KTNAME` keytab.
    #[test]
    fn tower_service_loads_keytab_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tower_keytab_env::tower_service_loads_keytab_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("http-keytab-env");
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab()
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;

        let mut service = krb_http::NegotiateService::from_keytab_env(AssertAcceptedService)
            .map_err(|cause| format!("service loads keytab env: {cause}"))?
            .with_now(timestamp(1_893_553_447))
            .with_ap_rep(false);
        let _ = std::fs::remove_file(&path);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header())
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::let_underscore_must_use,
            clippy::let_underscore_untyped,
            let_underscore_drop,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(feature = "tower")]
    /// Pins that `NegotiateLayer::from_keytab_env` loads the `KRB5_KTNAME` keytab.
    #[test]
    fn tower_layer_loads_keytab_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tower_keytab_env::tower_layer_loads_keytab_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("http-layer-keytab-env");
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab()
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;

        let layer = krb_http::NegotiateLayer::from_keytab_env()
            .map_err(|cause| format!("layer loads keytab env: {cause}"))?
            .with_now(timestamp(1_893_553_447))
            .with_ap_rep(false);
        let _ = std::fs::remove_file(&path);
        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header())
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_loads_config_default_keytab_name() {
    let path = temp_file("http-default-keytab-name");
    let name = format!("FILE:{}", path.display());
    keytab().save(&path).expect("keytab saves");
    let config = config_with_default_keytab_name(&name);

    let layer = krb_http::NegotiateLayer::from_default_keytab_name(&config)
        .expect("layer loads default keytab name")
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let _ = std::fs::remove_file(&path);

    let mut service = layer.layer(AssertAcceptedService);
    let mut request = Request::new(());
    krb_http::set_authorization_header(&mut request, &valid_authorization_header())
        .expect("authorization header sets");

    let response = run_ready(service.call(request)).expect("inner response succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(WWW_AUTHENTICATE).is_none(),
        "AP-REP header is disabled"
    );
}

/// Child-process tests of the tower default-keytab precedence.
#[cfg(test)]
#[cfg(feature = "tower")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tower_default_keytab_env {
    use std::{env::var, path::PathBuf};

    use pretty_assertions::assert_eq;

    use super::*;

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::let_underscore_must_use,
            clippy::let_underscore_untyped,
            let_underscore_drop,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(feature = "tower")]
    /// Pins that the layer falls back to the config default keytab without `KRB5_KTNAME`.
    #[test]
    fn tower_layer_loads_default_keytab_when_env_is_absent() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "tower_default_keytab_env::tower_layer_loads_default_keytab_when_env_is_absent";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", None)]);
            return Ok(());
        }
        let path = temp_file("http-default-keytab-env-fallback");
        let name = format!("FILE:{}", path.display());
        keytab()
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;
        let config = config_with_default_keytab_name(&name);

        let layer = krb_http::NegotiateLayer::from_default_keytab(&config)
            .map_err(|cause| format!("layer loads default keytab: {cause}"))?
            .with_now(timestamp(1_893_553_447))
            .with_ap_rep(false);
        let _ = std::fs::remove_file(&path);

        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header())
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::let_underscore_must_use,
            clippy::let_underscore_untyped,
            let_underscore_drop,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(feature = "tower")]
    /// Pins that the service prefers `KRB5_KTNAME` over the config default keytab.
    #[test]
    fn tower_service_prefers_env_keytab_over_config_default() -> Result<(), TestError> {
        const TEST_PATH: &str =
            "tower_default_keytab_env::tower_service_prefers_env_keytab_over_config_default";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("http-env-keytab-precedence");
            let env_name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(env_name.as_ref()))]);
            return Ok(());
        }
        let env_name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            env_name
                .strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab()
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;
        let missing_config_name = format!(
            "FILE:{}",
            temp_file("missing-http-config-default").display()
        );
        let config = config_with_default_keytab_name(&missing_config_name);
        let mut service =
            krb_http::NegotiateService::from_default_keytab(AssertAcceptedService, &config)
                .map_err(|cause| {
                    format!("service loads env keytab before config default: {cause}")
                })?
                .with_now(timestamp(1_893_553_447))
                .with_ap_rep(false);
        let _ = std::fs::remove_file(&path);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header())
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))
            .map_err(|cause| format!("inner response succeeds: {cause}"))?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(WWW_AUTHENTICATE).is_none(),
            "AP-REP header is disabled"
        );
        Ok(())
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_rejects_replayed_request() {
    let keytab = keytab();
    let mut service = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .layer(AssertAcceptedService);
    let header = valid_authorization_header();
    let mut first = Request::new(());
    krb_http::set_authorization_header(&mut first, &header).expect("authorization header sets");
    let mut replay = Request::new(());
    krb_http::set_authorization_header(&mut replay, &header).expect("authorization header sets");

    let first_response = run_ready(service.call(first)).expect("first response succeeds");
    let replay_response = run_ready(service.call(replay)).expect("replay returns reject response");

    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        replay_response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("reject header exists")
            .to_str()
            .expect("reject header is a string"),
        spnego::reject_header().expect("reject header encodes")
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
#[test]
fn tower_layer_rejects_replay_across_services() {
    let keytab = keytab();
    let layer = krb_http::NegotiateLayer::new(&keytab)
        .with_now(timestamp(1_893_553_447))
        .with_ap_rep(false);
    let mut first_service = layer.clone().layer(AssertAcceptedService);
    let mut second_service = layer.layer(AssertAcceptedService);
    let header = valid_authorization_header();
    let mut first = Request::new(());
    krb_http::set_authorization_header(&mut first, &header).expect("authorization header sets");
    let mut replay = Request::new(());
    krb_http::set_authorization_header(&mut replay, &header).expect("authorization header sets");

    let first_response = run_ready(first_service.call(first)).expect("first response succeeds");
    let replay_response =
        run_ready(second_service.call(replay)).expect("replay returns reject response");

    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        replay_response
            .headers()
            .get(WWW_AUTHENTICATE)
            .expect("reject header exists")
            .to_str()
            .expect("reject header is a string"),
        spnego::reject_header().expect("reject header encodes")
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn valid_authorization_header() -> String {
    let ap_req_token = Krb5MechToken::ap_req(decode_hex(VALID_AP_REQ))
        .encode()
        .expect("KRB5 AP-REQ token encodes");
    let spnego_token = SpnegoToken::Init(NegTokenInit::krb5(ap_req_token));
    spnego::negotiate_header(&spnego_token).expect("Negotiate header encodes")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn raw_krb5_authorization_header() -> String {
    let ap_req_token = Krb5MechToken::ap_req(decode_hex(VALID_AP_REQ))
        .encode()
        .expect("KRB5 AP-REQ token encodes");
    format!("Negotiate {}", base64_encode(&ap_req_token))
}

fn initiator_context() -> spnego::InitiatorContext {
    initiator_context_with_options(InitiatorContextOptions::new().with_sequence_number(Some(42)))
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Builds the fixture initiator context with `options`.
///
/// # Panics
///
/// Panics if the fixture context cannot be built.
fn initiator_context_with_options(options: InitiatorContextOptions) -> spnego::InitiatorContext {
    spnego::init_sec_context_with_confounder(
        &service_ticket_session_from_valid_ap_req(),
        options,
        timestamp(1_893_553_447),
        123_456,
        &decode_hex(AP_REP_CONFOUNDER),
    )
    .expect("client SPNEGO context builds")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::default_trait_access,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn ap_rep_response_header(context: &spnego::InitiatorContext) -> String {
    let keytab = keytab();
    let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447));
    let accepted = spnego::accept_sec_context_header(&mut validator, &context.header)
        .expect("client SPNEGO header validates");
    accepted
        .ap_rep_response_header_with_confounder(&decode_hex(AP_REP_CONFOUNDER), Default::default())
        .expect("AP-REP response header builds")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn service_ticket_session_from_valid_ap_req() -> AsRepSession {
    let ap_req: rasn_kerberos::ApReq =
        rasn::der::decode(&decode_hex(VALID_AP_REQ)).expect("AP-REQ fixture decodes");
    AsRepSession {
        client: Principal::user("TEST.GOKRB5", "testuser1"),
        service: Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
        session_key: EncryptionKey {
            etype: 18,
            value: decode_hex(VALID_SESSION_KEY),
        },
        ticket: rasn::der::encode(&ap_req.ticket).expect("ticket encodes"),
        ticket_flags: [0; 4],
        auth_time: timestamp(1_893_553_445),
        start_time: timestamp(1_893_553_445),
        end_time: timestamp(1_893_639_845),
        renew_till: None,
        key_expiration: None,
    }
}

fn response_with_www_authenticate(header: &str) -> Response<()> {
    response_with_www_authenticate_body(header, ())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::ignored_unit_patterns,
        clippy::missing_panics_doc,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn response_with_www_authenticate_body<B>(header: &str, body: B) -> Response<B> {
    let mut response = Response::new(());
    response.headers_mut().append(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(header).expect("WWW-Authenticate header value"),
    );
    response.map(|_| body)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::arithmetic_side_effects,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
fn current_service_ticket_session() -> AsRepSession {
    let mut service_ticket = service_ticket_session_from_valid_ap_req();
    let now = std::time::SystemTime::now();
    service_ticket.auth_time = now - Duration::from_secs(1);
    service_ticket.start_time = now - Duration::from_secs(1);
    service_ticket.end_time = now + Duration::from_secs(60);
    service_ticket
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn keytab() -> Keytab {
    Keytab::parse(&decode_hex(HTTP_KEYTAB)).expect("HTTP keytab parses")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::needless_raw_strings,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
fn config_with_default_keytab_name(keytab_name: &str) -> Config {
    let input = format!(
        r#"
[libdefaults]
 default_keytab_name = {keytab_name}
"#,
    );
    Config::parse(&input).expect("config parses")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::arithmetic_side_effects,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn timestamp(seconds: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tokio")]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
fn temp_file(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("rskrb5-{label}-{nanos}.keytab"))
}

#[cfg(feature = "tower")]
struct PanicService;

#[cfg(feature = "tower")]
impl Service<Request<()>> for PanicService {
    type Response = Response<()>;
    type Error = Infallible;
    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::std_instead_of_core,
            unused_qualifications,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::std_instead_of_core,
            unused_qualifications,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(clippy::panic, reason = "lint-migration: upstream baseline at ee9cb04")
    )]
    fn call(&mut self, _request: Request<()>) -> Self::Future {
        panic!("inner service must not be called without credentials")
    }
}

#[cfg(feature = "tower")]
struct AssertAcceptedService;

#[cfg(feature = "tower")]
impl Service<Request<()>> for AssertAcceptedService {
    type Response = Response<()>;
    type Error = Infallible;
    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::std_instead_of_core,
            unused_qualifications,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::std_instead_of_core,
            unused_qualifications,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::expect_used,
            clippy::renamed_function_params,
            clippy::std_instead_of_core,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    fn call(&mut self, request: Request<()>) -> Self::Future {
        let accepted = request
            .extensions()
            .get::<AcceptedContext>()
            .expect("accepted context exists");
        assert_eq!(accepted.ap_req.client.name(), "testuser1");
        assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
        std::future::ready(Ok(Response::new(())))
    }
}

#[cfg(feature = "tower")]
struct AssertBodyService {
    expected: Vec<u8>,
}

#[cfg(feature = "tower")]
impl Service<Request<Vec<u8>>> for AssertBodyService {
    type Response = Response<usize>;
    type Error = Infallible;
    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::std_instead_of_core,
            unused_qualifications,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::std_instead_of_core,
            unused_qualifications,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[cfg_attr(
        any(
            all(
                feature = "default",
                feature = "evaluation",
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                feature = "http",
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                feature = "tower",
                test
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::expect_used,
            clippy::renamed_function_params,
            clippy::std_instead_of_core,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    fn call(&mut self, request: Request<Vec<u8>>) -> Self::Future {
        let accepted = request
            .extensions()
            .get::<AcceptedContext>()
            .expect("accepted context exists");
        assert_eq!(accepted.ap_req.client.name(), "testuser1");
        assert_eq!(accepted.ap_req.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(request.method().as_str(), "POST");
        assert_eq!(request.uri().path(), "/upload");
        assert_eq!(request.body(), &self.expected);
        std::future::ready(Ok(Response::new(request.body().len())))
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        )
    ),
    expect(
        clippy::missing_panics_doc,
        clippy::panic,
        clippy::shadow_reuse,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "tower")]
fn run_ready<F>(future: F) -> F::Output
where
    F: Future,
{
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::default_numeric_fallback,
        clippy::integer_division_remainder_used,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_value(pair[0]);
            let low = hex_value(pair[1]);
            (high << 4) | low
        })
        .collect()
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::arithmetic_side_effects,
        clippy::missing_panics_doc,
        clippy::panic,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}

/// Fork-authored HTTP Negotiate tests: requested mutual authentication fails
/// closed without a verified AP-REP, and `clockskew` reaches the tower layer.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod fork_tests {
    #[cfg(feature = "tokio")]
    use core::future::ready;
    #[cfg(feature = "tower")]
    use std::fs;

    #[cfg(feature = "tokio")]
    use http_types::Uri;
    #[cfg(any(feature = "tokio", feature = "tower"))]
    use pretty_assertions::assert_eq;
    #[cfg(feature = "tokio")]
    use rskrb5::service::ApRepOptions;

    use super::*;

    /// Result of [`send_mutual_negotiate`].
    #[cfg(feature = "tokio")]
    type MutualSendResult = Result<
        krb_http::NegotiateHttpResponse<Vec<u8>>,
        krb_http::NegotiateHttpError<Infallible, Vec<u8>>,
    >;

    /// Pins that an AP-option mutual request classifies a completion without an AP-REP as a failure.
    #[cfg(feature = "tokio")]
    #[test]
    fn negotiate_http_client_classifies_missing_ap_rep_as_failure_when_mutual_requested()
    -> Result<(), TestError> {
        let accept_completed = spnego::accept_completed_header()
            .map_err(|cause| format!("accept-completed header: {cause}"))?;
        let (result, calls) = send_mutual_negotiate(
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            |_retry| response_with_www_authenticate_body(&accept_completed, b"ok".to_vec()),
        );

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert!(matches!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::InvalidToken { message: _ })
        ));
        assert_eq!(response.body().as_slice(), b"ok");
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that a mutual request fails closed on a final response without `WWW-Authenticate`.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_rejects_final_response_without_www_authenticate() -> Result<(), TestError> {
        let (result, calls) = send_mutual_negotiate(mutual_context_flag_options(), |_retry| {
            Response::new(b"ok".to_vec())
        });

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert_eq!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::NoAuthenticateHeader)
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body().as_slice(), b"ok");
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that a mutual request fails closed on a final non-Negotiate challenge.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_rejects_a_non_negotiate_challenge() -> Result<(), TestError> {
        let (result, calls) = send_mutual_negotiate(
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            |_retry| response_with_www_authenticate_body("Basic realm=\"test\"", b"ok".to_vec()),
        );

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert_eq!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::NoNegotiateChallenge)
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that a mutual request fails closed when the first response is never challenged.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_rejects_unchallenged_first_response() -> Result<(), TestError> {
        runtime().block_on(async {
            let mut client = negotiate_client_with_cached_service_ticket();
            let send_calls = Cell::new(0_usize);

            let result = krb_http::send_with_negotiate_options(
                &mut client,
                Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                mutual_context_flag_options(),
                || Request::new(()),
                |_request| {
                    send_calls.set(send_calls.get().saturating_add(1));
                    ready(Ok::<_, Infallible>(Response::new("public")))
                },
            )
            .await;

            let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
                negotiation,
                response,
            }) = result
            else {
                return Err(
                    format!("expected MutualAuthenticationNotProven, got {result:?}").into(),
                );
            };
            assert_eq!(negotiation, None);
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(*response.body(), "public");
            assert_eq!(send_calls.get(), 1);
            Ok(())
        })
    }

    /// Pins that a mutual request accepts a verified AP-REP that matches the authenticator.
    #[cfg(feature = "tokio")]
    #[test]
    fn mutual_wrapper_accepts_a_verified_ap_rep() -> Result<(), TestError> {
        let (result, calls) = send_mutual_negotiate(
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            |retry| {
                let built = krb_http::authorization_header(retry)
                    .map_err(|cause| {
                        TestError::from(format!("retry carries Authorization: {cause}"))
                    })
                    .and_then(ap_rep_response_header_for_live_authorization);
                match built {
                    Ok(header) => response_with_www_authenticate_body(&header, b"ok".to_vec()),
                    Err(cause) => Response::new(format!("no AP-REP header: {cause}").into_bytes()),
                }
            },
        );

        let negotiated = result
            .map_err(|cause| format!("verified AP-REP proves mutual authentication: {cause}"))?;
        let context = negotiated.context.as_ref().ok_or("context is retained")?;
        let Some(krb_http::ClientNegotiateResponse::Accepted {
            ap_rep: Some(verified),
        }) = &negotiated.negotiation
        else {
            return Err(
                format!("expected verified AP-REP, got {:?}", negotiated.negotiation).into(),
            );
        };
        assert_eq!(verified.ctime, context.authenticator_ctime);
        assert_eq!(verified.cusec, context.authenticator_cusec);
        assert_eq!(negotiated.response.body().as_slice(), b"ok");
        assert_eq!(calls, 2);
        Ok(())
    }

    /// Pins that the default async and blocking wrappers still accept a completion without an AP-REP.
    #[cfg(feature = "tokio")]
    #[test]
    fn default_wrapper_still_accepts_a_missing_ap_rep() -> Result<(), TestError> {
        let accept_header = spnego::accept_completed_header()
            .map_err(|cause| format!("accept-completed header: {cause}"))?;
        let challenge_then_accept = |call: usize| {
            if call == 1 {
                krb_http::challenge_response::<Vec<u8>>()
            } else {
                response_with_www_authenticate_body(&accept_header, b"ok".to_vec())
            }
        };

        let async_calls = Cell::new(0_usize);
        let async_result = runtime()
            .block_on(async {
                let mut client = negotiate_client_with_cached_service_ticket();
                krb_http::send_with_negotiate(
                    &mut client,
                    Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                    || Request::new(Vec::<u8>::new()),
                    |_request| {
                        async_calls.set(async_calls.get().saturating_add(1));
                        ready(Ok::<_, Infallible>(challenge_then_accept(
                            async_calls.get(),
                        )))
                    },
                )
                .await
            })
            .map_err(|cause| {
                format!("default async wrapper accepts a completion without an AP-REP: {cause}")
            })?;
        assert_eq!(
            async_result.negotiation,
            Some(krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
        );
        assert_eq!(async_calls.get(), 2);

        let mut blocking_client =
            BlockingNegotiateClient::new(negotiate_client_with_cached_service_ticket())
                .map_err(|cause| format!("blocking client builds: {cause}"))?;
        let blocking_calls = Cell::new(0_usize);
        let blocking_result = krb_http::send_with_blocking_negotiate(
            &mut blocking_client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            || Request::new(Vec::<u8>::new()),
            |_request| {
                blocking_calls.set(blocking_calls.get().saturating_add(1));
                Ok::<_, Infallible>(challenge_then_accept(blocking_calls.get()))
            },
        )
        .map_err(|cause| {
            format!("default blocking wrapper accepts a completion without an AP-REP: {cause}")
        })?;
        assert_eq!(
            blocking_result.negotiation,
            Some(krb_http::ClientNegotiateResponse::Accepted { ap_rep: None })
        );
        assert_eq!(blocking_calls.get(), 2);
        Ok(())
    }

    /// Pins that the blocking mutual wrapper fails closed on a completion without an AP-REP.
    #[cfg(feature = "tokio")]
    #[test]
    fn blocking_mutual_wrapper_rejects_a_missing_ap_rep() -> Result<(), TestError> {
        let accept_header = spnego::accept_completed_header()
            .map_err(|cause| format!("accept-completed header: {cause}"))?;
        let mut client =
            BlockingNegotiateClient::new(negotiate_client_with_cached_service_ticket())
                .map_err(|cause| format!("blocking client builds: {cause}"))?;
        let calls = Cell::new(0_usize);

        let result = krb_http::send_with_blocking_negotiate_options(
            &mut client,
            Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
            mutual_context_flag_options(),
            || Request::new(Vec::<u8>::new()),
            |_request| {
                calls.set(calls.get().saturating_add(1));
                let response = if calls.get() == 1 {
                    krb_http::challenge_response::<Vec<u8>>()
                } else {
                    response_with_www_authenticate_body(&accept_header, b"ok".to_vec())
                };
                Ok::<_, Infallible>(response)
            },
        );

        let Err(krb_http::NegotiateHttpError::MutualAuthenticationNotProven {
            negotiation,
            response,
        }) = result
        else {
            return Err(format!("expected MutualAuthenticationNotProven, got {result:?}").into());
        };
        assert!(matches!(
            negotiation,
            Some(krb_http::ClientNegotiateResponse::InvalidToken { message: _ })
        ));
        assert_eq!(response.body().as_slice(), b"ok");
        assert_eq!(calls.get(), 2);
        Ok(())
    }

    /// Pins that classification rejects a completion without an AP-REP for both mutual request forms.
    #[test]
    fn classify_rejects_missing_ap_rep_when_mutual_requested() -> Result<(), TestError> {
        let variants = [
            InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000),
            InitiatorContextOptions::new().with_context_flags(vec![
                spnego::CONTEXT_FLAG_INTEG,
                spnego::CONTEXT_FLAG_MUTUAL,
            ]),
        ];
        let accept_header = spnego::accept_completed_header()
            .map_err(|cause| format!("accept-completed header: {cause}"))?;
        for options in variants {
            let context = initiator_context_with_options(options);
            let response = response_with_www_authenticate(&accept_header);
            assert!(
                matches!(
                    krb_http::classify_negotiate_response(&context, &response),
                    krb_http::ClientNegotiateResponse::InvalidToken { message: _ }
                ),
                "requested mutual authentication must not accept a completion without an AP-REP"
            );
        }
        Ok(())
    }

    /// Pins that the tower layer honours the config `clockskew` and rejects a stale authenticator.
    #[cfg(feature = "tower")]
    #[test]
    fn tower_layer_config_clockskew_rejects_stale_authenticator() -> Result<(), TestError> {
        let path = temp_file("http-config-clockskew");
        let name = format!("FILE:{}", path.display());
        keytab()
            .save(&path)
            .map_err(|cause| format!("keytab saves: {cause}"))?;
        let config = config_with_default_keytab_name_and_clockskew(&name, "1s")?;

        let layer = krb_http::NegotiateLayer::from_default_keytab_name(&config)
            .map_err(|cause| format!("layer loads default keytab name: {cause}"))?
            .with_now(timestamp(1_893_553_447 + 2))
            .with_ap_rep(false);
        fs::remove_file(&path).map_err(|cause| format!("keytab file is removed: {cause}"))?;

        let mut service = layer.layer(AssertAcceptedService);
        let mut request = Request::new(());
        krb_http::set_authorization_header(&mut request, &valid_authorization_header())
            .map_err(|cause| format!("authorization header sets: {cause}"))?;

        let response = run_ready(service.call(request))
            .map_err(|cause| format!("reject response returned: {cause}"))?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// Run the async options wrapper against a sender that challenges first and
    /// answers the authenticated retry with `final_response`.
    #[cfg(feature = "tokio")]
    fn send_mutual_negotiate(
        options: InitiatorContextOptions,
        mut final_response: impl FnMut(&Request<Vec<u8>>) -> Response<Vec<u8>>,
    ) -> (MutualSendResult, usize) {
        runtime().block_on(async {
            let mut client = negotiate_client_with_cached_service_ticket();
            let calls = Cell::new(0_usize);
            let result = krb_http::send_with_negotiate_options(
                &mut client,
                Principal::new("TEST.GOKRB5", 1, ["HTTP", "host.test.gokrb5"]),
                options,
                || {
                    let mut request = Request::new(Vec::new());
                    *request.uri_mut() = Uri::from_static("/protected");
                    request
                },
                |request: Request<Vec<u8>>| {
                    calls.set(calls.get().saturating_add(1));
                    let response = if calls.get() == 1 {
                        krb_http::challenge_response::<Vec<u8>>()
                    } else {
                        final_response(&request)
                    };
                    ready(Ok::<_, Infallible>(response))
                },
            )
            .await;
            (result, calls.get())
        })
    }

    /// Initiator options that request mutual authentication through the context flags.
    #[cfg(feature = "tokio")]
    fn mutual_context_flag_options() -> InitiatorContextOptions {
        InitiatorContextOptions::new().with_context_flags(vec![
            spnego::CONTEXT_FLAG_INTEG,
            spnego::CONTEXT_FLAG_MUTUAL,
        ])
    }

    /// A Negotiate client whose cache already holds the fixture service ticket.
    #[cfg(feature = "tokio")]
    fn negotiate_client_with_cached_service_ticket() -> NegotiateClient {
        let mut tokio_client = TokioClient::with_password(
            Config::new(),
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            b"unused".to_vec(),
        );
        tokio_client.cache_service_ticket(current_service_ticket_session());
        NegotiateClient::from_tokio_client(tokio_client)
    }

    /// Accept a wrapper-built Authorization header and answer with a genuine AP-REP.
    ///
    /// The fixture ticket is valid at `1_893_553_447` while the wrapper stamps the
    /// authenticator with the wall clock, so the validator allows a wide skew.
    #[cfg(feature = "tokio")]
    fn ap_rep_response_header_for_live_authorization(
        authorization: &str,
    ) -> Result<String, TestError> {
        let keytab = keytab();
        let mut validator = ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447))
            .with_max_clock_skew(Duration::from_hours(100 * 365 * 24));
        let accepted = spnego::accept_sec_context_header(&mut validator, authorization)
            .map_err(|cause| format!("wrapper Authorization header validates: {cause}"))?;
        Ok(accepted
            .ap_rep_response_header_with_confounder(
                &decode_hex(AP_REP_CONFOUNDER),
                ApRepOptions::default(),
            )
            .map_err(|cause| format!("AP-REP response header builds: {cause}"))?)
    }

    /// A config naming `keytab_name` as the default keytab, with `clockskew`.
    #[cfg(feature = "tower")]
    fn config_with_default_keytab_name_and_clockskew(
        keytab_name: &str,
        clockskew: &str,
    ) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 default_keytab_name = {keytab_name}
 clockskew = {clockskew}
",
        );
        Ok(Config::parse(&input).map_err(|cause| format!("config parses: {cause}"))?)
    }
}
