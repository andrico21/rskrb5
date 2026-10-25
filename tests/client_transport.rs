#![expect(missing_docs, reason = "lint-migration: upstream baseline at ee9cb04")]
#![cfg(feature = "tokio")]

use core::{error::Error, time::Duration};

use rskrb5_ng::{
    client::{
        AsReqOptions, Error as ClientError, KRB_ERR_RESPONSE_TOO_BIG, KdcEndpoint,
        KdcEndpointSource, KdcProtocol, PA_ETYPE_INFO2, Principal, TokioKdcTransport,
        build_tgt_as_req,
    },
    config::Config,
    kadmin::{Error as KadminError, KPASSWD_AUTHERROR, KPASSWD_SUCCESS, Request as KpasswdRequest},
    keytab::EncryptionKey,
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::unused_trait_names,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

const MARSHALLED_KPASSWD_REQ: &str = include_str!("fixtures/kpasswd-request.hex");
const KPASSWD_HEADER_LEN: usize = 6;

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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_sends_udp_datagram() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = server.local_addr()?;
        let task = tokio::spawn(async move {
            let mut request = [0; 64];
            let (len, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(&request[..len], b"udp-as-req");
            server
                .send_to(b"udp-as-rep", peer)
                .await
                .expect("send response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send(KdcProtocol::Udp, addr, b"udp-as-req")
            .await?;

        task.await?;
        assert_eq!(response, b"udp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::as_conversions,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_uses_tcp_length_prefix() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept client");
            let mut header = [0; 4];
            socket
                .read_exact(&mut header)
                .await
                .expect("read request length");
            let request_len = u32::from_be_bytes(header) as usize;
            let mut request = vec![0; request_len];
            socket.read_exact(&mut request).await.expect("read request");
            assert_eq!(request, b"tcp-as-req");

            socket
                .write_all(&(10_u32).to_be_bytes())
                .await
                .expect("write response length");
            socket
                .write_all(b"tcp-as-rep")
                .await
                .expect("write response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_tcp(addr, b"tcp-as-req")
            .await?;

        task.await?;
        assert_eq!(response, b"tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::assertions_on_result_states,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn configured_kdc_endpoint_parses_authorities() -> Result<(), Box<dyn Error>> {
    let host = KdcEndpoint::configured(KdcProtocol::Tcp, "kdc.test.gokrb5:88")?;
    assert_eq!(host.protocol, KdcProtocol::Tcp);
    assert_eq!(host.host, "kdc.test.gokrb5");
    assert_eq!(host.port, 88);
    assert_eq!(host.source, KdcEndpointSource::Config);
    assert_eq!(host.authority(), "kdc.test.gokrb5:88");

    let default_port = KdcEndpoint::configured(KdcProtocol::Udp, "kdc.test.gokrb5")?;
    assert_eq!(default_port.port, 88);

    let kpasswd_default_port =
        KdcEndpoint::configured_with_default_port(KdcProtocol::Tcp, "kpasswd.test.gokrb5", 464)?;
    assert_eq!(kpasswd_default_port.host, "kpasswd.test.gokrb5");
    assert_eq!(kpasswd_default_port.port, 464);

    let ipv6 = KdcEndpoint::configured(KdcProtocol::Tcp, "[::1]:1088")?;
    assert_eq!(ipv6.host, "::1");
    assert_eq!(ipv6.port, 1088);
    assert_eq!(ipv6.authority(), "[::1]:1088");

    let bare_ipv6 = KdcEndpoint::configured(KdcProtocol::Tcp, "::1")?;
    assert_eq!(bare_ipv6.host, "::1");
    assert_eq!(bare_ipv6.port, 88);

    assert!(KdcEndpoint::configured(KdcProtocol::Tcp, "kdc.test.gokrb5:not-a-port").is_err());
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_sends_udp_to_configured_realm_kdc() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = server.local_addr()?;
        let config = config_with_kdcs([addr.to_string()]);
        let task = tokio::spawn(async move {
            let mut request = [0; 64];
            let (len, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(&request[..len], b"configured-udp-as-req");
            server
                .send_to(b"configured-udp-as-rep", peer)
                .await
                .expect("send response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Udp,
                "TEST.GOKRB5",
                b"configured-udp-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"configured-udp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::as_conversions,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_sends_tcp_to_configured_realm_kdc() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kdcs([addr.to_string()]);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept client");
            let mut header = [0; 4];
            socket
                .read_exact(&mut header)
                .await
                .expect("read request length");
            let request_len = u32::from_be_bytes(header) as usize;
            let mut request = vec![0; request_len];
            socket.read_exact(&mut request).await.expect("read request");
            assert_eq!(request, b"configured-tcp-as-req");

            socket
                .write_all(&(21_u32).to_be_bytes())
                .await
                .expect("write response length");
            socket
                .write_all(b"configured-tcp-as-rep")
                .await
                .expect("write response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                b"configured-tcp-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"configured-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::indexing_slicing,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_discovers_configured_kpasswd_servers() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let config = config_with_kpasswd_servers(
            ["kpasswd.test.gokrb5".to_owned(), "[::1]:7464".to_owned()],
            1465,
        );

        let endpoints = TokioKdcTransport::new()
            .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
            .await?;

        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].protocol, KdcProtocol::Tcp);
        assert_eq!(endpoints[0].host, "kpasswd.test.gokrb5");
        assert_eq!(endpoints[0].port, 464);
        assert_eq!(endpoints[0].source, KdcEndpointSource::Config);
        assert_eq!(endpoints[1].host, "::1");
        assert_eq!(endpoints[1].port, 7464);
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::indexing_slicing,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_prefers_configured_kpasswd_servers_when_dns_enabled()
-> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let mut config = config_with_kpasswd_servers(["kpasswd.test.gokrb5".to_owned()], 1465);
        config.libdefaults.dns_lookup_kdc = true;

        let endpoints = TokioKdcTransport::new()
            .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Udp)
            .await?;

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].protocol, KdcProtocol::Udp);
        assert_eq!(endpoints[0].host, "kpasswd.test.gokrb5");
        assert_eq!(endpoints[0].port, 464);
        assert_eq!(endpoints[0].source, KdcEndpointSource::Config);
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_sends_tcp_to_configured_kpasswd_server() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465);
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"kpasswd-tcp-req");
            write_tcp_response(&mut socket, b"kpasswd-tcp-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_kpasswd_realm(&config, KdcProtocol::Tcp, "TEST.GOKRB5", b"kpasswd-tcp-req")
            .await?;

        task.await?;
        assert_eq!(response, b"kpasswd-tcp-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::as_conversions,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::shadow_unrelated,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_exchanges_configured_kpasswd_request() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465);
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ))?;
        let expected_request = request.encode()?;
        let response = kpasswd_reply_frame(0, &response_too_big_error());
        let expected_response_len = response.len();
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, expected_request);
            write_tcp_response(&mut socket, &response).await;
        });

        let reply = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_kpasswd_request_with_config(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                &request,
            )
            .await?;

        task.await?;
        assert!(reply.is_krb_error());
        assert_eq!(reply.message_length as usize, expected_response_len);
        assert_eq!(
            reply.krb_error.expect("KRB-ERROR parsed").error_code,
            KRB_ERR_RESPONSE_TOO_BIG
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// kpasswd success and failure results over the configured transport.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod kpasswd_results {
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
                feature = "evaluation",
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
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
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                not(feature = "serde"),
                not(feature = "spnego"),
                feature = "tokio",
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::missing_errors_doc,
            clippy::missing_panics_doc,
            clippy::panic_in_result_fn,
            clippy::shadow_unrelated,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Pins that a kpasswd KRB-ERROR carrying a success result code is rejected as unauthenticated.
    #[test]
    fn tokio_transport_rejects_unauthenticated_kpasswd_success_result() -> Result<(), Box<dyn Error>>
    {
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kpasswd_servers([addr.to_string()], 1465);
            let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ))?;
            let expected_request = request.encode()?;
            let response = kpasswd_reply_frame(
                0,
                &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed"),
            );
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await;
                assert_eq!(request, expected_request);
                write_tcp_response(&mut socket, &response).await;
            });

            let error = TokioKdcTransport::new()
                .with_timeout(Duration::from_secs(2))
                .exchange_kpasswd_result_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    "TEST.GOKRB5",
                    &request,
                    &reply_key(),
                )
                .await
                .err()
                .ok_or("unsigned success result rejected")?;

            task.await?;
            assert!(matches!(
                error,
                ClientError::Kadmin(KadminError::UnauthenticatedSuccess)
            ));
            Ok::<_, Box<dyn Error>>(())
        })
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
                feature = "evaluation",
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
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
            ),
            all(
                feature = "default",
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                feature = "serde",
                feature = "spnego",
                feature = "tokio",
                not(feature = "tower"),
                test
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                feature = "messages",
                not(feature = "serde"),
                not(feature = "spnego"),
                feature = "tokio",
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::expect_used,
            clippy::shadow_unrelated,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Pins that a configured kpasswd exchange returns the server failure result with its raw text.
    #[test]
    fn tokio_transport_exchanges_configured_kpasswd_failure_result() -> Result<(), Box<dyn Error>> {
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kpasswd_servers([addr.to_string()], 1465);
            let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ))?;
            let expected_request = request.encode()?;
            let response = kpasswd_reply_frame(
                0,
                &kpasswd_result_krb_error(KPASSWD_AUTHERROR, "authentication failed"),
            );
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await;
                assert_eq!(request, expected_request);
                write_tcp_response(&mut socket, &response).await;
            });

            let error = TokioKdcTransport::new()
                .with_timeout(Duration::from_secs(2))
                .exchange_kpasswd_result_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    "TEST.GOKRB5",
                    &request,
                    &reply_key(),
                )
                .await
                .expect_err("non-zero kpasswd result returns error");

            task.await?;
            assert!(matches!(
                error,
                ClientError::Kadmin(KadminError::PasswordChangeFailed { code, text, text_raw: _ })
                    if code == KPASSWD_AUTHERROR && text == "authentication failed"
            ));
            Ok::<_, Box<dyn Error>>(())
        })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::as_conversions,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_tries_next_configured_kdc_after_tcp_failure() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kdcs(["127.0.0.1:9".to_owned(), addr.to_string()]);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept client");
            let mut header = [0; 4];
            socket
                .read_exact(&mut header)
                .await
                .expect("read request length");
            let request_len = u32::from_be_bytes(header) as usize;
            let mut request = vec![0; request_len];
            socket.read_exact(&mut request).await.expect("read request");
            assert_eq!(request, b"fallback-tcp-as-req");

            socket
                .write_all(&(19_u32).to_be_bytes())
                .await
                .expect("write response length");
            socket
                .write_all(b"fallback-tcp-as-rep")
                .await
                .expect("write response");
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                b"fallback-tcp-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"fallback-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_auto_retries_tcp_after_udp_response_too_big() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = udp.local_addr()?;
        let listener = TcpListener::bind(addr).await?;

        let udp_task = tokio::spawn(async move {
            let mut request = [0; 64];
            let (len, peer) = udp.recv_from(&mut request).await.expect("receive UDP");
            assert_eq!(&request[..len], b"auto-as-req");
            udp.send_to(&response_too_big_error(), peer)
                .await
                .expect("send UDP KRB-ERROR");
        });
        let tcp_task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"auto-as-req");
            write_tcp_response(&mut socket, b"auto-tcp-as-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send(KdcProtocol::Auto, addr, b"auto-as-req")
            .await?;

        udp_task.await?;
        tcp_task.await?;
        assert_eq!(response, b"auto-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_auto_honors_tcp_only_udp_preference_limit() -> Result<(), Box<dyn Error>> {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kdcs_and_udp_limit([addr.to_string()], 1);
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"auto-config-as-req");
            write_tcp_response(&mut socket, b"auto-config-tcp-as-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Auto,
                "TEST.GOKRB5",
                b"auto-config-as-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"auto-config-tcp-as-rep");
        Ok::<_, Box<dyn Error>>(())
    })
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn tokio_transport_auto_kpasswd_honors_tcp_only_udp_preference_limit() -> Result<(), Box<dyn Error>>
{
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1);
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await;
            assert_eq!(request, b"auto-kpasswd-req");
            write_tcp_response(&mut socket, b"auto-kpasswd-tcp-rep").await;
        });

        let response = TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_kpasswd_realm(
                &config,
                KdcProtocol::Auto,
                "TEST.GOKRB5",
                b"auto-kpasswd-req",
            )
            .await?;

        task.await?;
        assert_eq!(response, b"auto-kpasswd-tcp-rep");
        Ok::<_, Box<dyn Error>>(())
    })
}

fn config_with_kdcs<I>(kdcs: I) -> Config
where
    I: IntoIterator<Item = String>,
{
    config_with_kdcs_and_udp_limit(kdcs, 1465)
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
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
fn config_with_kdcs_and_udp_limit<I>(kdcs: I, udp_preference_limit: i32) -> Config
where
    I: IntoIterator<Item = String>,
{
    let mut input = String::from(
        r#"
[libdefaults]
 dns_lookup_kdc = false
"#,
    );
    input.push_str(" udp_preference_limit = ");
    input.push_str(&udp_preference_limit.to_string());
    input.push_str(
        r#"

[realms]
 TEST.GOKRB5 = {
"#,
    );
    for kdc in kdcs {
        input.push_str("  kdc = ");
        input.push_str(&kdc);
        input.push('\n');
    }
    input.push_str(" }\n");
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
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
fn config_with_kpasswd_servers<I>(servers: I, udp_preference_limit: i32) -> Config
where
    I: IntoIterator<Item = String>,
{
    let mut input = String::from(
        r#"
[libdefaults]
 dns_lookup_kdc = false
"#,
    );
    input.push_str(" udp_preference_limit = ");
    input.push_str(&udp_preference_limit.to_string());
    input.push_str(
        r#"

[realms]
 TEST.GOKRB5 = {
"#,
    );
    for server in servers {
        input.push_str("  kpasswd_server = ");
        input.push_str(&server);
        input.push('\n');
    }
    input.push_str(" }\n");
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::as_conversions,
        clippy::expect_used,
        clippy::missing_panics_doc,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
async fn read_tcp_request(listener: &TcpListener) -> (Vec<u8>, tokio::net::TcpStream) {
    let (mut socket, _) = listener.accept().await.expect("accept client");
    let mut header = [0; 4];
    socket
        .read_exact(&mut header)
        .await
        .expect("read request length");
    let request_len = u32::from_be_bytes(header) as usize;
    let mut request = vec![0; request_len];
    socket.read_exact(&mut request).await.expect("read request");
    (request, socket)
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
async fn write_tcp_response(socket: &mut tokio::net::TcpStream, response: &[u8]) {
    socket
        .write_all(&(response.len() as u32).to_be_bytes())
        .await
        .expect("write response length");
    socket.write_all(response).await.expect("write response");
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::default_numeric_fallback,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn response_too_big_error() -> Vec<u8> {
    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code: KRB_ERR_RESPONSE_TOO_BIG,
        crealm: None,
        cname: None,
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&["krbtgt", "TEST.GOKRB5"]),
        e_text: Some(kerberos_string("response too big")),
        e_data: None,
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::arithmetic_side_effects,
        clippy::default_numeric_fallback,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn kpasswd_result_krb_error(code: u16, text: &str) -> Vec<u8> {
    let mut e_data = Vec::with_capacity(2 + text.len());
    e_data.extend_from_slice(&code.to_be_bytes());
    e_data.extend_from_slice(text.as_bytes());

    let error = rasn_kerberos::KrbError {
        pvno: rasn::types::Integer::from(5),
        msg_type: rasn::types::Integer::from(30),
        ctime: None,
        cusec: None,
        stime: kerberos_time(1_893_553_440),
        susec: rasn::types::Integer::from(0),
        error_code: KRB_ERR_RESPONSE_TOO_BIG,
        crealm: None,
        cname: None,
        realm: realm("TEST.GOKRB5"),
        sname: rasn_principal(&["kadmin", "changepw"]),
        e_text: Some(kerberos_string(text)),
        e_data: Some(e_data.into()),
    };
    rasn::der::encode(&error).expect("KRB-ERROR encodes")
}

fn reply_key() -> EncryptionKey {
    EncryptionKey {
        etype: 18,
        value: vec![0; 32],
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::assertions_on_result_states,
        clippy::cast_possible_truncation,
        clippy::missing_assert_message,
        clippy::missing_panics_doc,
        clippy::unseparated_literal_suffix,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Vec<u8> {
    let message_length = KPASSWD_HEADER_LEN + body.len();
    assert!(u16::try_from(message_length).is_ok());

    let mut frame = Vec::with_capacity(message_length);
    frame.extend_from_slice(&(message_length as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&ap_rep_length.to_be_bytes());
    frame.extend_from_slice(body);
    frame
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::default_numeric_fallback,
        clippy::integer_division_remainder_used,
        clippy::missing_panics_doc,
        clippy::shadow_reuse,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = hex_nibble(pair[0]);
            let lo = hex_nibble(pair[1]);
            (hi << 4) | lo
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
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
fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit: {value}"),
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
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
fn kerberos_time(seconds: i64) -> rasn_kerberos::KerberosTime {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0).expect("valid time");
    let offset = chrono::FixedOffset::east_opt(0).expect("UTC offset exists");
    rasn_kerberos::KerberosTime(utc.with_timezone(&offset))
}

fn rasn_principal(components: &[&str]) -> rasn_kerberos::PrincipalName {
    rasn_kerberos::PrincipalName {
        r#type: 2,
        string: components
            .iter()
            .map(|component| kerberos_string(component))
            .collect(),
    }
}

fn realm(value: &str) -> rasn_kerberos::Realm {
    kerberos_string(value)
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
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
fn kerberos_string(value: &str) -> rasn_kerberos::KerberosString {
    rasn_kerberos::KerberosString::try_from(value).expect("valid KerberosString")
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
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
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
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
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
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("runtime")
}

/// Fork-authored transport tests: the unsigned kpasswd success result, TCP
/// stream reuse for the preauthentication retry, and the live KDC probe.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod fork_tests {
    use core::{fmt, net::SocketAddr};
    use std::{
        env,
        io::{self, Write as _},
        time::{Instant, SystemTime},
    };

    use rasn::{der, types::Integer};
    use rskrb5_ng::client::Error as ClientError;
    use tokio::{net::TcpStream, time::timeout};

    use super::*;

    /// Error type of these tests; `Send` so stub KDC tasks can return it.
    type TestError = Box<dyn Error + Send + Sync>;

    /// Pins that a TCP login sends the preauthentication retry on the first connection.
    #[test]
    fn tcp_login_reuses_one_connection_for_the_preauth_retry() -> Result<(), TestError> {
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                let first = read_framed(&mut socket).await?;
                write_framed(&mut socket, &preauth_required_error()?).await?;
                let second = read_framed(&mut socket).await?;
                write_framed(&mut socket, b"not-an-as-rep").await?;
                let reconnected = timeout(Duration::from_millis(250), listener.accept())
                    .await
                    .is_ok();
                Ok::<_, TestError>((first.len(), second.len(), reconnected))
            });

            // The stub second reply is not a decodable AS-REP, so the login fails.
            // The connection count is what is under test, not the login outcome.
            drop(login_over_tcp(addr).await.err());

            let (first_len, second_len, reconnected) = server.await??;
            assert!(first_len > 0, "KDC received the bare AS-REQ");
            assert!(
                second_len > 0,
                "KDC received the preauth retry on the same connection"
            );
            assert!(
                !reconnected,
                "preauth retry must not open a second connection"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Pins that after the UDP fall-back to TCP the preauthentication retry reuses that stream.
    #[test]
    fn auto_login_reuses_the_stream_after_the_udp_fall_back_to_tcp() -> Result<(), TestError> {
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                let first = read_framed(&mut socket).await?;
                write_framed(&mut socket, &preauth_required_error()?).await?;
                let second = read_framed(&mut socket).await?;
                write_framed(&mut socket, b"not-an-as-rep").await?;
                let reconnected = timeout(Duration::from_millis(250), listener.accept())
                    .await
                    .is_ok();
                Ok::<_, TestError>((first.len(), second.len(), reconnected))
            });

            // No UDP socket answers on this port, so the Auto leg falls back to
            // TCP; the retry must ride that same connection.
            drop(login_over(addr, KdcProtocol::Auto).await.err());

            let (first_len, second_len, reconnected) = server.await??;
            assert!(
                first_len > 0,
                "KDC received the AS-REQ after the UDP fallback"
            );
            assert!(second_len > 0, "preauth retry must ride the pinned stream");
            assert!(
                !reconnected,
                "preauth retry must not open a second connection"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a retry after the KDC closed the stream opens a fresh connection.
    #[test]
    fn tcp_login_reconnects_when_the_kdc_closes_the_stream() -> Result<(), TestError> {
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                drop(read_framed(&mut socket).await?);
                write_framed(&mut socket, &preauth_required_error()?).await?;
                // RFC 4120 section 7.2.2 allows the KDC to close here.
                drop(socket);

                let (mut retry_socket, _) = listener.accept().await?;
                let retry = read_framed(&mut retry_socket).await?;
                write_framed(&mut retry_socket, b"not-an-as-rep").await?;
                Ok::<_, TestError>(retry.len())
            });

            drop(login_over_tcp(addr).await.err());

            let retry_len = server.await??;
            assert!(
                retry_len > 0,
                "closed stream must be retried on a fresh connection"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Probe whether a live KDC leaves the TCP stream open for a follow-up request.
    ///
    /// RFC 4120 section 7.2.2 permits a KDC either to close the stream after a
    /// response or to keep it open for a follow-up, so the behaviour of any given
    /// KDC has to be measured. Sends two bare AS-REQs on one stream and reports
    /// whether the second is answered.
    ///
    /// Gated on `TEST_KDC_REUSE=1`. Reads `TEST_KDC_ADDR`, `TEST_KDC_PORT`,
    /// `TEST_KDC_REALM` and `TEST_KDC_USER`. Needs no credentials: a bare AS-REQ
    /// carries no preauthentication data and is answered with KRB-ERROR.
    #[test]
    fn live_kdc_tcp_stream_reuse_probe() -> Result<(), TestError> {
        if env::var("TEST_KDC_REUSE").as_deref() != Ok("1") {
            return Ok(());
        }

        let host = env::var("TEST_KDC_ADDR").map_err(|cause| format!("TEST_KDC_ADDR: {cause}"))?;
        let port: u16 = env::var("TEST_KDC_PORT")
            .unwrap_or_else(|_| "88".to_owned())
            .parse()?;
        let realm =
            env::var("TEST_KDC_REALM").map_err(|cause| format!("TEST_KDC_REALM: {cause}"))?;
        let user = env::var("TEST_KDC_USER").map_err(|cause| format!("TEST_KDC_USER: {cause}"))?;

        runtime().block_on(async {
            let connect_start = Instant::now();
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            stream.set_nodelay(true)?;
            writeln!(
                io::stdout(),
                "handshake: {} ms",
                connect_start.elapsed().as_millis()
            )?;

            let first_start = Instant::now();
            let first = probe_exchange(&mut stream, &realm, &user, 1).await?;
            writeln!(
                io::stdout(),
                "request 1: {first} in {} ms",
                first_start.elapsed().as_millis()
            )?;
            assert!(
                matches!(
                    first,
                    ProbeOutcome::Answered {
                        len: _,
                        error_code: _
                    }
                ),
                "first exchange must reach the KDC: {first}"
            );

            let second_start = Instant::now();
            let second = probe_exchange(&mut stream, &realm, &user, 2).await?;
            writeln!(
                io::stdout(),
                "request 2: {second} in {} ms",
                second_start.elapsed().as_millis()
            )?;
            match &second {
                ProbeOutcome::Answered {
                    len: _,
                    error_code: _,
                } => writeln!(
                    io::stdout(),
                    "VERDICT: KDC reuses the stream; pinning the connection is worthwhile"
                )?,
                ProbeOutcome::Closed(reason) => writeln!(
                    io::stdout(),
                    "VERDICT: KDC closed the stream ({reason}); pinning gains nothing against this KDC"
                )?,
            }
            Ok::<_, TestError>(())
        })
    }

    /// Drive a password TGT login over TCP against a stub KDC.
    async fn login_over_tcp(addr: SocketAddr) -> Result<(), ClientError> {
        login_over(addr, KdcProtocol::Tcp).await
    }

    /// Drive a password TGT login over the given protocol against a stub KDC.
    async fn login_over(addr: SocketAddr, protocol: KdcProtocol) -> Result<(), ClientError> {
        let options = AsReqOptions::new(SystemTime::now(), 1);
        TokioKdcTransport::new()
            .with_timeout(Duration::from_secs(2))
            .login_tgt_with_password(
                protocol,
                addr,
                Principal::user("TEST.GOKRB5", "testuser1"),
                b"password",
                options,
            )
            .await
            .map(|_| ())
    }

    /// Read one RFC 4120 framed message from a stub KDC connection.
    async fn read_framed(socket: &mut TcpStream) -> Result<Vec<u8>, TestError> {
        let mut header = [0; 4];
        let _: usize = socket.read_exact(&mut header).await?;
        let mut body = vec![0; usize::try_from(u32::from_be_bytes(header))?];
        let _: usize = socket.read_exact(&mut body).await?;
        Ok(body)
    }

    /// Write one RFC 4120 framed message from a stub KDC connection.
    async fn write_framed(socket: &mut TcpStream, body: &[u8]) -> Result<(), TestError> {
        socket
            .write_all(&u32::try_from(body.len())?.to_be_bytes())
            .await?;
        socket.write_all(body).await?;
        Ok(())
    }

    /// Build a `KDC_ERR_PREAUTH_REQUIRED` carrying an ETYPE-INFO2 hint for AES256.
    ///
    /// Drives the client into the second phase of the AS exchange, which is the
    /// request that should reuse the connection.
    fn preauth_required_error() -> Result<Vec<u8>, TestError> {
        let etype_info2 = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: 18,
            salt: Some(kerberos_string("TEST.GOKRB5testuser1")),
            s2kparams: None,
        }]);
        let method_data = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
            r#type: PA_ETYPE_INFO2,
            value: der::encode(&etype_info2)
                .map_err(|cause| format!("ETYPE-INFO2 encodes: {cause}"))?
                .into(),
        }]);
        let error = rasn_kerberos::KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440),
            susec: Integer::from(0_i32),
            error_code: 25,
            crealm: Some(realm("TEST.GOKRB5")),
            cname: Some(rasn_principal(&["testuser1"])),
            realm: realm("TEST.GOKRB5"),
            sname: rasn_principal(&["krbtgt", "TEST.GOKRB5"]),
            e_text: None,
            e_data: Some(
                der::encode(&method_data)
                    .map_err(|cause| format!("METHOD-DATA encodes: {cause}"))?
                    .into(),
            ),
        };
        Ok(der::encode(&error).map_err(|cause| format!("KRB-ERROR encodes: {cause}"))?)
    }

    /// Result of one framed request/response attempt against a live KDC.
    enum ProbeOutcome {
        /// KDC answered. Carries the response length and KRB-ERROR code when present.
        Answered { len: usize, error_code: Option<i32> },
        /// KDC did not answer and the stream is unusable.
        Closed(String),
    }

    impl fmt::Display for ProbeOutcome {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Answered {
                    len,
                    error_code: Some(code),
                } => write!(f, "answered, {len} bytes, error code {code}"),
                Self::Answered {
                    len,
                    error_code: None,
                } => write!(f, "answered, {len} bytes, no error code"),
                Self::Closed(reason) => write!(f, "closed: {reason}"),
            }
        }
    }

    /// Send one bare AS-REQ on an existing stream and classify the outcome.
    async fn probe_exchange(
        stream: &mut TcpStream,
        realm: &str,
        user: &str,
        nonce: u32,
    ) -> Result<ProbeOutcome, TestError> {
        let client = Principal::user(realm, user);
        let request = build_tgt_as_req(client, AsReqOptions::new(SystemTime::now(), nonce))?;

        let mut framed = Vec::with_capacity(request.der.len().saturating_add(4));
        framed.extend_from_slice(&u32::try_from(request.der.len())?.to_be_bytes());
        framed.extend_from_slice(&request.der);
        if let Err(error) = stream.write_all(&framed).await {
            return Ok(ProbeOutcome::Closed(format!("write failed: {error}")));
        }

        let mut header = [0; 4];
        if let Err(error) = stream.read_exact(&mut header).await {
            return Ok(ProbeOutcome::Closed(format!(
                "no response length: {} ({error})",
                error.kind()
            )));
        }

        let mut response = vec![0; usize::try_from(u32::from_be_bytes(header))?];
        if let Err(error) = stream.read_exact(&mut response).await {
            return Ok(ProbeOutcome::Closed(format!(
                "truncated response: {} ({error})",
                error.kind()
            )));
        }

        Ok(ProbeOutcome::Answered {
            len: response.len(),
            error_code: krb_error_code(&response),
        })
    }

    /// Read the `error-code` field out of a DER-encoded KRB-ERROR, if the response is one.
    fn krb_error_code(response: &[u8]) -> Option<i32> {
        der::decode::<rasn_kerberos::KrbError>(response)
            .ok()
            .map(|error| error.error_code)
    }
}
