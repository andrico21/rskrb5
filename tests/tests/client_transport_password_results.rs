//! Checked password result regressions.

use super::*;

/// Pins that a kpasswd KRB-ERROR carrying a success result code is rejected as unauthenticated.
#[test]
fn tokio_transport_rejects_unauthenticated_kpasswd_success_result() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        let expected_request = request.encode()?;
        let response = kpasswd_reply_frame(
            0,
            &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed")?,
        )?;
        let task = tokio::spawn(async move {
            let (received, mut socket) = read_tcp_request(&listener).await?;
            assert_eq!(received, expected_request);
            write_tcp_response(&mut socket, &response).await
        });

        let error = Tokio::new()
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

        task.await??;
        assert!(matches!(
            error,
            ClientError::Kadmin(KadminError::UnauthenticatedSuccess)
        ));
        Ok::<_, TestError>(())
    })
}

/// Pins that a configured kpasswd exchange returns the server failure result with its raw text.
#[test]
fn tokio_transport_exchanges_configured_kpasswd_failure_result() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        let expected_request = request.encode()?;
        let response = kpasswd_reply_frame(
            0,
            &kpasswd_result_krb_error(KPASSWD_AUTHERROR, "authentication failed")?,
        )?;
        let task = tokio::spawn(async move {
            let (received, mut socket) = read_tcp_request(&listener).await?;
            assert_eq!(received, expected_request);
            write_tcp_response(&mut socket, &response).await
        });

        let error = Tokio::new()
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
            .ok_or("non-zero kpasswd result returns error")?;

        task.await??;
        assert!(matches!(
            error,
            ClientError::Kadmin(KadminError::PasswordChangeFailed { code, text, text_raw: _ })
                if code == KPASSWD_AUTHERROR && text == "authentication failed"
        ));
        Ok::<_, TestError>(())
    })
}
