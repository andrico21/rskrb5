use super::*;

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn builds_kpasswd_request_with_subkey_encrypted_payload() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let reply_key = EncryptionKey {
        etype: 18,
        value: vec![0x55; 32],
    };
    let change_data = ChangePasswdData::for_target(b"newpassword", 1, ["testuser1"], "TEST.GOKRB5")
        .expect("ChangePasswdData builds");

    let built = build_kpasswd_request_with_confounders(
        &service_ticket,
        &change_data,
        reply_key.clone(),
        KpasswdRequestOptions::new(
            timestamp(1_893_553_452),
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        ),
        &decode_hex(TGS_REQ_CONFOUNDER),
        &decode_hex(PREAUTH_CONFOUNDER),
    )
    .expect("kpasswd request builds");

    assert_eq!(built.reply_key, reply_key);
    assert_eq!(built.der, built.request.encode().expect("request encodes"));
    let parsed = KpasswdRequest::parse(&built.der).expect("request parses");
    assert_eq!(parsed.ap_req, built.request.ap_req);
    assert_eq!(parsed.krb_priv, built.request.krb_priv);

    let authenticator_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &service_ticket.session_key.value,
            parsed.ap_req.authenticator.cipher.as_ref(),
            AP_REQ_AUTHENTICATOR_USAGE,
        )
        .expect("AP-REQ authenticator decrypts");
    let authenticator: rasn_kerberos::Authenticator =
        rasn::der::decode(&authenticator_bytes).expect("Authenticator decodes");
    let subkey = authenticator.subkey.expect("authenticator subkey");
    assert_eq!(subkey.r#type, reply_key.etype);
    assert_eq!(subkey.value.as_ref(), reply_key.value.as_slice());
    assert_eq!(authenticator.seq_number, Some(42));

    let krb_priv_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &reply_key.value,
            parsed.krb_priv.enc_part.cipher.as_ref(),
            KRB_PRIV_ENCPART_USAGE,
        )
        .expect("KRB-PRIV decrypts");
    let enc_part: rasn_kerberos::EncKrbPrivPart =
        rasn::der::decode(&krb_priv_bytes).expect("EncKrbPrivPart decodes");
    let decoded_change_data =
        ChangePasswdData::decode_der(enc_part.user_data.as_ref()).expect("payload decodes");

    assert_eq!(decoded_change_data, change_data);
    assert_eq!(enc_part.seq_number, Some(42));
    assert_eq!(
        enc_part
            .usec
            .expect("KRB-PRIV usec")
            .to_string()
            .parse::<u32>()
            .expect("usec parses"),
        456_789
    );
    assert_eq!(
        system_time_from_kerberos_time(enc_part.timestamp.as_ref().expect("KRB-PRIV timestamp")),
        timestamp(1_893_553_452)
    );
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn builds_kpasswd_request_with_generated_reply_key() {
    let tgt = sample_tgt_session();
    let request = sample_tgs_request(&tgt);
    let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
    let service_ticket =
        process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
    let change_data = ChangePasswdData::new(b"newpassword");

    let built = build_kpasswd_request(
        &service_ticket,
        &change_data,
        KpasswdRequestOptions::new(
            timestamp(1_893_553_452),
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        ),
    )
    .expect("kpasswd request builds");
    let parsed = KpasswdRequest::parse(&built.der).expect("request parses");

    assert_eq!(built.reply_key.etype, service_ticket.session_key.etype);
    assert_eq!(built.reply_key.value.len(), 32);

    let krb_priv_bytes = AesSha1Etype::Aes256
        .decrypt_message(
            &built.reply_key.value,
            parsed.krb_priv.enc_part.cipher.as_ref(),
            KRB_PRIV_ENCPART_USAGE,
        )
        .expect("KRB-PRIV decrypts");
    let enc_part: rasn_kerberos::EncKrbPrivPart =
        rasn::der::decode(&krb_priv_bytes).expect("EncKrbPrivPart decodes");
    let decoded_change_data =
        ChangePasswdData::decode_der(enc_part.user_data.as_ref()).expect("payload decodes");

    assert_eq!(decoded_change_data, change_data);
    assert_eq!(enc_part.seq_number, Some(42));
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn verifies_kpasswd_reply_ap_rep_timestamp() {
    let built = sample_built_kpasswd_request();
    let ap_rep = kpasswd_ap_rep(&built, 456_789);
    let reply = KpasswdReply::parse(&kpasswd_reply_with_ap_rep(&built, &ap_rep))
        .expect("kpasswd reply parses");

    let verified = verify_kpasswd_ap_rep(&reply, &built)
        .expect("AP-REP verifies")
        .expect("successful reply has AP-REP");

    assert_eq!(verified.ctime, timestamp(1_893_553_452));
    assert_eq!(verified.cusec, 456_789);
    assert_eq!(verified.sequence_number, Some(99));
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::rest_pattern_accessible_field,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn rejects_kpasswd_reply_ap_rep_timestamp_mismatch() {
    let built = sample_built_kpasswd_request();
    let ap_rep = kpasswd_ap_rep(&built, 456_790);
    let reply = KpasswdReply::parse(&kpasswd_reply_with_ap_rep(&built, &ap_rep))
        .expect("kpasswd reply parses");

    assert!(matches!(
        verify_kpasswd_ap_rep(&reply, &built).expect_err("timestamp mismatch is rejected"),
        Error::KpasswdApRepTimestampMismatch { .. }
    ));
}

/// `TokioClient` password change through a cached `kadmin/changepw` ticket.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tokio_cached_changepw {
    use super::*;

    #[expect(
        clippy::absolute_paths,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::default_numeric_fallback,
        clippy::duration_suboptimal_units,
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::shadow_unrelated,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins a password change through a cached `kadmin/changepw` ticket against an authenticated reply.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_password_with_cached_changepw_ticket() -> Result<(), TestError> {
        runtime().block_on(async {
            let tgt = sample_tgt_session();
            let changepw = change_password_principal();
            let request = build_tgs_req_with_confounder(
                &tgt,
                changepw,
                TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
                timestamp(1_893_553_451),
                654_321,
                &decode_hex(TGS_REQ_CONFOUNDER),
            )
            .expect("changepw TGS-REQ builds");
            let tgs_rep = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
            let mut changepw_ticket = process_tgs_rep(&request, &tgs_rep, &tgt.session_key)
                .map_err(|cause| format!("TGS-REP validates: {cause}"))?;
            let now = SystemTime::now();
            changepw_ticket.start_time = now
                .checked_sub(Duration::from_secs(60))
                .expect("start time");
            changepw_ticket.end_time = now
                .checked_add(Duration::from_secs(60 * 60))
                .expect("end time");
            changepw_ticket.renew_till = Some(
                now.checked_add(Duration::from_secs(2 * 60 * 60))
                    .expect("renew time"),
            );
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kpasswd listener");
            let addr = listener.local_addr().expect("local listener address");
            let mut client = TokioClient::from_tgt_session(
                config_with_kpasswd_server(addr.to_string()),
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(changepw_ticket);
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
                let parsed = KpasswdRequest::parse(&request).expect("kpasswd request parses");
                assert_eq!(parsed.ap_req.msg_type, rasn::types::Integer::from(14));
                assert_eq!(parsed.krb_priv.msg_type, rasn::types::Integer::from(21));

                let session_key = EncryptionKey {
                    etype: 18,
                    value: decode_hex(SERVICE_SESSION_KEY),
                };
                let response = kpasswd_authenticated_success_reply(&request, &session_key, 0x77);
                socket
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .await
                    .expect("write response length");
                socket.write_all(&response).await.expect("write response");
            });

            let result = client
                .change_password_with_options(
                    b"newpassword",
                    KpasswdRequestOptions::new(
                        timestamp(1_893_553_452),
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .expect("change password succeeds");

            task.await.expect("kpasswd listener task completes");
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok(())
        })
    }
}

#[expect(
    clippy::absolute_paths,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::default_numeric_fallback,
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    unused_results,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[cfg(feature = "tokio")]
#[test]
fn tokio_client_changes_password_uses_kpasswd_ap_rep_subkey_for_result() {
    runtime().block_on(async {
        let tgt = sample_tgt_session();
        let changepw = change_password_principal();
        let request = build_tgs_req_with_confounder(
            &tgt,
            changepw,
            TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
            timestamp(1_893_553_451),
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER),
        )
        .expect("changepw TGS-REQ builds");
        let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
        let mut changepw_ticket =
            process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
        let now = SystemTime::now();
        changepw_ticket.start_time = now
            .checked_sub(Duration::from_secs(60))
            .expect("start time");
        changepw_ticket.end_time = now
            .checked_add(Duration::from_secs(60 * 60))
            .expect("end time");
        changepw_ticket.renew_till = Some(
            now.checked_add(Duration::from_secs(2 * 60 * 60))
                .expect("renew time"),
        );
        let changepw_session_key = changepw_ticket.session_key.clone();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local kpasswd listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kpasswd_server(addr.to_string()),
            KdcProtocol::Tcp,
            tgt,
        );
        client.cache_service_ticket(changepw_ticket);
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
            let parsed = KpasswdRequest::parse(&request).expect("kpasswd request parses");
            let authenticator = rskrb5_ng::ap_req::decrypt_ap_req_authenticator(
                &parsed.ap_req,
                &changepw_session_key,
                AP_REQ_AUTHENTICATOR_USAGE,
            )
            .expect("AP-REQ authenticator decrypts");
            let response_key = EncryptionKey {
                etype: 18,
                value: vec![0x66; 32],
            };
            let response = kpasswd_success_reply_with_ap_rep_subkey(
                &authenticator,
                &changepw_session_key,
                &response_key,
                KPASSWD_SUCCESS,
                "password changed",
            );
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write response length");
            socket.write_all(&response).await.expect("write response");
        });

        let result = client
            .change_password_with_options(
                b"newpassword",
                KpasswdRequestOptions::new(
                    timestamp(1_893_553_452),
                    456_789,
                    42,
                    ipv4_host_address([127, 0, 0, 1]),
                ),
            )
            .await
            .expect("change password succeeds");

        task.await.expect("kpasswd listener task completes");
        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert_eq!(result.text, "password changed");
    });
}

#[expect(
    clippy::absolute_paths,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::default_numeric_fallback,
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    unused_results,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[cfg(feature = "tokio")]
#[test]
fn tokio_client_changes_explicit_target_password() {
    runtime().block_on(async {
        let tgt = sample_tgt_session();
        let changepw = change_password_principal();
        let request = build_tgs_req_with_confounder(
            &tgt,
            changepw,
            TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
            timestamp(1_893_553_451),
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER),
        )
        .expect("changepw TGS-REQ builds");
        let response = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
        let mut changepw_ticket =
            process_tgs_rep(&request, &response, &tgt.session_key).expect("TGS-REP validates");
        let now = SystemTime::now();
        changepw_ticket.start_time = now
            .checked_sub(Duration::from_secs(60))
            .expect("start time");
        changepw_ticket.end_time = now
            .checked_add(Duration::from_secs(60 * 60))
            .expect("end time");
        changepw_ticket.renew_till = Some(
            now.checked_add(Duration::from_secs(2 * 60 * 60))
                .expect("renew time"),
        );
        let changepw_session_key = changepw_ticket.session_key.clone();
        let target = Principal::new("TEST.GOKRB5", 1, ["other-user"]);
        let target_for_server = target.clone();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local kpasswd listener");
        let addr = listener.local_addr().expect("local listener address");
        let mut client = TokioClient::from_tgt_session(
            config_with_kpasswd_server(addr.to_string()),
            KdcProtocol::Tcp,
            tgt,
        );
        client.cache_service_ticket(changepw_ticket);
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
            let parsed = KpasswdRequest::parse(&request).expect("kpasswd request parses");
            let authenticator = rskrb5_ng::ap_req::decrypt_ap_req_authenticator(
                &parsed.ap_req,
                &changepw_session_key,
                AP_REQ_AUTHENTICATOR_USAGE,
            )
            .expect("AP-REQ authenticator decrypts");
            let reply_key = EncryptionKey {
                etype: authenticator
                    .subkey
                    .as_ref()
                    .expect("AP-REQ reply key included")
                    .r#type,
                value: authenticator
                    .subkey
                    .as_ref()
                    .expect("AP-REQ reply key included")
                    .value
                    .as_ref()
                    .to_vec(),
            };
            let enc_part =
                rskrb5_ng::kadmin::decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key)
                    .expect("KRB-PRIV payload decrypts");
            let change_data = ChangePasswdData::decode_der(enc_part.user_data.as_ref())
                .expect("ChangePasswdData decodes");
            assert_eq!(
                principal_from_parts(
                    change_data.targ_realm.as_ref().expect("target realm set"),
                    change_data
                        .targ_name
                        .as_ref()
                        .expect("target principal name set"),
                ),
                target_for_server
            );
            assert_eq!(change_data.new_passwd.to_vec(), b"newpassword".to_vec());
            let response = kpasswd_success_reply_with_ap_rep_subkey(
                &authenticator,
                &changepw_session_key,
                &changepw_session_key,
                KPASSWD_SUCCESS,
                "password changed",
            );
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write response length");
            socket.write_all(&response).await.expect("write response");
        });

        let result = client
            .change_password_for_with_options(
                target.clone(),
                b"newpassword",
                KpasswdRequestOptions::new(
                    timestamp(1_893_553_452),
                    456_789,
                    42,
                    ipv4_host_address([127, 0, 0, 1]),
                ),
            )
            .await
            .expect("change target password succeeds");

        task.await.expect("kpasswd listener task completes");
        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert_eq!(result.text, "password changed");
    });
}

/// `NegotiateClient` password change through a cached `kadmin/changepw` ticket.
#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod negotiate_cached_changepw {
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
            )
        ),
        expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::default_numeric_fallback,
            clippy::duration_suboptimal_units,
            clippy::expect_used,
            clippy::let_underscore_untyped,
            clippy::missing_panics_doc,
            clippy::shadow_reuse,
            clippy::shadow_unrelated,
            let_underscore_drop,
            unused_results,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    /// Pins a `NegotiateClient` password change through a cached `kadmin/changepw` ticket.
    #[test]
    fn negotiate_client_changes_password_with_cached_changepw_ticket() -> Result<(), TestError> {
        runtime().block_on(async {
            let tgt = sample_tgt_session();
            let changepw = change_password_principal();
            let request = build_tgs_req_with_confounder(
                &tgt,
                changepw,
                TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
                timestamp(1_893_553_451),
                654_321,
                &decode_hex(TGS_REQ_CONFOUNDER),
            )
            .expect("changepw TGS-REQ builds");
            let tgs_rep = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
            let mut changepw_ticket = process_tgs_rep(&request, &tgs_rep, &tgt.session_key)
                .map_err(|cause| format!("TGS-REP validates: {cause}"))?;
            let now = SystemTime::now();
            changepw_ticket.start_time = now
                .checked_sub(Duration::from_secs(60))
                .expect("start time");
            changepw_ticket.end_time = now
                .checked_add(Duration::from_secs(60 * 60))
                .expect("end time");
            changepw_ticket.renew_till = Some(
                now.checked_add(Duration::from_secs(2 * 60 * 60))
                    .expect("renew time"),
            );

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kpasswd listener");
            let listener_addr = listener.local_addr().expect("local listener address");
            let mut client = TokioClient::from_tgt_session(
                config_with_kpasswd_server(listener_addr.to_string()),
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(changepw_ticket);
            let mut client = NegotiateClient::from_tokio_client(client);

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
                let _ = KpasswdRequest::parse(&request).expect("kpasswd request parses");

                let session_key = EncryptionKey {
                    etype: 18,
                    value: decode_hex(SERVICE_SESSION_KEY),
                };
                let response = kpasswd_authenticated_success_reply(&request, &session_key, 0x77);
                socket
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .await
                    .expect("write response length");
                socket.write_all(&response).await.expect("write response");
            });

            let result = client
                .change_password_with_options(
                    b"newpassword",
                    KpasswdRequestOptions::new(
                        timestamp(1_893_553_452),
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .expect("change password succeeds");

            task.await.expect("kpasswd listener task completes");
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok(())
        })
    }
}

/// `NegotiateClient` password change for an explicit target principal.
#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod negotiate_explicit_target {
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
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::default_numeric_fallback,
            clippy::duration_suboptimal_units,
            clippy::expect_used,
            clippy::missing_panics_doc,
            clippy::shadow_reuse,
            clippy::shadow_unrelated,
            clippy::too_many_lines,
            unused_results,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    /// Pins a `NegotiateClient` password change for an explicit target principal.
    #[test]
    fn negotiate_client_changes_explicit_target_password() -> Result<(), TestError> {
        runtime().block_on(async {
            let tgt = sample_tgt_session();
            let changepw = change_password_principal();
            let request = build_tgs_req_with_confounder(
                &tgt,
                changepw,
                TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
                timestamp(1_893_553_451),
                654_321,
                &decode_hex(TGS_REQ_CONFOUNDER),
            )
            .expect("changepw TGS-REQ builds");
            let tgs_rep = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
            let mut changepw_ticket = process_tgs_rep(&request, &tgs_rep, &tgt.session_key)
                .map_err(|cause| format!("TGS-REP validates: {cause}"))?;
            let now = SystemTime::now();
            changepw_ticket.start_time = now
                .checked_sub(Duration::from_secs(60))
                .expect("start time");
            changepw_ticket.end_time = now
                .checked_add(Duration::from_secs(60 * 60))
                .expect("end time");
            changepw_ticket.renew_till = Some(
                now.checked_add(Duration::from_secs(2 * 60 * 60))
                    .expect("renew time"),
            );

            let changepw_session_key = changepw_ticket.session_key.clone();
            let target = Principal::new("TEST.GOKRB5", 1, ["other-user"]);
            let target_for_server = target.clone();

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kpasswd listener");
            let addr = listener.local_addr().expect("local listener address");
            let mut client = TokioClient::from_tgt_session(
                config_with_kpasswd_server(addr.to_string()),
                KdcProtocol::Tcp,
                tgt,
            );
            client.cache_service_ticket(changepw_ticket);
            let mut client = NegotiateClient::from_tokio_client(client);

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
                let parsed = KpasswdRequest::parse(&request).expect("kpasswd request parses");
                let authenticator = rskrb5_ng::ap_req::decrypt_ap_req_authenticator(
                    &parsed.ap_req,
                    &changepw_session_key,
                    AP_REQ_AUTHENTICATOR_USAGE,
                )
                .expect("AP-REQ authenticator decrypts");
                let reply_key = EncryptionKey {
                    etype: authenticator
                        .subkey
                        .as_ref()
                        .expect("AP-REQ reply key included")
                        .r#type,
                    value: authenticator
                        .subkey
                        .as_ref()
                        .expect("AP-REQ reply key included")
                        .value
                        .as_ref()
                        .to_vec(),
                };
                let enc_part =
                    rskrb5_ng::kadmin::decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key)
                        .expect("KRB-PRIV payload decrypts");
                let change_data = ChangePasswdData::decode_der(enc_part.user_data.as_ref())
                    .expect("ChangePasswdData decodes");
                assert_eq!(
                    principal_from_parts(
                        change_data.targ_realm.as_ref().expect("target realm set"),
                        change_data
                            .targ_name
                            .as_ref()
                            .expect("target principal set"),
                    ),
                    target_for_server
                );
                assert_eq!(change_data.new_passwd.to_vec(), b"newpassword".to_vec());
                let response_key = EncryptionKey {
                    etype: 18,
                    value: vec![0x77; 32],
                };
                let response = kpasswd_success_reply_with_ap_rep_subkey(
                    &authenticator,
                    &changepw_session_key,
                    &response_key,
                    KPASSWD_SUCCESS,
                    "password changed",
                );
                socket
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .await
                    .expect("write response length");
                socket.write_all(&response).await.expect("write response");
            });

            let result = client
                .change_password_for_with_options(
                    target,
                    b"newpassword",
                    KpasswdRequestOptions::new(
                        timestamp(1_893_553_452),
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .expect("change target password succeeds");

            task.await.expect("kpasswd listener task completes");
            assert_eq!(result.code, KPASSWD_SUCCESS);
            assert_eq!(result.text, "password changed");
            Ok(())
        })
    }
}

/// `BlockingNegotiateClient` password change through a cached `kadmin/changepw` ticket.
#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "spnego"))]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod blocking_negotiate_cached_changepw {
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
            )
        ),
        expect(
            clippy::absolute_paths,
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::default_numeric_fallback,
            clippy::duration_suboptimal_units,
            clippy::expect_used,
            clippy::missing_panics_doc,
            clippy::shadow_reuse,
            clippy::shadow_unrelated,
            clippy::unused_trait_names,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    #[cfg(all(feature = "tokio", feature = "spnego"))]
    /// Pins a `BlockingNegotiateClient` password change through a cached `kadmin/changepw` ticket.
    #[test]
    fn blocking_negotiate_client_changes_password_with_cached_changepw_ticket()
    -> Result<(), TestError> {
        let tgt = sample_tgt_session();
        let changepw = change_password_principal();
        let request = build_tgs_req_with_confounder(
            &tgt,
            changepw,
            TgsReqOptions::new(timestamp(1_893_553_450), 0x2233_4455).with_etypes(vec![18]),
            timestamp(1_893_553_451),
            654_321,
            &decode_hex(TGS_REQ_CONFOUNDER),
        )
        .map_err(|cause| format!("changepw TGS-REQ builds: {cause}"))?;
        let tgs_rep = synthetic_tgs_rep(&request, request.nonce, &tgt.session_key);
        let mut changepw_ticket = process_tgs_rep(&request, &tgs_rep, &tgt.session_key)
            .map_err(|cause| format!("TGS-REP validates: {cause}"))?;
        let now = SystemTime::now();
        changepw_ticket.start_time = now
            .checked_sub(Duration::from_secs(60))
            .expect("start time");
        changepw_ticket.end_time = now
            .checked_add(Duration::from_secs(60 * 60))
            .expect("end time");
        changepw_ticket.renew_till = Some(
            now.checked_add(Duration::from_secs(2 * 60 * 60))
                .expect("renew time"),
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|cause| format!("bind local kpasswd listener: {cause}"))?;
        let listener_addr = listener
            .local_addr()
            .map_err(|cause| format!("local listener address: {cause}"))?;
        let mut client = TokioClient::from_tgt_session(
            config_with_kpasswd_server(listener_addr.to_string()),
            KdcProtocol::Tcp,
            tgt,
        );
        client.cache_service_ticket(changepw_ticket);
        let mut client = BlockingNegotiateClient::new(NegotiateClient::from_tokio_client(client))
            .map_err(|cause| {
            format!("blocking negotiate client wraps tokio client: {cause}")
        })?;

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};

            let (mut socket, _) = listener.accept().expect("accept client");
            let mut header = [0; 4];
            socket.read_exact(&mut header).expect("read request length");
            let request_len = u32::from_be_bytes(header) as usize;
            let mut request = vec![0; request_len];
            socket.read_exact(&mut request).expect("read request");
            let session_key = EncryptionKey {
                etype: 18,
                value: decode_hex(SERVICE_SESSION_KEY),
            };
            let response = kpasswd_authenticated_success_reply(&request, &session_key, 0x77);
            socket
                .write_all(&(response.len() as u32).to_be_bytes())
                .expect("write response length");
            socket.write_all(&response).expect("write response");
        });

        let result = client
            .change_password_with_options(
                b"newpassword",
                KpasswdRequestOptions::new(
                    timestamp(1_893_553_452),
                    456_789,
                    42,
                    ipv4_host_address([127, 0, 0, 1]),
                ),
            )
            .map_err(|cause| format!("change password succeeds: {cause}"))?;

        server
            .join()
            .map_err(|cause| format!("kpasswd listener task completes: {cause:?}"))?;
        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert_eq!(result.text, "password changed");
        Ok(())
    }
}

/// Credential handling of a password change for an explicit target.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod explicit_target_credentials {
    use super::*;

    #[expect(
        clippy::absolute_paths,
        clippy::default_numeric_fallback,
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::needless_raw_strings,
        clippy::too_many_lines,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that changing an explicit target's password keeps the client's own password credential.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_explicit_target_does_not_rotate_password_credentials()
    -> Result<(), TestError> {
        runtime().block_on(async {
            let old_password = b"old-passwordvalue";
            let new_password = b"new-passwordvalue";
            let self_client = Principal::user("TEST.GOKRB5", "testuser1");
            let explicit_target = Principal::new("TEST.GOKRB5", 1, ["other-user"]);
            let old_reply_key =
                derive_password_reply_key(&self_client, old_password, &password_key_info())
                    .expect("old reply key derives");
            let service_key = EncryptionKey {
                etype: 18,
                value: decode_hex(SESSION_KEY),
            };

            let kdc_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kdc listener");
            let kdc_addr = kdc_listener
                .local_addr()
                .expect("local kdc listener address");
            let kpasswd_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kpasswd listener");
            let kpasswd_addr = kpasswd_listener
                .local_addr()
                .expect("local kpasswd listener address");

            let config = Config::parse(&format!(
                r#"
[libdefaults]
dns_lookup_kdc = false
udp_preference_limit = 1

[realms]
TEST.GOKRB5 = {{
 kdc = {kdc_addr}
 kpasswd_server = {kpasswd_addr}
}}
"#
            ))
            .expect("config parses");
            let mut client = TokioClient::with_password(
                config,
                KdcProtocol::Tcp,
                self_client.clone(),
                old_password.to_vec(),
            );

            let kdc_task_client = self_client.clone();
            let kdc_task = tokio::spawn(async move {
                let expected_service = change_password_principal();
                for _ in 0..2 {
                    let (request, mut socket) = read_tcp_kdc_request(&kdc_listener).await;
                    let decoded: rasn_kerberos::AsReq =
                        rasn::der::decode(&request).expect("AS-REQ decodes");
                    let built = built_request_from_der(decoded, &request);
                    assert_eq!(built.client, kdc_task_client);
                    assert_eq!(built.service, expected_service);
                    let response = synthetic_as_rep_with_reply_key(
                        &built,
                        built.nonce,
                        built.service.clone(),
                        &old_reply_key,
                    );
                    write_tcp_kdc_response(&mut socket, &response).await;
                }
            });

            let kpasswd_task_target = explicit_target.clone();
            let kpasswd_task = tokio::spawn(async move {
                let expected_target = kpasswd_task_target;
                let service_session_key = service_key;
                for call in 0..2 {
                    let (request, mut socket) = read_tcp_kdc_request(&kpasswd_listener).await;
                    let parsed = KpasswdRequest::parse(&request).expect("kpasswd request parses");
                    let authenticator = rskrb5_ng::ap_req::decrypt_ap_req_authenticator(
                        &parsed.ap_req,
                        &service_session_key,
                        AP_REQ_AUTHENTICATOR_USAGE,
                    )
                    .expect("AP-REQ authenticator decrypts");
                    let reply_key = EncryptionKey {
                        etype: authenticator
                            .subkey
                            .as_ref()
                            .expect("AP-REQ reply key included")
                            .r#type,
                        value: authenticator
                            .subkey
                            .as_ref()
                            .expect("AP-REQ reply key included")
                            .value
                            .as_ref()
                            .to_vec(),
                    };
                    let enc_part =
                        rskrb5_ng::kadmin::decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key)
                            .expect("KRB-PRIV payload decrypts");
                    let change_data = ChangePasswdData::decode_der(enc_part.user_data.as_ref())
                        .expect("ChangePasswdData decodes");
                    if call == 0 {
                        assert_eq!(
                            principal_from_parts(
                                change_data.targ_realm.as_ref().expect("target realm set"),
                                change_data
                                    .targ_name
                                    .as_ref()
                                    .expect("target principal set"),
                            ),
                            expected_target
                        );
                        assert_eq!(change_data.new_passwd, new_password.to_vec());
                    } else {
                        assert_eq!(
                            principal_from_parts(
                                change_data.targ_realm.as_ref().expect("target realm set"),
                                change_data
                                    .targ_name
                                    .as_ref()
                                    .expect("target principal set"),
                            ),
                            self_client.clone()
                        );
                        assert_eq!(change_data.new_passwd, old_password.to_vec());
                    }
                    let session_key = EncryptionKey {
                        etype: 18,
                        value: decode_hex(SESSION_KEY),
                    };
                    let response =
                        kpasswd_authenticated_success_reply(&request, &session_key, 0x77);
                    write_tcp_kdc_response(&mut socket, &response).await;
                }
            });

            let options = KpasswdRequestOptions::new(
                timestamp(1_893_553_452),
                456_789,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            );
            let change_target = client
                .change_password_for_with_options(explicit_target, new_password, options)
                .await
                .expect("change target password succeeds");
            let change_self = client
                .change_password_with_options(
                    old_password,
                    KpasswdRequestOptions::new(
                        timestamp(1_893_553_453),
                        456_790,
                        43,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .expect("change own password with old credential succeeds");

            kdc_task.await.expect("kdc task completes");
            kpasswd_task.await.expect("kpasswd task completes");
            assert_eq!(change_target.code, KPASSWD_SUCCESS);
            assert_eq!(change_target.text, "password changed");
            assert_eq!(change_self.code, KPASSWD_SUCCESS);
            assert_eq!(change_self.text, "password changed");
            Ok(())
        })
    }
}

/// Credential rotation of a password change for the client's own principal.
#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod own_password_credentials {
    use super::*;

    #[expect(
        clippy::absolute_paths,
        clippy::default_numeric_fallback,
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::needless_raw_strings,
        clippy::too_many_lines,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that changing the client's own password rotates its stored password credential.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_changes_password_updates_password_credentials() -> Result<(), TestError> {
        runtime().block_on(async {
            let old_password = b"old-passwordvalue";
            let new_password = b"new-passwordvalue";
            let self_client = Principal::user("TEST.GOKRB5", "testuser1");
            let old_reply_key =
                derive_password_reply_key(&self_client, old_password, &password_key_info())
                    .expect("old reply key derives");
            let new_reply_key =
                derive_password_reply_key(&self_client, new_password, &password_key_info())
                    .expect("new reply key derives");

            let kdc_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kdc listener");
            let kdc_addr = kdc_listener
                .local_addr()
                .expect("local kdc listener address");
            let kpasswd_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local kpasswd listener");
            let kpasswd_addr = kpasswd_listener
                .local_addr()
                .expect("local kpasswd listener address");

            let config = Config::parse(&format!(
                r#"
[libdefaults]
dns_lookup_kdc = false
udp_preference_limit = 1

[realms]
TEST.GOKRB5 = {{
 kdc = {kdc_addr}
 kpasswd_server = {kpasswd_addr}
}}
"#
            ))
            .expect("config parses");
            let mut client = TokioClient::with_password(
                config,
                KdcProtocol::Tcp,
                self_client.clone(),
                old_password.to_vec(),
            );

            let kdc_task_client = self_client.clone();
            let kdc_task = tokio::spawn(async move {
                let expected_service = change_password_principal();
                for step in 0..2 {
                    let (request, mut socket) = read_tcp_kdc_request(&kdc_listener).await;
                    let decoded: rasn_kerberos::AsReq =
                        rasn::der::decode(&request).expect("AS-REQ decodes");
                    let built = built_request_from_der(decoded, &request);
                    assert_eq!(built.client, kdc_task_client);
                    assert_eq!(built.service, expected_service);
                    let reply_key = if step == 0 {
                        &old_reply_key
                    } else {
                        &new_reply_key
                    };
                    let response = synthetic_as_rep_with_reply_key(
                        &built,
                        built.nonce,
                        built.service.clone(),
                        reply_key,
                    );
                    write_tcp_kdc_response(&mut socket, &response).await;
                }
            });

            let kpasswd_task = tokio::spawn(async move {
                for _ in 0..2 {
                    let (request, mut socket) = read_tcp_kdc_request(&kpasswd_listener).await;
                    let session_key = EncryptionKey {
                        etype: 18,
                        value: decode_hex(SESSION_KEY),
                    };
                    let response =
                        kpasswd_authenticated_success_reply(&request, &session_key, 0x77);
                    write_tcp_kdc_response(&mut socket, &response).await;
                }
            });

            let change_self_with_new = client
                .change_password_with_options(
                    new_password,
                    KpasswdRequestOptions::new(
                        timestamp(1_893_553_452),
                        456_789,
                        42,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .expect("change own password succeeds");
            let change_self_with_updated = client
                .change_password_with_options(
                    new_password,
                    KpasswdRequestOptions::new(
                        timestamp(1_893_553_453),
                        456_790,
                        43,
                        ipv4_host_address([127, 0, 0, 1]),
                    ),
                )
                .await
                .expect("change own password with rotated credential succeeds");

            kdc_task.await.expect("kdc task completes");
            kpasswd_task.await.expect("kpasswd task completes");
            assert_eq!(change_self_with_new.code, KPASSWD_SUCCESS);
            assert_eq!(change_self_with_new.text, "password changed");
            assert_eq!(change_self_with_updated.code, KPASSWD_SUCCESS);
            assert_eq!(change_self_with_updated.text, "password changed");
            Ok(())
        })
    }
}

/// Fork-authored password-change tests: kpasswd success replies must be authenticated.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod fork_tests {
    use rasn::der;
    use rskrb5_ng::kadmin::Error as KadminError;

    use super::*;

    /// Pins that an unsigned kpasswd success result is rejected and keeps the old credential.
    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_client_rejects_unsigned_kpasswd_success() -> Result<(), TestError> {
        runtime().block_on(async {
            let old_password = b"old-passwordvalue";
            let new_password = b"new-passwordvalue";
            let self_client = Principal::user("TEST.GOKRB5", "testuser1");
            let old_reply_key =
                derive_password_reply_key(&self_client, old_password, &password_key_info())?;

            let kdc_listener = TcpListener::bind("127.0.0.1:0").await?;
            let kdc_addr = kdc_listener.local_addr()?;
            let kpasswd_listener = TcpListener::bind("127.0.0.1:0").await?;
            let kpasswd_addr = kpasswd_listener.local_addr()?;

            let config = Config::parse(&format!(
                "
[libdefaults]
dns_lookup_kdc = false
udp_preference_limit = 1

[realms]
TEST.GOKRB5 = {{
 kdc = {kdc_addr}
 kpasswd_server = {kpasswd_addr}
}}
"
            ))?;
            let mut client = TokioClient::with_password(
                config,
                KdcProtocol::Tcp,
                self_client.clone(),
                old_password.to_vec(),
            );

            let kdc_task_client = self_client.clone();
            let kdc_task = tokio::spawn(async move {
                let expected_service = change_password_principal();
                for _ in 0_u8..2 {
                    let (request, mut socket) = read_tcp_kdc_request(&kdc_listener).await;
                    let decoded: rasn_kerberos::AsReq = der::decode(&request)?;
                    let built = built_request_from_der(decoded, &request);
                    assert_eq!(built.client, kdc_task_client);
                    assert_eq!(built.service, expected_service);
                    // The failed change must not rotate the stored credential, so
                    // both AS exchanges have to decrypt under the old reply key.
                    let response = synthetic_as_rep_with_reply_key(
                        &built,
                        built.nonce,
                        built.service.clone(),
                        &old_reply_key,
                    );
                    write_tcp_kdc_response(&mut socket, &response).await;
                }
                Ok::<(), TestError>(())
            });

            let kpasswd_task = tokio::spawn(async move {
                for _ in 0_u8..2 {
                    let (_request, mut socket) = read_tcp_kdc_request(&kpasswd_listener).await;
                    let response = kpasswd_reply_frame(
                        0,
                        &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed"),
                    );
                    write_tcp_kdc_response(&mut socket, &response).await;
                }
            });

            for attempt in 0_u64..2 {
                let Err(error) = client
                    .change_password_with_options(
                        new_password,
                        KpasswdRequestOptions::new(
                            timestamp(1_893_553_452 + attempt),
                            456_789,
                            42,
                            ipv4_host_address([127, 0, 0, 1]),
                        ),
                    )
                    .await
                else {
                    return Err("an unsigned success result must be rejected".into());
                };
                assert!(matches!(
                    error,
                    Error::Kadmin(KadminError::UnauthenticatedSuccess)
                ));
            }

            kdc_task.await??;
            kpasswd_task.await?;
            Ok::<(), TestError>(())
        })
    }
}
