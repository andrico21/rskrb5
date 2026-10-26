use super::*;

/// Cookie conversation regression tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;
    use rasn::der;
    struct CookieKdc {
        calls: usize,
        key: EncryptionKey,
    }

    impl KdcTransport for CookieKdc {
        fn send(&mut self, _: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(request)
                .map_err(|cause| Error::Transport(cause.to_string()))
        }
    }

    impl CookieKdc {
        fn reply(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
            use rskrb5_ng::client::PA_FX_COOKIE;
            let decoded: rasn_kerberos::AsReq = der::decode(request)?;
            self.calls = self.calls.checked_add(1).context("call count")?;
            if self.calls == 1 {
                let mut challenge: rasn_kerberos::KrbError =
                    der::decode(&synthetic_preauth_required_error()?)?;
                let mut data: rasn_kerberos::MethodData =
                    der::decode(challenge.e_data.as_ref().context("method data")?.as_ref())?;
                data.push(rasn_kerberos::PaData {
                    r#type: PA_FX_COOKIE,
                    value: b"fresh\0cookie".to_vec().into(),
                });
                challenge.e_data = Some(der::encode(&data)?.into());
                return Ok(der::encode(&challenge)?);
            }
            let cookies = decoded
                .0
                .padata
                .as_ref()
                .context("retry padata")?
                .iter()
                .filter(|pa| pa.r#type == PA_FX_COOKIE)
                .collect::<Vec<_>>();
            assert_eq!(cookies.len(), 1);
            assert_eq!(
                cookies.first().context("cookie")?.value.as_ref(),
                b"fresh\0cookie"
            );
            let built = built_request_from_der(decoded, request)?;
            synthetic_as_rep_with_reply_key(&built, built.nonce, &built.service, &self.key)
        }
    }

    /// Password retries replace stale cookies with the exact challenge value.
    #[test]
    fn password_retry_echoes_latest_cookie() -> Result<(), TestError> {
        let request = sample_request()?;
        let mut kdc = CookieKdc {
            calls: 0,
            key: derive_password_reply_key(
                &request.client,
                TESTUSER_PASSWORD,
                &password_key_info(),
            )?,
        };
        let options = AsReq::new(timestamp(1_893_553_447)?, 42)
            .with_etypes(vec![18])
            .with_padata(vec![rasn_kerberos::PaData {
                r#type: rskrb5_ng::client::PA_FX_COOKIE,
                value: b"stale".to_vec().into(),
            }]);
        let session =
            login_tgt_with_password(&mut kdc, request.client.clone(), TESTUSER_PASSWORD, options)?;
        assert_eq!(session.client, request.client);
        Ok(())
    }

    /// Keytab retries copy cookies without echoing unrelated challenge data.
    #[test]
    fn keytab_retry_echoes_latest_cookie() -> Result<(), TestError> {
        let request = sample_request()?;
        let mut kdc = CookieKdc {
            calls: 0,
            key: reply_key()?,
        };
        let session = login_tgt_with_keytab(
            &mut kdc,
            request.client.clone(),
            &keytab_with_reply_key(3)?,
            AsReq::new(timestamp(1_893_553_447)?, 42).with_etypes(vec![18]),
        )?;
        assert_eq!(session.client, request.client);
        Ok(())
    }
}
