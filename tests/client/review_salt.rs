use super::*;

/// Initial password reply key derivation regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;

    use super::*;

    struct SaltKdc;
    impl KdcTransport for SaltKdc {
        fn send(&mut self, _: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            Self::reply(request).map_err(|cause| Error::Transport(cause.to_string()))
        }
    }
    impl SaltKdc {
        fn reply(request: &[u8]) -> Result<Vec<u8>, TestError> {
            let decoded = der::decode(request)?;
            let built = built_request_from_der(decoded, request)?;
            let info = PreauthKeyInfo::new(18)
                .with_salt(Some("nondefault-salt".to_owned()))
                .with_s2kparams(Some(vec![0, 0, 0, 2]));
            let key = derive_password_reply_key(&built.client, TESTUSER_PASSWORD, &info)?;
            let mut response: rasn_kerberos::AsRep = der::decode(
                &synthetic_as_rep_with_reply_key(&built, built.nonce, &built.service, &key)?,
            )?;
            response.0.padata = Some(vec![rasn_kerberos::PaData {
                r#type: PA_ETYPE_INFO2,
                value: der::encode(&rasn_kerberos::EtypeInfo2::from([
                    rasn_kerberos::EtypeInfo2Entry {
                        etype: 18,
                        salt: Some(kerberos_string("nondefault-salt")?),
                        s2kparams: Some(vec![0, 0, 0, 2].into()),
                    },
                ]))?
                .into(),
            }]);
            Ok(der::encode(&response)?)
        }
    }

    /// An initial AS reply can select a nondefault salt and iteration count.
    #[test]
    fn initial_password_reply_uses_info2_salt_and_parameters() -> Result<(), TestError> {
        let client = sample_request()?.client;
        let session = login_tgt_with_password(
            &mut SaltKdc,
            client.clone(),
            TESTUSER_PASSWORD,
            AsReq::new(timestamp(1_893_553_447)?, 42).with_etypes(vec![18_i32]),
        )?;
        assert_eq!(session.client, client);
        Ok(())
    }
}
