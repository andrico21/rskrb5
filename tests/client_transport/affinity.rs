//! Configured preauthentication connection reuse.

use rskrb5_ng::keytab::{Keytab, Principal as KeytabPrincipal};

use super::*;

/// Configured password and keytab Auto logins reuse the TCP winner on both preference paths.
#[test]
fn configured_auto_logins_reuse_connection() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for limit in [1_u16, 1465] {
            for keytab in [false, true] {
                // Given a TCP KDC requiring a second AS request and no UDP listener.
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let config = Config::parse(&format!("[libdefaults]\ndns_lookup_kdc = false\nudp_preference_limit = {limit}\n[realms]\nTEST.GOKRB5 = {{\nkdc = {addr}\n}}\n"))?;
                let transport = Tokio::new().with_timeout(Duration::from_millis(200));
                let fixture = async {
                    let (mut stream, _) = listener.accept().await?;
                    drop(read_framed(&mut stream).await?);
                    write_framed(&mut stream, &preauth_required_error()?).await?;
                    let second = timeout(Duration::from_secs(1), read_framed(&mut stream)).await??;
                    write_framed(&mut stream, b"invalid-as-rep").await?;
                    assert!(!second.is_empty(), "preauthentication request missing");
                    assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err(), "second connection opened");
                    Ok::<_, TestError>(())
                };
                // When the configured login runs through either credential path.
                let login = async {
                    let principal = Principal::user("TEST.GOKRB5", "testuser1");
                    let options = AsReq::new(SystemTime::now(), 1);
                    if keytab {
                        let mut keys = Keytab::new();
                        keys.add_entry_from_password(
                            KeytabPrincipal::new("TEST.GOKRB5", 1, ["testuser1"]),
                            b"password", SystemTime::now(), 1, 18,
                        )?;
                        drop(transport.login_tgt_with_keytab_config(&config, KdcProtocol::Auto, principal, &keys, options).await);
                    } else {
                        drop(transport.login_tgt_with_password_config(&config, KdcProtocol::Auto, principal, b"password", options).await);
                    }
                    Ok::<_, TestError>(())
                };
                // Then the peer sees the follow-up on the original stream.
                let (exchange, result) = tokio::join!(fixture, login);
                exchange?;
                result?;
            }
        }
        Ok(())
    })
}
