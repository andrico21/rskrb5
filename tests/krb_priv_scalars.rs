//! Complete KRB-PRIV scalar boundary regressions.
#![cfg(feature = "messages")]

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{keytab::EncryptionKey, krb_priv};

    /// Mutable options cannot bypass complete-builder scalar validation.
    #[test]
    fn builder_rejects_invalid_scalars() -> Result<(), Box<dyn Error>> {
        // Given fractional time and out-of-range microseconds set directly.
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        for (nanos, usec) in [(1_u32, 0_i32), (0, -1_i32), (0, 1_000_000_i32)] {
            let utc = chrono::DateTime::from_timestamp(1, nanos).ok_or("time")?;
            let offset = chrono::FixedOffset::east_opt(0).ok_or("offset")?;
            let mut options =
                krb_priv::EncKrbPrivPartOptions::new(krb_priv::ipv4_host_address([127, 0, 0, 1]));
            options.timestamp = Some(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)));
            options.usec = Some(usec.into());
            // When the complete builder encrypts the payload.
            let result = krb_priv::build_krb_priv_with_confounder(
                b"payload",
                options,
                &key,
                None,
                &[0x24; 16],
            );
            // Then invalid protocol scalars are rejected before encryption.
            assert!(result.is_err(), "invalid scalar accepted");
        }
        Ok(())
    }

    /// Both inclusive microsecond boundaries survive complete construction.
    #[test]
    fn builder_roundtrips_scalar_boundaries() -> Result<(), Box<dyn Error>> {
        // Given whole-second timestamps and boundary microseconds.
        let key = EncryptionKey::new(17, vec![0x42; 16]);
        let utc = chrono::DateTime::from_timestamp(1, 0).ok_or("time")?;
        let offset = chrono::FixedOffset::east_opt(0).ok_or("offset")?;
        for usec in [0_u32, 999_999] {
            let options =
                krb_priv::EncKrbPrivPartOptions::new(krb_priv::ipv4_host_address([127, 0, 0, 1]))
                    .with_timestamp(
                        rasn_kerberos::KerberosTime(utc.with_timezone(&offset)),
                        usec,
                    );
            // When the complete message is constructed and decrypted.
            let message = krb_priv::build_krb_priv_with_confounder(
                b"payload",
                options,
                &key,
                None,
                &[0x24; 16],
            )?;
            let plaintext = krb_priv::decrypt_krb_priv_enc_part(&message, &key)?;
            // Then the accepted scalar is preserved exactly.
            assert_eq!(plaintext.usec, Some(usec.into()));
        }
        Ok(())
    }
}
