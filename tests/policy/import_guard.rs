use core::error::Error;
use std::{fs::read_to_string, path::Path};

/// Pin the small checked-import dependency boundary, not a purported Rust call-graph parser.
#[test]
fn checked_import_has_no_public_raw_conversion_calls() -> Result<(), Box<dyn Error>> {
    // Given the checked import module's source, including imports and qualified calls.
    let source =
        read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/krb_cred/import.rs"))?;
    // When examining names of public raw conversion entry points.
    for name in [
        "decrypt_krb_cred_to_ccache_credentials",
        "decode_decrypt_krb_cred_to_ccache_credentials",
        "decrypted_krb_cred_to_ccache_credentials",
        "decrypt_krb_cred_enc_part",
    ] {
        // Then only private conversion/crypto machinery may be shared with checked import.
        assert!(
            !source.contains(name),
            "checked import reaches raw public entry point {name}"
        );
    }
    Ok(())
}
