use core::error::Error;

use rskrb5_ng::{
    config::{Config, LibDefaults},
    crypto::{CryptoPolicy, s2k::Family},
    error::Policy,
};

/// Defaults and trusted overrides are independent for each AES family.
#[test]
fn family_minima_and_override() -> Result<(), Box<dyn Error>> {
    // Given defaults and an API-only SHA1 override.
    let defaults = LibDefaults::new().with_min_s2k_iterations(Family::AesSha1, 1)?;
    let policy = CryptoPolicy::from_libdefaults(&defaults)?;
    // When querying both key sizes and the other AES family.
    assert_eq!(policy.min_s2k_iterations(17), Some(1_u32));
    assert_eq!(policy.min_s2k_iterations(18), Some(1_u32));
    assert_eq!(policy.min_s2k_iterations(19), Some(0x8000_u32));
    assert_eq!(policy.min_s2k_iterations(20), Some(0x8000_u32));
    // Then defaults retain RFC floors and non-PBKDF2 profiles have no count.
    let default = CryptoPolicy::default();
    assert_eq!(default.min_s2k_iterations(17), Some(4096_u32));
    assert_eq!(default.min_s2k_iterations(18), Some(4096_u32));
    assert_eq!(default.min_s2k_iterations(16), None);
    assert_eq!(default.min_s2k_iterations(23), None);
    Ok(())
}

/// Invalid trusted overrides cannot disable the work ceiling or encode RFC zero.
#[test]
fn invalid_overrides_are_rejected() -> Result<(), Box<dyn Error>> {
    // Given impossible minimum values.
    for minimum in [0_u32, 0x0100_0001_u32] {
        // When attempting the trusted API.
        let error = LibDefaults::new()
            .with_min_s2k_iterations(Family::AesSha2, minimum)
            .err()
            .ok_or("invalid override accepted")?;
        // Then no invalid minimum is installed.
        assert!(
            matches!(error, Policy::InvalidS2kMinimum { minimum: actual } if actual == minimum)
        );
    }
    Ok(())
}

/// Text cannot lower the API-only minimum.
#[test]
fn text_does_not_override_minima() -> Result<(), Box<dyn Error>> {
    // Given an unrecognized profile relation attempting to lower the floor.
    let config = Config::parse("[libdefaults]\nmin_s2k_iterations = 1")?;
    // When constructing effective policy.
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    // Then both RFC minima remain unchanged.
    assert_eq!(policy.min_s2k_iterations(17), Some(4096_u32));
    assert_eq!(policy.min_s2k_iterations(20), Some(0x8000_u32));
    Ok(())
}

/// Serialized input cannot install an API-only work-factor downgrade.
#[cfg(feature = "serde")]
#[test]
fn serde_restores_secure_minima() -> Result<(), Box<dyn Error>> {
    // Given a trusted low-count override serialized for unrelated config fields.
    let defaults = LibDefaults::new().with_min_s2k_iterations(Family::AesSha1, 1)?;
    let mut value = serde_json::to_value(&defaults)?;
    drop(value.as_object_mut().ok_or("config object")?.insert(
        "min_s2k_iterations".to_owned(),
        serde_json::json!({"sha1": 1_u32, "sha2": 1_u32}),
    ));
    // When untrusted serialized data attempts to supply a minimum.
    let decoded: LibDefaults = serde_json::from_value(value)?;
    let policy = CryptoPolicy::from_libdefaults(&decoded)?;
    // Then only application code can lower the floors.
    assert_eq!(policy.min_s2k_iterations(17), Some(4096_u32));
    assert_eq!(policy.min_s2k_iterations(20), Some(0x8000_u32));
    Ok(())
}
