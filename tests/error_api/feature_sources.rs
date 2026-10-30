#[cfg(feature = "evaluation")]
retains_source!(
    fixture_hex_source,
    hex::FromHexError,
    error::Any::Hex(hex::FromHexError::OddLength)
);

#[cfg(feature = "http")]
retains_source!(
    http_header_source,
    ToStrError,
    error::Http::InvalidHeader(
        HeaderValue::from_bytes(&[255_u8])?
            .to_str()
            .err()
            .ok_or("header text fixture")?
    )
);
#[cfg(feature = "http")]
retains_source!(
    http_header_value_source,
    InvalidHeaderValue,
    error::Http::InvalidHeaderValue(
        HeaderValue::from_bytes(b"\n")
            .err()
            .ok_or("header value fixture")?
    )
);
#[cfg(feature = "http")]
retains_source!(
    http_spnego_source,
    error::Spnego,
    error::Http::Spnego(error::Spnego::EmptyInput)
);
#[cfg(all(feature = "http", feature = "tokio"))]
retains_source!(
    http_client_source,
    error::Client,
    error::Http::Client(error::Client::TimeOverflow)
);
#[cfg(feature = "tower")]
retains_source!(
    http_keytab_source,
    error::Keytab,
    error::Http::Keytab(error::Keytab::InvalidKeytabName)
);
