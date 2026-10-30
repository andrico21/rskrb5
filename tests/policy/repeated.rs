use core::error::Error;

use rskrb5_ng::{Config, config::ParseMode, error};

/// A later value cannot conceal an earlier forbidden or disabled positive term.
#[test]
fn overwritten_invalid_terms_still_fail() -> Result<(), Box<dyn Error>> {
    // Given repeated lists whose first value violates policy.
    for token in ["des-cbc-crc", "rc4-hmac-exp", "rc4-hmac", "typo"] {
        for key in [
            "permitted_enctypes",
            "default_tkt_enctypes",
            "default_tgs_enctypes",
        ] {
            let input = format!("[libdefaults]\n{key} = aes {token}\n{key} = aes\n");
            // When the later valid value would formerly overwrite the evidence.
            let failure = Config::parse(&input)
                .err()
                .ok_or("overwritten forbidden term accepted")?;
            // Then the original offending token is still named.
            assert!(failure.to_string().contains(token));
        }
    }
    Ok(())
}

/// Empty resolved lists fail in every relation and mode.
#[test]
fn empty_relations_fail() -> Result<(), Box<dyn Error>> {
    // Given explicit subtraction to an empty list in each relation.
    for key in [
        "permitted_enctypes",
        "default_tkt_enctypes",
        "default_tgs_enctypes",
    ] {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            // When parsing a syntactically valid but unusable expression.
            let failure =
                Config::parse_with_mode(&format!("[libdefaults]\n{key} = DEFAULT -aes"), mode)
                    .err()
                    .ok_or("empty relation accepted")?;
            // Then no defaults are substituted.
            assert!(matches!(failure, error::Config::EmptyEnctypeExpression));
        }
    }
    Ok(())
}
