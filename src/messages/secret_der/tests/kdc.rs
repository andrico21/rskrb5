//! KDC reply encoder ownership regressions.

use core::error::Error;

use rasn::der;

use super::{ERASED, EncryptionKey, kdc_rep};

/// Both reply tags erase their encoding on successful and failing encryption.
#[test]
fn kdc_encode_owners_erased_on_each_exit() -> Result<(), Box<dyn Error>> {
    // Given a marker-bearing encrypted reply part.
    let part: rasn_kerberos::EncTgsRepPart = der::decode(&hex::decode(concat!(
        "7A81B23081AFA0133011A003020101A10A04083132333435363738A13630343018A003",
        "0201FBA111180F31393934303631303036303331375A3018A0030201FBA111180F3139",
        "3934303631303036303331375AA20302012AA407030500FE5CBA98A511180F313939",
        "34303631303036303331375AA711180F31393934303631303036303331375AA9101B",
        "0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B0668667473",
        "61691B056578747261"
    ))?)?;
    let key = EncryptionKey::new(17, vec![0x42; 16]);
    for (purpose, as_reply) in [("as-rep encode", true), ("tgs-rep encode", false)] {
        for confounder in [vec![0x24; 16], Vec::new()] {
            ERASED.with_borrow_mut(Vec::clear);
            // When the real tag-specific builder attempts encryption.
            let result = if as_reply {
                kdc_rep::encrypt_as_rep_enc_part_with_confounder(&part.0, &key, None, &confounder)
            } else {
                kdc_rep::encrypt_tgs_rep_enc_part_with_confounder(&part.0, &key, None, &confounder)
            };
            // Then exactly that tag's staging owner was erased.
            assert_eq!(result.is_ok(), confounder.len() == 16);
            ERASED.with_borrow(|events| assert_eq!(events.as_slice(), [(purpose, 181)]));
        }
    }
    Ok(())
}
