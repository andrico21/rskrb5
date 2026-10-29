//! SPNEGO sequence field cardinality and ordering regressions.

use super::{Error, NegTokenInit, NegTokenResp, der::encode_tlv};

/// Duplicate fields and adjacent reversals must fail for both negotiation choices.
#[test]
fn sequences_reject_duplicate_and_reordered_fields() -> Result<(), Error> {
    for (tag, fields) in [
        (
            0xa0,
            vec![
                vec![0xa0, 4, 0x30, 2, 6, 0],
                vec![0xa1, 3, 3, 1, 0],
                vec![0xa2, 2, 4, 0],
                vec![0xa3, 2, 4, 0],
            ],
        ),
        (
            0xa1,
            vec![
                vec![0xa0, 3, 0x0a, 1, 0],
                vec![0xa1, 3, 6, 1, 0x2a],
                vec![0xa2, 2, 4, 0],
                vec![0xa3, 2, 4, 0],
            ],
        ),
    ] {
        let mut valid = fields;
        if tag == 0xa0 {
            *valid.first_mut().ok_or(Error::TruncatedDer)? = vec![0xa0, 5, 0x30, 3, 6, 1, 0x2a];
        }
        for index in 0..4 {
            // Given a valid sequence with one known field repeated.
            let mut duplicate = valid.clone();
            duplicate.insert(index, valid.get(index).ok_or(Error::TruncatedDer)?.clone());
            // When decoded, then the duplicate cannot overwrite its predecessor.
            assert!(decode_fields(tag, &duplicate).is_err());
        }
        for index in 0_usize..3 {
            // Given a valid sequence with adjacent fields reversed.
            let mut reversed = valid.clone();
            reversed.swap(index, index.saturating_add(1));
            // When decoded, then ordering is enforced independently of payload processing.
            assert!(decode_fields(tag, &reversed).is_err());
        }
        decode_fields(tag, &valid)?;
        for field in valid.iter().skip(1) {
            let subset = if tag == 0xa0 {
                vec![
                    valid.first().ok_or(Error::TruncatedDer)?.clone(),
                    field.clone(),
                ]
            } else {
                vec![field.clone()]
            };
            decode_fields(tag, &subset)?;
        }
    }
    Ok(())
}

/// Decode independent field encodings through the public token boundary.
fn decode_fields(tag: u8, fields: &[Vec<u8>]) -> Result<(), Error> {
    let wire = encode_tlv(tag, &encode_tlv(0x30, &fields.concat()));
    if tag == 0xa0 {
        drop(NegTokenInit::decode(&wire)?);
    } else {
        drop(NegTokenResp::decode(&wire)?);
    }
    Ok(())
}
