use core::iter;

use proptest::{
    bool::ANY,
    collection,
    prelude::{TestCaseError, prop_assert_eq, proptest},
    sample,
};
use rskrb5_ng::{
    config::{EnctypeExpr, ParseMode, Toggle},
    crypto::KerberosEtype,
};

proptest! {
    /// Ordered selector execution matches an independent last-insertion model.
    #[test]
    fn ordered_edits_match_model(operations in collection::vec((ANY, sample::select(vec![17_i32, 18_i32, 19_i32, 20_i32])), 0..80)) {
        // Given arbitrary additions/removals and a guaranteed surviving RC4 entry.
        let mut text = String::from("rc4");
        let mut timestamps = Vec::new();
        for (index, &(add, id)) in operations.iter().enumerate() {
            let name = match id { 17_i32 => "aes128-sha1", 18_i32 => "aes256-sha1", 19_i32 => "aes128-sha2", _ => "aes256-sha2" };
            text.push_str(if add { " +" } else { " -" });
            text.push_str(name);
            match (add, timestamps.iter().any(|&(existing, _)| existing == id)) {
                (true, false) => timestamps.push((id, index)),
                (false, _) => timestamps.retain(|&(existing, _)| existing != id),
                (true, true) => (),
            }
        }
        timestamps.sort_by_key(|&(_, time)| time);
        let expected: Vec<i32> = iter::once(23_i32).chain(timestamps.into_iter().map(|(id, _)| id)).collect();
        // When executing the public parser and resolver.
        let resolved = EnctypeExpr::parse(&text).and_then(|expr| expr.resolve(Toggle::Enabled, Toggle::Disabled, ParseMode::Strict))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let actual: Vec<i32> = resolved.enctypes().iter().copied().map(KerberosEtype::etype_id).collect();
        // Then all ordering, duplicate and removal decisions agree.
        prop_assert_eq!(actual, expected);
    }
}
