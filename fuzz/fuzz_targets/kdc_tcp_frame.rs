//! Fuzz KDC TCP record marks independently of the inner DER parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{client::transport::kdc_tcp_record_length, error::Client};

fuzz_target!(|data: &[u8]| {
    let Some(header) = data
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
    else {
        return;
    };
    let raw = u32::from_be_bytes(header);
    for max in [0_usize, 16, 0xFFFF, 0x0100_0000, usize::MAX] {
        match kdc_tcp_record_length(header, max) {
            Ok(length) => {
                assert_eq!(raw & 0x8000_0000, 0, "accepted reserved record bit");
                assert!(length > 0 && length <= max, "accepted length outside cap");
                assert_eq!(u32::try_from(length), Ok(raw), "record length changed");
            }
            Err(Client::TcpReservedBitSet) => {
                assert_ne!(raw & 0x8000_0000, 0, "reserved error without reserved bit");
            }
            Err(Client::EmptyKdcResponse) => assert_eq!(raw, 0, "nonempty record reported empty"),
            Err(Client::TcpResponseTooLarge { actual, limit }) => {
                assert_eq!(actual, raw, "size error lost wire length");
                assert_eq!(limit, max, "size error lost configured cap");
                assert!(
                    usize::try_from(raw).map_or(true, |length| length > max),
                    "bounded record reported too large"
                );
            }
            Err(error) => assert!(
                matches!(
                    error,
                    Client::TcpReservedBitSet
                        | Client::EmptyKdcResponse
                        | Client::TcpResponseTooLarge {
                            actual: _,
                            limit: _
                        }
                ),
                "unexpected record-mark error: {error}"
            ),
        }
    }
});
