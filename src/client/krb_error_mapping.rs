/// Map a KRB-ERROR helper error into the client error.
fn krb_error_error(error: error::KrbErrorCodec) -> Error {
    match error {
        error::KrbErrorCodec::Policy(policy) => policy.into(),
        error::KrbErrorCodec::Decode { target, message } => Error::Decode { target, message },
        error::KrbErrorCodec::Encode { target, message } => Error::Encode { target, message },
        error::KrbErrorCodec::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::KrbErrorCodec::IntegerOutOfRange { field, value } => Error::InvalidUnsignedInteger {
            field,
            actual: value,
        },
        error::KrbErrorCodec::TimeOverflow => Error::TimeOverflow,
        other @ (error::KrbErrorCodec::InvalidString(_)
        | error::KrbErrorCodec::KvnoOutOfRange { target: _, kvno: _ }) => Error::Decode {
            target: "KRB-ERROR",
            message: other.to_string(),
        },
    }
}
