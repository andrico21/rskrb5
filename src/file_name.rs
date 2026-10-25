use std::{env, path::PathBuf};

/// Why a credential file name could not be resolved to a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The name, or the residual after its type prefix, is empty.
    Empty,
    /// The name carries a type prefix that the caller does not accept.
    UnsupportedType {
        /// The rejected type prefix as written in the name.
        name_type: String,
    },
}

/// Resolve a `TYPE:residual` credential file name to a filesystem path.
///
/// A name without a type prefix, or one that looks like a Windows drive path
/// such as `C:\\krb5cc`, is taken as a path as written. Path tokens such as
/// `%{uid}` are expanded in the resulting path.
///
/// # Errors
///
/// Returns [`Error::Empty`] when `name` or its residual is empty, and
/// [`Error::UnsupportedType`] when the prefix is not one of `allowed_types`
/// (compared case-insensitively).
pub(crate) fn file_path_from_name(name: &str, allowed_types: &[&str]) -> Result<PathBuf, Error> {
    if name.is_empty() {
        return Err(Error::Empty);
    }

    let Some((prefix, path)) = name.split_once(':') else {
        return Ok(PathBuf::from(expand_path_tokens(name)));
    };

    if is_windows_drive_path(prefix, path) {
        return Ok(PathBuf::from(expand_path_tokens(name)));
    }

    if allowed_types
        .iter()
        .any(|allowed| prefix.eq_ignore_ascii_case(allowed))
    {
        if path.is_empty() {
            return Err(Error::Empty);
        }
        Ok(PathBuf::from(expand_path_tokens(path)))
    } else {
        Err(Error::UnsupportedType {
            name_type: prefix.to_owned(),
        })
    }
}

/// Whether `prefix:path` is a Windows drive path such as `C:\\krb5cc` rather
/// than a typed name.
fn is_windows_drive_path(prefix: &str, path: &str) -> bool {
    prefix.len() == 1
        && prefix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && (path.starts_with('\\') || path.starts_with('/'))
}

/// Expand the `%{uid}` and `%{euid}` tokens in a credential file path.
///
/// Both tokens expand to the `UID` environment variable, or to `0` when it is
/// unset or not valid Unicode.
pub(crate) fn expand_path_tokens(value: &str) -> String {
    if !value.contains("%{") {
        return value.to_owned();
    }

    let user_id = env::var("UID").unwrap_or_else(|_| "0".to_owned());
    value
        .replace("%{uid}", &user_id)
        .replace("%{euid}", &user_id)
}
