#[cfg(target_os = "linux")]
use std::fs;
use std::path::PathBuf;

/// Why a credential file name could not be resolved to a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The name, or the residual after its type prefix, is empty.
    Empty,
    /// Process identities are unavailable on this platform or from procfs.
    IdentityUnavailable,
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
        return expand_path_tokens(name).map(PathBuf::from);
    };

    if is_windows_drive_path(prefix, path) {
        return expand_path_tokens(name).map(PathBuf::from);
    }

    if allowed_types
        .iter()
        .any(|allowed| prefix.eq_ignore_ascii_case(allowed))
    {
        if path.is_empty() {
            return Err(Error::Empty);
        }
        expand_path_tokens(path).map(PathBuf::from)
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
/// Linux reads real/effective identities from `/proc/self/status`. Other
/// platforms reject these tokens; no environment variable supplies identity.
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] when process identity cannot be read.
pub(crate) fn expand_path_tokens(value: &str) -> Result<String, Error> {
    if !value.contains("%{uid}") && !value.contains("%{euid}") {
        return Ok(value.to_owned());
    }
    let (real, effective) = process_identity()?;
    Ok(value
        .replace("%{uid}", &real.to_string())
        .replace("%{euid}", &effective.to_string()))
}

/// Real and effective Linux identities, without consulting ambient UID text.
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] for unsupported or unavailable procfs.
#[cfg(target_os = "linux")]
fn process_identity() -> Result<(u32, u32), Error> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_io| Error::IdentityUnavailable)?;
    let mut ids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or(Error::IdentityUnavailable)?
        .split_whitespace();
    let real = ids
        .next()
        .ok_or(Error::IdentityUnavailable)?
        .parse()
        .map_err(|_parse| Error::IdentityUnavailable)?;
    let effective = ids
        .next()
        .ok_or(Error::IdentityUnavailable)?
        .parse()
        .map_err(|_parse| Error::IdentityUnavailable)?;
    Ok((real, effective))
}

/// Unsupported platforms cannot infer identities for token expansion.
///
/// # Errors
///
/// Always returns [`Error::IdentityUnavailable`].
#[cfg(not(target_os = "linux"))]
const fn process_identity() -> Result<(u32, u32), Error> {
    Err(Error::IdentityUnavailable)
}
