use core::{
    mem,
    ops::{Deref, DerefMut},
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use zeroize::{Zeroize as _, Zeroizing};

/// Internal credential bytes with erasure attached to their lifetime.
pub(crate) struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Adopt an allocation without copying its contents.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Transfer raw exported bytes to the caller's cleanup responsibility.
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut *self.0)
    }
}

impl Deref for SecretBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Drop audit: live-slice erasure is in-place, nonblocking and infallible;
// test-only observation inspects live storage before the allocation is released.
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        {
            assert!(self.0.iter().all(|byte| *byte == 0));
            tests::ERASED_BYTES.with(|count| count.set(count.get().saturating_add(self.0.len())));
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{cell::Cell, error::Error as StdError};
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        ccache::{CCache, Principal as CachePrincipal},
        error::Keytab as KeytabError,
        keytab::{EncryptionKey, Entry, Keytab, Principal},
    };

    std::thread_local! {
        pub(super) static ERASED_BYTES: Cell<usize> = const { Cell::new(0) };
    }

    /// File reads and save serialization erase internal credential allocations.
    #[test]
    fn credential_file_buffers_are_erased() -> Result<(), Box<dyn StdError>> {
        // Given real cache/keytab file operations and an erasure counter.
        let directory = env::temp_dir().join(format!(
            "file-erasure-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        let mut keytab = Keytab::new();
        keytab.entries_mut().push(Entry::new(
            Principal::new("REALM", 1, ["user"]),
            1,
            1,
            EncryptionKey::new(18, vec![7; 16]),
            1,
        ));
        let cache = CCache::new(CachePrincipal::new("REALM", 1, vec!["user".to_owned()]));
        ERASED_BYTES.with(|count| count.set(0));

        // When persisting and reading each real format.
        keytab.save(directory.join("keytab"))?;
        drop(Keytab::load(directory.join("keytab"))?);
        cache.save(directory.join("cache"))?;
        drop(CCache::load(directory.join("cache"))?);

        // Then owned file/serialization copies passed through erasing owners.
        let erased = ERASED_BYTES.with(Cell::get);
        fs::remove_dir_all(directory)?;
        assert!(erased >= 32, "owned file buffers were not erased");
        Ok(())
    }

    /// Partial keytab output is erased when a later entry cannot serialize.
    #[test]
    fn partial_serialization_is_erased() -> Result<(), Box<dyn StdError>> {
        // Given one secret-bearing entry followed by an invalid entry.
        let mut keytab = Keytab::parse(&[5, 2])?;
        let entry = Entry::new(
            Principal::new("REALM", 1, ["user"]),
            1,
            1,
            EncryptionKey::new(18, vec![7; 16]),
            1,
        );
        keytab.entries_mut().push(entry.clone());
        let mut invalid = entry;
        invalid.key.etype = i32::MAX;
        keytab.entries_mut().push(invalid);
        ERASED_BYTES.with(|count| count.set(0));

        // When serialization fails after writing the first entry.
        let result = keytab.to_bytes();

        // Then the partial secret output is erased on the error path.
        assert!(matches!(result, Err(KeytabError::LengthOverflow)));
        assert!(
            ERASED_BYTES.with(Cell::get) >= 16,
            "partial output was not erased"
        );
        Ok(())
    }

    /// Failed replacement preserves the destination and removes the stage.
    #[test]
    fn failed_private_rename_preserves_destination() -> Result<(), Box<dyn StdError>> {
        // Given a nonempty directory where a credential file should be.
        let directory = env::temp_dir().join(format!(
            "private-rename-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let destination = directory.join("keytab");
        fs::create_dir_all(&destination)?;
        fs::write(destination.join("keep"), b"existing")?;
        // When the real staged write cannot replace that directory.
        let result = super::write_private(&destination, b"secret");
        // Then the error is returned without damaging the existing destination.
        assert!(result.is_err());
        assert_eq!(fs::read(destination.join("keep"))?, b"existing");
        assert_eq!(fs::read_dir(&directory)?.count(), 1);
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}

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

/// Replace a credential file using an exclusively created same-directory stage.
///
/// Unix staging is owner-only before the first write and never widens the
/// destination's existing owner permissions. Windows callers must provide a
/// directory with an owner-only ACL; std does not expose ACL construction.
///
/// # Errors
///
/// Returns filesystem errors from staging, writing, syncing or renaming.
/// A Unix directory-sync error can occur after replacement has completed.
/// Cleanup failures never replace the original error.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    reject_symlink(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let suffix = u128::from_be_bytes(random);
    let temporary = parent.join(format!(".rskrb5-{suffix:032x}.tmp"));
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create_new(true);
    #[cfg(unix)]
    let _: &mut OpenOptions = options.mode(0o600);
    let mut file = options.open(&temporary)?;
    let result = (|| {
        #[cfg(unix)]
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o600;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        reject_symlink(path)?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // Preserve the primary failure, including a sync failure after rename
        // has already removed the stage.
        let _cleanup = fs::remove_file(temporary);
    }
    result
}

/// Reject only a final-component symlink; parent aliases remain supported.
///
/// # Errors
///
/// Returns `InvalidInput` for a symlink and propagates metadata errors except
/// an absent final entry, which is admissible for exclusive creation.
pub(crate) fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential destination is a symlink",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Initialize a missing DIR primary without following or replacing an entry.
///
/// # Errors
///
/// Returns an open or write error, including `AlreadyExists` for any existing
/// entry (dangling symlinks included).
pub(crate) fn create_primary(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create_new(true);
    #[cfg(unix)]
    let _: &mut OpenOptions = options.mode(0o600);
    options.open(path)?.write_all(bytes)
}
