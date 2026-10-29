//! Mapping between PAC wire checksums and Kerberos enctypes.

use super::KerberosEtype;

/// Kerberos encryption type whose checksum is `signature_type`, if any.
pub(super) fn kerberos_etype_for_checksum_type(signature_type: u32) -> Option<KerberosEtype> {
    KerberosEtype::from_checksum_type_id(signature_type.try_into().ok()?)
}
