//! Kerberos cryptographic primitives.
//!
//! The implemented encryption families cover RFC3962
//! `aes128-cts-hmac-sha1-96` / `aes256-cts-hmac-sha1-96` and RFC8009
//! `aes128-cts-hmac-sha256-128` / `aes256-cts-hmac-sha384-192`, RFC3961
//! `des3-cbc-sha1-kd`, and RFC4757 `arcfour-hmac-md5` / `rc4-hmac`,
//! matching the gokrb5 v8 surface used by key derivation, checksums, and
//! encrypted message handling.

use core::mem;

use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, InvalidLength, Key, KeyInit, consts::U16,
};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rc4::{Rc4, StreamCipher as _};
use sha1::Sha1;
use sha2::{Sha256, Sha384};

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;
/// AES-128 key size in bytes.
const AES128_KEY_SIZE: usize = 16;
/// DES3 (triple DES) block size in bytes.
const DES3_BLOCK_SIZE: usize = 8;
/// DES3 key size in bytes, three 8-byte DES keys with parity bits.
const DES3_KEY_SIZE: usize = 24;
/// DES3 random-to-key seed size in bytes (RFC3961 section 6.3.1).
const DES3_SEED_SIZE: usize = 21;
/// Number of seed bytes stretched into one 8-byte DES key.
const DES3_SEED_CHUNK_SIZE: usize = 7;
/// RC4-HMAC protocol key size in bytes.
const RC4_HMAC_KEY_SIZE: usize = 16;
/// RC4-HMAC confounder size in bytes.
const RC4_HMAC_CONFOUNDER_SIZE: usize = 8;
/// HMAC-SHA1-96 truncated MAC size in bytes.
const HMAC_SHA1_96_SIZE: usize = 12;
/// Full HMAC-SHA1 MAC size in bytes.
const HMAC_SHA1_SIZE: usize = 20;
/// HMAC-SHA256-128 truncated MAC size in bytes.
const HMAC_SHA256_128_SIZE: usize = 16;
/// HMAC-SHA384-192 truncated MAC size in bytes.
const HMAC_SHA384_192_SIZE: usize = 24;
/// HMAC-MD5 MAC size in bytes.
const HMAC_MD5_SIZE: usize = 16;
/// RFC3962 default string-to-key parameters: 4096 iterations.
const DEFAULT_RFC3962_S2KPARAMS: &str = "00001000";
/// RFC8009 default string-to-key parameters: 32768 iterations.
const DEFAULT_RFC8009_S2KPARAMS: &str = "00008000";
/// DES3 string-to-key parameters, which RFC3961 requires to be empty.
const DEFAULT_DES3_S2KPARAMS: &str = "";
/// RC4-HMAC string-to-key parameters, which RFC4757 ignores.
const DEFAULT_RC4_HMAC_S2KPARAMS: &str = "";
/// RFC3961 `"kerberos"` constant used to derive a protocol key from a password.
const KERBEROS_CONSTANT: &[u8] = b"kerberos";
/// RFC4757 signing-key constant for `KERB_CHECKSUM_HMAC_MD5`, NUL included.
const RC4_HMAC_SIGNATURE_KEY: &[u8] = b"signaturekey\0";
/// All-zero initial vector of RFC3962 and RFC8009 AES-CTS.
const ZERO_AES_IV: [u8; AES_BLOCK_SIZE] = [0; AES_BLOCK_SIZE];

/// Kerberos AES CTS-HMAC-SHA1-96 encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AesSha1Etype {
    /// `aes128-cts-hmac-sha1-96`, etype 17.
    Aes128,
    /// `aes256-cts-hmac-sha1-96`, etype 18.
    Aes256,
}

impl AesSha1Etype {
    #[must_use]
    /// Return the AES-SHA1 encryption type for a Kerberos etype id.
    #[inline]
    pub const fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            17 => Some(Self::Aes128),
            18 => Some(Self::Aes256),
            _ => None,
        }
    }

    #[must_use]
    /// Kerberos encryption type ID.
    #[inline]
    pub const fn etype_id(self) -> i32 {
        match self {
            Self::Aes128 => 17,
            Self::Aes256 => 18,
        }
    }

    #[must_use]
    /// Kerberos checksum type ID.
    #[inline]
    pub const fn checksum_type_id(self) -> i32 {
        match self {
            Self::Aes128 => 15,
            Self::Aes256 => 16,
        }
    }

    #[must_use]
    /// Protocol key size in bytes.
    #[inline]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    #[must_use]
    /// Confounder size in bytes.
    #[inline]
    pub const fn confounder_len() -> usize {
        AES_BLOCK_SIZE
    }

    #[must_use]
    /// Truncated SHA-1 HMAC size in bytes.
    #[inline]
    pub const fn hmac_len() -> usize {
        HMAC_SHA1_96_SIZE
    }

    #[must_use]
    /// Default RFC3962 string-to-key parameters, encoded as big-endian hex.
    #[inline]
    pub const fn default_s2kparams() -> &'static str {
        DEFAULT_RFC3962_S2KPARAMS
    }

    #[must_use]
    /// Derive the PBKDF2 intermediate key for RFC3962 string-to-key.
    #[inline]
    pub fn string_to_pbkdf2(self, secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0; self.key_len()];
        pbkdf2::pbkdf2_hmac::<Sha1>(secret, salt, iterations, &mut out);
        out
    }

    /// Derive an AES protocol key from a password and salt.
    ///
    /// `s2kparams` must be the Kerberos four-byte iteration count encoded as
    /// eight hex characters. The RFC3962 zero value means 2^32 iterations; this
    /// implementation rejects it rather than attempting an impractical derive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidS2kParamsLength`], [`Error::InvalidS2kParamsHex`] or
    /// [`Error::UnsupportedIterationCountZero`] for unusable `s2kparams`.
    #[inline]
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        let iterations = s2kparams_to_iterations(s2kparams)?;
        let tkey = self.string_to_pbkdf2(secret, salt, iterations);
        self.derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// Derive a usage-specific key from a protocol key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `usage` is empty.
    #[inline]
    pub fn derive_key(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        let random = self.derive_random(protocol_key, usage)?;
        Ok(random)
    }

    /// RFC3961 DR function for AES.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `usage` is empty.
    #[inline]
    pub fn derive_random(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }

        let folded_usage = nfold(usage, AES_BLOCK_SIZE * 8)?;
        let mut out = Vec::with_capacity(self.key_len());
        let (_, mut block) = self.encrypt_data(protocol_key, &folded_usage)?;

        while out.len() < self.key_len() {
            let remaining = self.key_len().saturating_sub(out.len());
            out.extend(block.iter().take(remaining));
            if out.len() < self.key_len() {
                let (_, next) = self.encrypt_data(protocol_key, &block)?;
                block = next;
            }
        }

        Ok(out)
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long.
    #[inline]
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = self.derive_key(protocol_key, &usage_constant(usage, 0x99))?;
        Ok(hmac_sha1_96(&key, data))
    }

    #[must_use]
    /// Verify a keyed checksum.
    #[inline]
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with RFC3962 AES-CTS and a zero initial IV.
    ///
    /// Returns `(next_iv, ciphertext)`, matching gokrb5's AES-CTS helper.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyPlaintext`] when `plaintext` is empty.
    #[inline]
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_key(key)?;
        aes_cts_encrypt(key, plaintext)
    }

    /// Decrypt raw bytes with RFC3962 AES-CTS and a zero initial IV.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long,
    /// and [`Error::CiphertextTooShort`] when `ciphertext` is shorter than one AES block.
    #[inline]
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_key(key)?;
        aes_cts_decrypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// The explicit confounder keeps tests deterministic and lets callers wire
    /// in their own randomness policy. The returned bytes are ciphertext plus
    /// the RFC3962 integrity hash.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::InvalidConfounderLength`] when `confounder` is not
    /// [`Self::confounder_len`] bytes long.
    #[inline]
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        if confounder.len() != Self::confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: Self::confounder_len(),
                actual: confounder.len(),
            });
        }

        let plain = [confounder, message].concat();

        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let (_, mut encrypted) = self.encrypt_data(&encryption_key, &plain)?;
        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        encrypted.extend_from_slice(&hmac_sha1_96(&integrity_key, &plain));
        Ok(encrypted)
    }

    /// Decrypt a Kerberos message and verify its RFC3962 integrity hash.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// [`Error::CiphertextTooShort`] when `ciphertext` cannot hold a confounder and an
    /// integrity hash, and [`Error::IntegrityCheckFailed`] when the integrity hash does
    /// not match.
    #[inline]
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        self.validate_key(protocol_key)?;
        let (encrypted, mac) = split_trailing_mac(
            ciphertext,
            Self::hmac_len(),
            Self::hmac_len().saturating_add(Self::confounder_len()),
        )?;
        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let plain = self.decrypt_data(&encryption_key, encrypted)?;

        let message = strip_confounder(&plain, Self::confounder_len())?;

        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        let expected = hmac_sha1_96(&integrity_key, &plain);
        if !constant_time_eq(&expected, mac) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(message.to_vec())
    }

    /// Check that `key` has this encryption type's protocol key length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    const fn validate_key(self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// Kerberos RFC8009 AES CTS-HMAC-SHA2 encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AesSha2Etype {
    /// `aes128-cts-hmac-sha256-128`, etype 19.
    Aes128,
    /// `aes256-cts-hmac-sha384-192`, etype 20.
    Aes256,
}

impl AesSha2Etype {
    #[must_use]
    /// Return the AES-SHA2 encryption type for a Kerberos etype id.
    #[inline]
    pub const fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            19 => Some(Self::Aes128),
            20 => Some(Self::Aes256),
            _ => None,
        }
    }

    #[must_use]
    /// Kerberos encryption type ID.
    #[inline]
    pub const fn etype_id(self) -> i32 {
        match self {
            Self::Aes128 => 19,
            Self::Aes256 => 20,
        }
    }

    #[must_use]
    /// Kerberos checksum type ID.
    #[inline]
    pub const fn checksum_type_id(self) -> i32 {
        match self {
            Self::Aes128 => 19,
            Self::Aes256 => 20,
        }
    }

    #[must_use]
    /// RFC8009 encryption type name used when building saltp.
    #[inline]
    pub const fn ename(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128-cts-hmac-sha256-128",
            Self::Aes256 => "aes256-cts-hmac-sha384-192",
        }
    }

    #[must_use]
    /// Protocol base key size in bytes.
    #[inline]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    #[must_use]
    /// Confounder size in bytes.
    #[inline]
    pub const fn confounder_len() -> usize {
        AES_BLOCK_SIZE
    }

    #[must_use]
    /// Truncated HMAC size in bytes.
    #[inline]
    pub const fn hmac_len(self) -> usize {
        match self {
            Self::Aes128 => HMAC_SHA256_128_SIZE,
            Self::Aes256 => HMAC_SHA384_192_SIZE,
        }
    }

    #[must_use]
    /// Default RFC8009 string-to-key parameters, encoded as big-endian hex.
    #[inline]
    pub const fn default_s2kparams() -> &'static str {
        DEFAULT_RFC8009_S2KPARAMS
    }

    #[must_use]
    /// Return the RFC8009 saltp value for this encryption type.
    #[inline]
    pub fn saltp(self, salt: &[u8]) -> Vec<u8> {
        let mut saltp = Vec::with_capacity(
            self.ename()
                .len()
                .saturating_add(1)
                .saturating_add(salt.len()),
        );
        saltp.extend_from_slice(self.ename().as_bytes());
        saltp.push(0);
        saltp.extend_from_slice(salt);
        saltp
    }

    #[must_use]
    /// Derive the PBKDF2 intermediate key for RFC8009 string-to-key.
    #[inline]
    pub fn string_to_pbkdf2(self, secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0; self.key_len()];
        match self {
            Self::Aes128 => pbkdf2::pbkdf2_hmac::<Sha256>(secret, salt, iterations, &mut out),
            Self::Aes256 => pbkdf2::pbkdf2_hmac::<Sha384>(secret, salt, iterations, &mut out),
        }
        out
    }

    /// Derive an AES protocol key from a password and salt.
    ///
    /// RFC8009 prepends the encryption type name and a NUL byte to the supplied
    /// salt before PBKDF2.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidS2kParamsLength`], [`Error::InvalidS2kParamsHex`] or
    /// [`Error::UnsupportedIterationCountZero`] for unusable `s2kparams`.
    #[inline]
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        let iterations = s2kparams_to_iterations(s2kparams)?;
        let saltp = self.saltp(salt);
        let tkey = self.string_to_pbkdf2(secret, &saltp, iterations);
        self.derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// Derive a usage-specific key from a protocol key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `label` is empty.
    #[inline]
    pub fn derive_key(self, protocol_key: &[u8], label: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if label.is_empty() {
            return Err(Error::EmptyUsage);
        }

        Ok(self.kdf_hmac_sha2(protocol_key, label, &[], self.derive_key_len(label)))
    }

    /// RFC8009 PRF derivation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `usage` is empty.
    #[inline]
    pub fn derive_random(self, protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }

        Ok(self.kdf_hmac_sha2(protocol_key, b"prf", usage, self.hash_len()))
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long.
    #[inline]
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = self.derive_key(protocol_key, &usage_constant(usage, 0x99))?;
        Ok(self.truncated_hmac(&key, data))
    }

    #[must_use]
    /// Verify a keyed checksum.
    #[inline]
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        self.checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with RFC8009 AES-CTS and a zero initial IV.
    ///
    /// The key is the derived encryption key, not the protocol base key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyPlaintext`] when `plaintext` is empty.
    #[inline]
    pub fn encrypt_data(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_encrypt_key(key)?;
        aes_cts_encrypt(key, plaintext)
    }

    /// Decrypt raw bytes with RFC8009 AES-CTS and a zero initial IV.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long,
    /// and [`Error::CiphertextTooShort`] when `ciphertext` is shorter than one AES block.
    #[inline]
    pub fn decrypt_data(self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.validate_encrypt_key(key)?;
        aes_cts_decrypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// RFC8009 calculates integrity over a zero IV followed by the AES output,
    /// rather than over confounder-plus-plaintext as RFC3962 does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::InvalidConfounderLength`] when `confounder` is not
    /// [`Self::confounder_len`] bytes long.
    #[inline]
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        if confounder.len() != Self::confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: Self::confounder_len(),
                actual: confounder.len(),
            });
        }

        let plain = [confounder, message].concat();

        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let (_, mut encrypted) = self.encrypt_data(&encryption_key, &plain)?;
        let mac = self.integrity_hash(protocol_key, usage, &encrypted)?;
        encrypted.extend_from_slice(&mac);
        Ok(encrypted)
    }

    /// Decrypt a Kerberos message and verify its RFC8009 integrity hash.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// [`Error::CiphertextTooShort`] when `ciphertext` cannot hold a confounder and an
    /// integrity hash, and [`Error::IntegrityCheckFailed`] when the integrity hash does
    /// not match.
    #[inline]
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        self.validate_protocol_key(protocol_key)?;
        let (encrypted, mac) = split_trailing_mac(
            ciphertext,
            self.hmac_len(),
            self.hmac_len().saturating_add(Self::confounder_len()),
        )?;
        let encryption_key = self.derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let plain = self.decrypt_data(&encryption_key, encrypted)?;

        let message = strip_confounder(&plain, Self::confounder_len())?;

        let expected = self.integrity_hash(protocol_key, usage, encrypted)?;
        if !constant_time_eq(&expected, mac) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(message.to_vec())
    }

    /// Output length in bytes of the RFC8009 key derivation for `label`.
    ///
    /// AES-256 derives 256-bit base and encryption keys but 192-bit integrity
    /// and checksum keys.
    fn derive_key_len(self, label: &[u8]) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 if label == KERBEROS_CONSTANT => 32,
            Self::Aes256 if label.last() == Some(&0xaa) => 32,
            Self::Aes256 => 24,
        }
    }

    /// Output size in bytes of the untruncated HMAC hash.
    const fn hash_len(self) -> usize {
        match self {
            Self::Aes128 => 32,
            Self::Aes256 => 48,
        }
    }

    /// RFC8009 `KDF-HMAC-SHA2` with its output truncated to `output_len` bytes.
    ///
    /// `output_len` never exceeds [`Self::hash_len`], so the single HMAC block
    /// the RFC8009 KDF computes always covers it.
    fn kdf_hmac_sha2(
        self,
        protocol_key: &[u8],
        label: &[u8],
        context: &[u8],
        output_len: usize,
    ) -> Vec<u8> {
        // The KDF encodes the output length in bits as a 32-bit big-endian
        // integer. Lengths here are at most 48 bytes, so saturation never
        // happens; it only rules out a silent wrap.
        let output_bits = u32::try_from(output_len)
            .unwrap_or(u32::MAX)
            .saturating_mul(8);
        let mut input =
            Vec::with_capacity(label.len().saturating_add(context.len()).saturating_add(9));
        input.extend_from_slice(&1_u32.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(context);
        input.extend_from_slice(&output_bits.to_be_bytes());

        let mut output = match self {
            Self::Aes128 => hmac_sha256(protocol_key, &input),
            Self::Aes256 => hmac_sha384(protocol_key, &input),
        };
        output.truncate(output_len);
        output
    }

    /// RFC8009 integrity hash over a zero IV followed by `encrypted`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not
    /// [`Self::key_len`] bytes long.
    fn integrity_hash(
        self,
        protocol_key: &[u8],
        usage: u32,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let integrity_key = self.derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        let data = [ZERO_AES_IV.as_slice(), encrypted].concat();
        Ok(self.truncated_hmac(&integrity_key, &data))
    }

    /// HMAC-SHA2 of `data` truncated to [`Self::hmac_len`] bytes.
    fn truncated_hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = match self {
            Self::Aes128 => hmac_sha256(key, data),
            Self::Aes256 => hmac_sha384(key, data),
        };
        mac.truncate(self.hmac_len());
        mac
    }

    /// Check that `key` has this encryption type's protocol key length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    const fn validate_protocol_key(self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }

    /// Check the length of a derived RFC8009 encryption key.
    ///
    /// The derived encryption key has the protocol key length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    const fn validate_encrypt_key(self, key: &[u8]) -> Result<(), Error> {
        self.validate_protocol_key(key)
    }
}

/// Kerberos RFC3961 DES3-CBC-SHA1-KD encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Des3CbcSha1KdEtype;

impl Default for Des3CbcSha1KdEtype {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Des3CbcSha1KdEtype {
    /// Creates the Triple-DES encryption type descriptor.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    /// Return the DES3 encryption type for a Kerberos etype id.
    #[inline]
    pub const fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            16 => Some(Self),
            _ => None,
        }
    }

    #[must_use]
    /// Return the DES3 encryption type for a Kerberos checksum type id.
    #[inline]
    pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            12 => Some(Self),
            _ => None,
        }
    }

    #[must_use]
    /// Kerberos encryption type ID.
    #[inline]
    pub const fn etype_id() -> i32 {
        16
    }

    #[must_use]
    /// Kerberos checksum type ID.
    #[inline]
    pub const fn checksum_type_id() -> i32 {
        12
    }

    #[must_use]
    /// Protocol key size in bytes.
    #[inline]
    pub const fn key_len() -> usize {
        DES3_KEY_SIZE
    }

    #[must_use]
    /// Confounder size in bytes.
    #[inline]
    pub const fn confounder_len() -> usize {
        DES3_BLOCK_SIZE
    }

    #[must_use]
    /// HMAC-SHA1 size in bytes.
    #[inline]
    pub const fn hmac_len() -> usize {
        HMAC_SHA1_SIZE
    }

    #[must_use]
    /// DES3 string-to-key parameters must be empty.
    #[inline]
    pub const fn default_s2kparams() -> &'static str {
        DEFAULT_DES3_S2KPARAMS
    }

    /// Derive a DES3 protocol key from a password and salt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NonEmptyDes3S2kParams`] when `s2kparams` is not empty.
    #[inline]
    pub fn string_to_key(secret: &[u8], salt: &[u8], s2kparams: &str) -> Result<Vec<u8>, Error> {
        if !s2kparams.is_empty() {
            return Err(Error::NonEmptyDes3S2kParams);
        }

        let input = [secret, salt].concat();

        let folded = nfold(&input, DES3_SEED_SIZE * 8)?;
        let tkey = Self::random_to_key(&folded)?;
        Self::derive_key(&tkey, KERBEROS_CONSTANT)
    }

    /// Convert 21 seed bytes into a DES3 key with DES parity and weak-key fixups.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSeedLength`] unless `bytes` is 21 bytes long.
    #[inline]
    pub fn random_to_key(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        des3_random_to_key(bytes)
    }

    /// Derive a usage-specific key from a protocol key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `usage` is empty.
    #[inline]
    pub fn derive_key(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        let random = Self::derive_random(protocol_key, usage)?;
        Self::random_to_key(&random)
    }

    /// RFC3961 DR function for DES3.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `usage` is empty.
    #[inline]
    pub fn derive_random(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }

        let folded_usage = nfold(usage, DES3_BLOCK_SIZE * 8)?;
        let mut out = Vec::with_capacity(DES3_SEED_SIZE);
        let (_, mut block) = Self::encrypt_data(protocol_key, &folded_usage)?;

        while out.len() < DES3_SEED_SIZE {
            let remaining = DES3_SEED_SIZE.saturating_sub(out.len());
            out.extend(block.iter().take(remaining));
            if out.len() < DES3_SEED_SIZE {
                let (_, next) = Self::encrypt_data(protocol_key, &block)?;
                block = next;
            }
        }

        Ok(out)
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long.
    #[inline]
    pub fn checksum(protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        let key = Self::derive_key(protocol_key, &usage_constant(usage, 0x99))?;
        Ok(hmac_sha1(&key, data))
    }

    #[must_use]
    /// Verify a keyed checksum.
    #[inline]
    pub fn verify_checksum(protocol_key: &[u8], data: &[u8], checksum: &[u8], usage: u32) -> bool {
        Self::checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with DES3-CBC and a zero initial IV.
    ///
    /// Returns `(next_iv, ciphertext)`, matching gokrb5's DES3-CBC helper.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyPlaintext`] when `plaintext` is empty.
    #[inline]
    pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Self::validate_key(key)?;
        des3_cbc_encrypt(key, plaintext)
    }

    /// Decrypt raw bytes with DES3-CBC and a zero initial IV.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long,
    /// [`Error::CiphertextTooShort`] when `ciphertext` is shorter than one DES3 block, and
    /// [`Error::InvalidCiphertextBlockSize`] when it is not a whole number of blocks.
    #[inline]
    pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Self::validate_key(key)?;
        des3_cbc_decrypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// The returned bytes are zero-padded DES3-CBC ciphertext plus the RFC3961
    /// HMAC-SHA1 integrity hash over the padded confounder-plus-message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::InvalidConfounderLength`] when `confounder` is not
    /// [`Self::confounder_len`] bytes long.
    #[inline]
    pub fn encrypt_message_with_confounder(
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        if confounder.len() != Self::confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: Self::confounder_len(),
                actual: confounder.len(),
            });
        }

        let mut plain = [confounder, message].concat();
        zero_pad(&mut plain, DES3_BLOCK_SIZE);

        let encryption_key = Self::derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let (_, mut encrypted) = Self::encrypt_data(&encryption_key, &plain)?;
        let integrity_key = Self::derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        encrypted.extend_from_slice(&hmac_sha1(&integrity_key, &plain));
        Ok(encrypted)
    }

    /// Decrypt a Kerberos message and verify its RFC3961 integrity hash.
    ///
    /// Like gokrb5, this returns the decrypted message after the confounder and
    /// preserves any zero padding added before encryption.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// [`Error::CiphertextTooShort`] when `ciphertext` cannot hold a confounder and an
    /// integrity hash, and [`Error::IntegrityCheckFailed`] when the integrity hash does
    /// not match.
    #[inline]
    pub fn decrypt_message(
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        let (encrypted, mac) = split_trailing_mac(
            ciphertext,
            Self::hmac_len(),
            Self::hmac_len().saturating_add(Self::confounder_len()),
        )?;
        let encryption_key = Self::derive_key(protocol_key, &usage_constant(usage, 0xaa))?;
        let plain = Self::decrypt_data(&encryption_key, encrypted)?;

        let message = strip_confounder(&plain, Self::confounder_len())?;

        let integrity_key = Self::derive_key(protocol_key, &usage_constant(usage, 0x55))?;
        let expected = hmac_sha1(&integrity_key, &plain);
        if !constant_time_eq(&expected, mac) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(message.to_vec())
    }

    /// Check that `key` has the DES3 protocol key length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    const fn validate_key(key: &[u8]) -> Result<(), Error> {
        if key.len() != Self::key_len() {
            return Err(Error::InvalidKeyLength {
                expected: Self::key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// Kerberos RFC4757 RC4-HMAC encryption type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Rc4HmacEtype;

impl Default for Rc4HmacEtype {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Rc4HmacEtype {
    /// Creates the RC4-HMAC encryption type descriptor.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    /// Return the RC4-HMAC encryption type for a Kerberos etype id.
    #[inline]
    pub const fn from_etype_id(etype_id: i32) -> Option<Self> {
        match etype_id {
            23 => Some(Self),
            _ => None,
        }
    }

    #[must_use]
    /// Return the RC4-HMAC encryption type for a Kerberos checksum type id.
    #[inline]
    pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            -138 => Some(Self),
            _ => None,
        }
    }

    #[must_use]
    /// Kerberos encryption type ID.
    #[inline]
    pub const fn etype_id() -> i32 {
        23
    }

    #[must_use]
    /// Kerberos checksum type ID.
    #[inline]
    pub const fn checksum_type_id() -> i32 {
        -138
    }

    #[must_use]
    /// Protocol key size in bytes.
    #[inline]
    pub const fn key_len() -> usize {
        RC4_HMAC_KEY_SIZE
    }

    #[must_use]
    /// Confounder size in bytes.
    #[inline]
    pub const fn confounder_len() -> usize {
        RC4_HMAC_CONFOUNDER_SIZE
    }

    #[must_use]
    /// HMAC-MD5 size in bytes.
    #[inline]
    pub const fn hmac_len() -> usize {
        HMAC_MD5_SIZE
    }

    #[must_use]
    /// Default RFC4757 string-to-key parameters.
    #[inline]
    pub const fn default_s2kparams() -> &'static str {
        DEFAULT_RC4_HMAC_S2KPARAMS
    }

    /// Derive an RC4-HMAC protocol key from a password.
    ///
    /// RFC4757 ignores salt and string-to-key parameters and hashes the
    /// password's UTF-16LE form with MD4.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidStringToKeySecret`] when `secret` is not valid UTF-8.
    #[inline]
    pub fn string_to_key(secret: &[u8], _salt: &[u8], _s2kparams: &str) -> Result<Vec<u8>, Error> {
        let Ok(password) = str::from_utf8(secret) else {
            return Err(Error::InvalidStringToKeySecret);
        };
        let mut utf16le = Vec::with_capacity(password.len().saturating_mul(2));
        for unit in password.encode_utf16() {
            utf16le.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(Md4::digest(&utf16le).to_vec())
    }

    #[must_use]
    /// Convert random bytes into an RC4-HMAC key.
    #[inline]
    pub fn random_to_key(bytes: &[u8]) -> Vec<u8> {
        Md4::digest(bytes).to_vec()
    }

    /// Derive a usage-specific key from a protocol key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::EmptyUsage`] when `usage` is empty.
    #[inline]
    pub fn derive_key(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        if usage.is_empty() {
            return Err(Error::EmptyUsage);
        }
        Ok(hmac_md5(protocol_key, usage))
    }

    /// Calculate the RFC4757 keyed checksum for message bytes and a key usage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long.
    #[inline]
    pub fn checksum(protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        Ok(kerb_checksum_hmac_md5(protocol_key, data, usage))
    }

    #[must_use]
    /// Verify an RFC4757 keyed checksum.
    #[inline]
    pub fn verify_checksum(protocol_key: &[u8], data: &[u8], checksum: &[u8], usage: u32) -> bool {
        Self::checksum(protocol_key, data, usage)
            .is_ok_and(|expected| constant_time_eq(&expected, checksum))
    }

    /// Encrypt raw bytes with RC4.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    #[inline]
    pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        Self::validate_key(key)?;
        rc4_hmac_crypt(key, plaintext)
    }

    /// Decrypt raw bytes with RC4.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    #[inline]
    pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Self::validate_key(key)?;
        rc4_hmac_crypt(key, ciphertext)
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// The returned bytes are the 16-byte HMAC-MD5 checksum followed by the
    /// RC4 encrypted confounder-plus-message payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// and [`Error::InvalidConfounderLength`] when `confounder` is not
    /// [`Self::confounder_len`] bytes long.
    #[inline]
    pub fn encrypt_message_with_confounder(
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        if confounder.len() != Self::confounder_len() {
            return Err(Error::InvalidConfounderLength {
                expected: Self::confounder_len(),
                actual: confounder.len(),
            });
        }

        let plain = [confounder, message].concat();

        let usage_key = hmac_md5(protocol_key, &rc4_hmac_usage_to_ms_msg_type(usage));
        let checksum = hmac_md5(&usage_key, &plain);
        let encryption_key = hmac_md5(&usage_key, &checksum);
        let encrypted = rc4_hmac_crypt(&encryption_key, &plain)?;

        Ok([checksum, encrypted].concat())
    }

    /// Decrypt a Kerberos message and verify its RFC4757 integrity checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `protocol_key` is not [`Self::key_len`] bytes long,
    /// [`Error::CiphertextTooShort`] when `ciphertext` cannot hold a confounder and an
    /// integrity hash, and [`Error::IntegrityCheckFailed`] when the integrity hash does
    /// not match.
    #[inline]
    pub fn decrypt_message(
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        Self::validate_key(protocol_key)?;
        let minimum = Self::hmac_len().saturating_add(Self::confounder_len());
        let Some((checksum, encrypted)) = ciphertext
            .split_at_checked(Self::hmac_len())
            .filter(|_| ciphertext.len() >= minimum)
        else {
            return Err(Error::CiphertextTooShort {
                minimum,
                actual: ciphertext.len(),
            });
        };
        let usage_key = hmac_md5(protocol_key, &rc4_hmac_usage_to_ms_msg_type(usage));
        let encryption_key = hmac_md5(&usage_key, checksum);
        let plain = rc4_hmac_crypt(&encryption_key, encrypted)?;

        let message = strip_confounder(&plain, Self::confounder_len())?;

        let expected = hmac_md5(&usage_key, &plain);
        if !constant_time_eq(&expected, checksum) {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(message.to_vec())
    }

    /// Check that `key` has the RC4-HMAC protocol key length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyLength`] when `key` is not [`Self::key_len`] bytes long.
    const fn validate_key(key: &[u8]) -> Result<(), Error> {
        if key.len() != Self::key_len() {
            return Err(Error::InvalidKeyLength {
                expected: Self::key_len(),
                actual: key.len(),
            });
        }
        Ok(())
    }
}

/// Kerberos encryption type supported by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KerberosEtype {
    /// RFC3962 AES-SHA1 etype.
    Sha1(AesSha1Etype),
    /// RFC8009 AES-SHA2 etype.
    Sha2(AesSha2Etype),
    /// RFC3961 DES3-CBC-SHA1-KD etype.
    Des3CbcSha1Kd(Des3CbcSha1KdEtype),
    /// RFC4757 RC4-HMAC etype.
    Rc4Hmac(Rc4HmacEtype),
}

impl KerberosEtype {
    /// Return a supported encryption type for a Kerberos etype id.
    #[inline]
    pub fn from_etype_id(etype_id: i32) -> Option<Self> {
        AesSha1Etype::from_etype_id(etype_id)
            .map(Self::Sha1)
            .or_else(|| AesSha2Etype::from_etype_id(etype_id).map(Self::Sha2))
            .or_else(|| Des3CbcSha1KdEtype::from_etype_id(etype_id).map(Self::Des3CbcSha1Kd))
            .or_else(|| Rc4HmacEtype::from_etype_id(etype_id).map(Self::Rc4Hmac))
    }

    /// Return a supported encryption type for a Kerberos checksum type id.
    #[inline]
    pub fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self> {
        match checksum_type_id {
            12 => Some(Self::Des3CbcSha1Kd(Des3CbcSha1KdEtype)),
            15 => Some(Self::Sha1(AesSha1Etype::Aes128)),
            16 => Some(Self::Sha1(AesSha1Etype::Aes256)),
            19 => Some(Self::Sha2(AesSha2Etype::Aes128)),
            20 => Some(Self::Sha2(AesSha2Etype::Aes256)),
            _ => Rc4HmacEtype::from_checksum_type_id(checksum_type_id).map(Self::Rc4Hmac),
        }
    }

    #[must_use]
    /// Kerberos encryption type ID.
    #[inline]
    pub const fn etype_id(self) -> i32 {
        match self {
            Self::Sha1(etype) => etype.etype_id(),
            Self::Sha2(etype) => etype.etype_id(),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::etype_id(),
            Self::Rc4Hmac(_) => Rc4HmacEtype::etype_id(),
        }
    }

    #[must_use]
    /// Kerberos checksum type ID.
    #[inline]
    pub const fn checksum_type_id(self) -> i32 {
        match self {
            Self::Sha1(etype) => etype.checksum_type_id(),
            Self::Sha2(etype) => etype.checksum_type_id(),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::checksum_type_id(),
            Self::Rc4Hmac(_) => Rc4HmacEtype::checksum_type_id(),
        }
    }

    #[must_use]
    /// Protocol base key size in bytes.
    #[inline]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Sha1(etype) => etype.key_len(),
            Self::Sha2(etype) => etype.key_len(),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::key_len(),
            Self::Rc4Hmac(_) => Rc4HmacEtype::key_len(),
        }
    }

    #[must_use]
    /// Confounder size in bytes.
    #[inline]
    pub const fn confounder_len(self) -> usize {
        match self {
            Self::Sha1(_) => AesSha1Etype::confounder_len(),
            Self::Sha2(_) => AesSha2Etype::confounder_len(),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::confounder_len(),
            Self::Rc4Hmac(_) => Rc4HmacEtype::confounder_len(),
        }
    }

    #[must_use]
    /// Truncated HMAC size in bytes.
    #[inline]
    pub const fn hmac_len(self) -> usize {
        match self {
            Self::Sha1(_) => AesSha1Etype::hmac_len(),
            Self::Sha2(etype) => etype.hmac_len(),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::hmac_len(),
            Self::Rc4Hmac(_) => Rc4HmacEtype::hmac_len(),
        }
    }

    #[must_use]
    /// Default string-to-key parameters, encoded as big-endian hex.
    #[inline]
    pub const fn default_s2kparams(self) -> &'static str {
        match self {
            Self::Sha1(_) => AesSha1Etype::default_s2kparams(),
            Self::Sha2(_) => AesSha2Etype::default_s2kparams(),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::default_s2kparams(),
            Self::Rc4Hmac(_) => Rc4HmacEtype::default_s2kparams(),
        }
    }

    /// Derive a protocol key from a password and salt.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] reported by the wrapped encryption type's
    /// `string_to_key`.
    #[inline]
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => etype.string_to_key(secret, salt, s2kparams),
            Self::Sha2(etype) => etype.string_to_key(secret, salt, s2kparams),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::string_to_key(secret, salt, s2kparams),
            Self::Rc4Hmac(_) => Rc4HmacEtype::string_to_key(secret, salt, s2kparams),
        }
    }

    /// Calculate the keyed checksum for message bytes and a Kerberos key usage.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] reported by the wrapped encryption type's
    /// `checksum`.
    #[inline]
    pub fn checksum(self, protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => etype.checksum(protocol_key, data, usage),
            Self::Sha2(etype) => etype.checksum(protocol_key, data, usage),
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::checksum(protocol_key, data, usage),
            Self::Rc4Hmac(_) => Rc4HmacEtype::checksum(protocol_key, data, usage),
        }
    }

    #[must_use]
    /// Verify a keyed checksum.
    #[inline]
    pub fn verify_checksum(
        self,
        protocol_key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> bool {
        match self {
            Self::Sha1(etype) => etype.verify_checksum(protocol_key, data, checksum, usage),
            Self::Sha2(etype) => etype.verify_checksum(protocol_key, data, checksum, usage),
            Self::Des3CbcSha1Kd(_) => {
                Des3CbcSha1KdEtype::verify_checksum(protocol_key, data, checksum, usage)
            }
            Self::Rc4Hmac(_) => Rc4HmacEtype::verify_checksum(protocol_key, data, checksum, usage),
        }
    }

    /// Encrypt a Kerberos message with an explicit confounder.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] reported by the wrapped encryption type's
    /// `encrypt_message_with_confounder`.
    #[inline]
    pub fn encrypt_message_with_confounder(
        self,
        protocol_key: &[u8],
        message: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => {
                etype.encrypt_message_with_confounder(protocol_key, message, usage, confounder)
            }
            Self::Sha2(etype) => {
                etype.encrypt_message_with_confounder(protocol_key, message, usage, confounder)
            }
            Self::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::encrypt_message_with_confounder(
                protocol_key,
                message,
                usage,
                confounder,
            ),
            Self::Rc4Hmac(_) => Rc4HmacEtype::encrypt_message_with_confounder(
                protocol_key,
                message,
                usage,
                confounder,
            ),
        }
    }

    /// Decrypt a Kerberos message and verify its integrity hash.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] reported by the wrapped encryption type's
    /// `decrypt_message`.
    #[inline]
    pub fn decrypt_message(
        self,
        protocol_key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Sha1(etype) => etype.decrypt_message(protocol_key, ciphertext, usage),
            Self::Sha2(etype) => etype.decrypt_message(protocol_key, ciphertext, usage),
            Self::Des3CbcSha1Kd(_) => {
                Des3CbcSha1KdEtype::decrypt_message(protocol_key, ciphertext, usage)
            }
            Self::Rc4Hmac(_) => Rc4HmacEtype::decrypt_message(protocol_key, ciphertext, usage),
        }
    }
}

#[must_use]
/// Convert a Kerberos iteration count to RFC3962 string-to-key parameters.
#[inline]
pub fn iterations_to_s2kparams(iterations: u32) -> String {
    hex_encode(&iterations.to_be_bytes())
}

/// Parse RFC3962 string-to-key parameters into an iteration count.
///
/// # Errors
///
/// Returns [`Error::InvalidS2kParamsLength`] unless `s2kparams` has eight
/// characters, [`Error::InvalidS2kParamsHex`] for a non-hex character, and
/// [`Error::UnsupportedIterationCountZero`] for the RFC3962 zero value.
#[inline]
pub fn s2kparams_to_iterations(s2kparams: &str) -> Result<u32, Error> {
    if s2kparams.len() != 8 {
        return Err(Error::InvalidS2kParamsLength(s2kparams.len()));
    }

    let mut bytes = [0; 4];
    for (slot, &[high, low]) in bytes
        .iter_mut()
        .zip(s2kparams.as_bytes().as_chunks::<2>().0)
    {
        *slot = hex_pair(high, low)?;
    }

    let iterations = u32::from_be_bytes(bytes);
    if iterations == 0 {
        return Err(Error::UnsupportedIterationCountZero);
    }
    Ok(iterations)
}

#[must_use]
/// Calculate the RFC4757 `KERB_CHECKSUM_HMAC_MD5` checksum.
///
/// This checksum is used by RC4-HMAC and by Microsoft S4U PA-FOR-USER data.
/// Unlike [`Rc4HmacEtype::checksum`], this accepts arbitrary Kerberos session
/// key lengths because PA-FOR-USER signs with the TGT session key directly.
#[inline]
pub fn kerb_checksum_hmac_md5(protocol_key: &[u8], data: &[u8], usage: u32) -> Vec<u8> {
    let signing_key = hmac_md5(protocol_key, RC4_HMAC_SIGNATURE_KEY);
    let msg_type = rc4_hmac_usage_to_ms_msg_type(usage);
    let md5_input = [msg_type.as_slice(), data].concat();
    let digest = Md5::digest(&md5_input);
    hmac_md5(&signing_key, &digest)
}

/// RFC3961 n-fold operation.
///
/// # Errors
///
/// Returns [`Error::EmptyNfoldInput`] when `input` is empty, and
/// [`Error::InvalidNfoldOutputBits`] when `output_bits` is zero, not a whole number
/// of bytes, or too large to fold `input` into.
#[inline]
pub fn nfold(input: &[u8], output_bits: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Err(Error::EmptyNfoldInput);
    }
    if output_bits == 0 || !output_bits.is_multiple_of(8) {
        return Err(Error::InvalidNfoldOutputBits(output_bits));
    }

    // Both lengths are whole bytes, so the input is repeated
    // lcm(output_len, input_len) / input_len = output_len / gcd times. The
    // division is exact because `output_bits` is a multiple of eight, and the
    // gcd of two non-zero lengths is non-zero.
    let too_large = Error::InvalidNfoldOutputBits(output_bits);
    let output_len = output_bits.div_euclid(8);
    let replicate = output_len
        .checked_div(gcd(output_len, input.len()))
        .ok_or(too_large)?;
    let mut sum_bytes = Vec::with_capacity(input.len().checked_mul(replicate).ok_or(too_large)?);

    for step in 0..replicate {
        sum_bytes.extend_from_slice(&rotate_right(input, step.saturating_mul(13)));
    }

    let mut folded = vec![0; output_len];
    for chunk in sum_bytes.chunks_exact(output_len) {
        folded = ones_complement_addition(&folded, chunk);
    }

    Ok(folded)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            not(feature = "messages"),
            not(feature = "serde"),
            not(feature = "spnego"),
            not(feature = "tokio"),
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            not(feature = "messages"),
            not(feature = "serde"),
            not(feature = "spnego"),
            not(feature = "tokio"),
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::error_impl_error,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Errors produced by Kerberos cryptographic operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// AES key material length did not match the selected encryption type.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected key length.
        expected: usize,
        /// Actual key length.
        actual: usize,
    },

    /// Confounder length did not match the selected encryption type.
    #[error("invalid confounder length: expected {expected} bytes, got {actual}")]
    InvalidConfounderLength {
        /// Expected confounder length.
        expected: usize,
        /// Actual confounder length.
        actual: usize,
    },

    /// Ciphertext was too short for the requested operation.
    #[error("ciphertext too short: expected at least {minimum} bytes, got {actual}")]
    CiphertextTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Decrypted plaintext was too short to remove a confounder.
    #[error("plaintext too short: expected at least {minimum} bytes, got {actual}")]
    PlaintextTooShort {
        /// Minimum accepted byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Message integrity verification failed.
    #[error("integrity verification failed")]
    IntegrityCheckFailed,

    /// String-to-key parameters were not four bytes of hex.
    #[error("invalid s2kparams length: expected 8 hex characters, got {0}")]
    InvalidS2kParamsLength(usize),

    /// String-to-key parameter hex was invalid.
    #[error("invalid s2kparams hex byte: {0}")]
    InvalidS2kParamsHex(char),

    /// RFC3962's zero iteration value means 2^32 iterations and is not run.
    #[error("s2kparams iteration count zero is not supported")]
    UnsupportedIterationCountZero,

    /// RC4-HMAC string-to-key requires a UTF-8 password byte string.
    #[error("RC4-HMAC string-to-key secret must be valid UTF-8")]
    InvalidStringToKeySecret,

    /// DES3 string-to-key parameters are required to be empty.
    #[error("DES3 string-to-key parameters must be empty")]
    NonEmptyDes3S2kParams,

    /// DES3 random-to-key seed material length did not match RFC3961.
    #[error("invalid random-to-key seed length: expected {expected} bytes, got {actual}")]
    InvalidSeedLength {
        /// Expected seed length.
        expected: usize,
        /// Actual seed length.
        actual: usize,
    },

    /// The n-fold input was empty.
    #[error("n-fold input must not be empty")]
    EmptyNfoldInput,

    /// The n-fold usage constant was empty.
    #[error("key usage constant must not be empty")]
    EmptyUsage,

    /// The n-fold output size was not a positive whole number of bytes.
    #[error("invalid n-fold output bit count: {0}")]
    InvalidNfoldOutputBits(usize),

    /// Data encryption needs at least one plaintext byte.
    #[error("plaintext must not be empty")]
    EmptyPlaintext,

    /// CBC ciphertext was not an exact multiple of the selected block size.
    #[error("ciphertext length {actual} is not a multiple of {block_size}")]
    InvalidCiphertextBlockSize {
        /// Required block size.
        block_size: usize,
        /// Actual ciphertext length.
        actual: usize,
    },
}

/// Split `ciphertext` into its encrypted part and the trailing `mac_len`-byte
/// integrity hash.
///
/// # Errors
///
/// Returns [`Error::CiphertextTooShort`] when `ciphertext` is shorter than
/// `minimum` bytes.
fn split_trailing_mac(
    ciphertext: &[u8],
    mac_len: usize,
    minimum: usize,
) -> Result<(&[u8], &[u8]), Error> {
    ciphertext
        .len()
        .checked_sub(mac_len)
        .filter(|_| ciphertext.len() >= minimum)
        .and_then(|encrypted_len| ciphertext.split_at_checked(encrypted_len))
        .ok_or(Error::CiphertextTooShort {
            minimum,
            actual: ciphertext.len(),
        })
}

/// Return the message that follows the `confounder_len`-byte confounder in
/// decrypted `plain`.
///
/// # Errors
///
/// Returns [`Error::PlaintextTooShort`] when `plain` is shorter than the
/// confounder.
fn strip_confounder(plain: &[u8], confounder_len: usize) -> Result<&[u8], Error> {
    plain.get(confounder_len..).ok_or(Error::PlaintextTooShort {
        minimum: confounder_len,
        actual: plain.len(),
    })
}

/// Key the block or stream cipher `C` with `key`.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyLength`], naming the key size of `C`, when `key`
/// does not have that size.
fn keyed_cipher<C>(key: &[u8]) -> Result<C, Error>
where
    C: KeyInit,
{
    C::new_from_slice(key).map_err(|InvalidLength| Error::InvalidKeyLength {
        expected: C::key_size(),
        actual: key.len(),
    })
}

/// RFC3962 AES-CTS (CBC with ciphertext stealing) encryption with a zero IV.
///
/// Returns `(next_iv, ciphertext)`, where `next_iv` is the last CBC output
/// block. Like gokrb5, a plaintext of at most one block is zero-padded to a
/// whole block and returned without stealing.
///
/// # Errors
///
/// Returns [`Error::EmptyPlaintext`] for an empty `plaintext`, and
/// [`Error::InvalidKeyLength`] when `key` is neither 16 nor 32 bytes long.
fn aes_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let mut padded = plaintext.to_vec();
    zero_pad(&mut padded, AES_BLOCK_SIZE);

    // CTS is CBC over the zero-padded input with the last two output blocks
    // swapped and the result cut back to the input length.
    let (mut ciphertext, last_block) = match key.len() {
        AES128_KEY_SIZE => cbc_encrypt(&keyed_cipher::<aes::Aes128>(key)?, &padded),
        _ => cbc_encrypt(&keyed_cipher::<aes::Aes256>(key)?, &padded),
    };
    if plaintext.len() > AES_BLOCK_SIZE {
        swap_last_two_blocks(&mut ciphertext);
        ciphertext.truncate(plaintext.len());
    }

    Ok((last_block.to_vec(), ciphertext))
}

/// RFC3962 AES-CTS decryption with a zero IV.
///
/// # Errors
///
/// Returns [`Error::CiphertextTooShort`] when `ciphertext` is shorter than one
/// AES block, and [`Error::InvalidKeyLength`] when `key` is neither 16 nor 32
/// bytes long.
fn aes_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(Error::CiphertextTooShort {
            minimum: AES_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }

    match key.len() {
        AES128_KEY_SIZE => Ok(cts_decrypt(&keyed_cipher::<aes::Aes128>(key)?, ciphertext)),
        _ => Ok(cts_decrypt(&keyed_cipher::<aes::Aes256>(key)?, ciphertext)),
    }
}

/// CTS-decrypt `ciphertext` of at least one block with `cipher` and a zero IV.
fn cts_decrypt<C>(cipher: &C, ciphertext: &[u8]) -> Vec<u8>
where
    C: BlockCipherDecrypt<BlockSize = U16>,
{
    let (blocks, last_partial) = ciphertext.as_chunks::<AES_BLOCK_SIZE>();
    let Some((penultimate_cipher, regular_blocks)) =
        blocks.split_last().filter(|_| !last_partial.is_empty())
    else {
        // Whole blocks: undo the swap of the last two blocks, then plain CBC.
        let mut swapped = ciphertext.to_vec();
        swap_last_two_blocks(&mut swapped);
        return cbc_decrypt(cipher, &ZERO_AES_IV, &swapped);
    };

    let mut plaintext = cbc_decrypt(cipher, &ZERO_AES_IV, regular_blocks.as_flattened());
    let chain_iv = regular_blocks.last().copied().unwrap_or(ZERO_AES_IV);

    // The penultimate block decrypts to the last plaintext block XOR the last
    // ciphertext block; its tail is the ciphertext the sender stole.
    let mut completed_last_cipher = *penultimate_cipher;
    cipher.decrypt_block((&mut completed_last_cipher).into());
    copy_prefix(&mut completed_last_cipher, last_partial);

    plaintext.extend_from_slice(&cbc_decrypt(cipher, &chain_iv, &completed_last_cipher));
    plaintext.extend_from_slice(&cbc_decrypt(
        cipher,
        &completed_last_cipher,
        penultimate_cipher,
    ));
    plaintext.truncate(ciphertext.len());
    plaintext
}

/// CBC-encrypt the whole AES blocks of `plaintext` with a zero IV.
///
/// Returns the ciphertext and its last block. `plaintext` is a whole number of
/// blocks.
fn cbc_encrypt<C>(cipher: &C, plaintext: &[u8]) -> (Vec<u8>, [u8; AES_BLOCK_SIZE])
where
    C: BlockCipherEncrypt<BlockSize = U16>,
{
    debug_assert!(
        plaintext.len().is_multiple_of(AES_BLOCK_SIZE),
        "CBC input must be a whole number of AES blocks"
    );

    let mut previous = ZERO_AES_IV;
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.as_chunks::<AES_BLOCK_SIZE>().0 {
        let mut block = *chunk;
        xor_in_place(&mut block, &previous);
        cipher.encrypt_block((&mut block).into());
        previous = block;
        out.extend_from_slice(&block);
    }
    (out, previous)
}

/// CBC-decrypt the whole AES blocks of `ciphertext`, chaining from `iv`.
///
/// `ciphertext` is a whole number of blocks.
fn cbc_decrypt<C>(cipher: &C, iv: &[u8; AES_BLOCK_SIZE], ciphertext: &[u8]) -> Vec<u8>
where
    C: BlockCipherDecrypt<BlockSize = U16>,
{
    debug_assert!(
        ciphertext.len().is_multiple_of(AES_BLOCK_SIZE),
        "CBC input must be a whole number of AES blocks"
    );

    let mut previous = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.as_chunks::<AES_BLOCK_SIZE>().0 {
        let mut block = *chunk;
        cipher.decrypt_block((&mut block).into());
        xor_in_place(&mut block, &previous);
        previous = *chunk;
        out.extend_from_slice(&block);
    }
    out
}

/// XOR `mask` into `block` byte by byte, up to the shorter of the two.
fn xor_in_place(block: &mut [u8], mask: &[u8]) {
    for (byte, mask_byte) in block.iter_mut().zip(mask) {
        *byte ^= mask_byte;
    }
}

/// Copy `source` over the start of `target`, up to the shorter of the two.
fn copy_prefix(target: &mut [u8], source: &[u8]) {
    for (slot, byte) in target.iter_mut().zip(source) {
        *slot = *byte;
    }
}

/// DES3-CBC encryption with a zero IV of `plaintext` zero-padded to whole
/// blocks.
///
/// Returns `(next_iv, ciphertext)`, where `next_iv` is the last ciphertext
/// block.
///
/// # Errors
///
/// Returns [`Error::EmptyPlaintext`] for an empty `plaintext`, and
/// [`Error::InvalidKeyLength`] unless `key` is 24 bytes long.
fn des3_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }

    let cipher = keyed_cipher::<TdesEde3>(key)?;
    let mut padded = plaintext.to_vec();
    zero_pad(&mut padded, DES3_BLOCK_SIZE);

    let mut previous = [0; DES3_BLOCK_SIZE];
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.as_chunks::<DES3_BLOCK_SIZE>().0 {
        let mut block = *chunk;
        xor_in_place(&mut block, &previous);
        cipher.encrypt_block((&mut block).into());
        previous = block;
        out.extend_from_slice(&block);
    }

    Ok((previous.to_vec(), out))
}

/// DES3-CBC decryption with a zero IV.
///
/// # Errors
///
/// Returns [`Error::CiphertextTooShort`] when `ciphertext` is shorter than one
/// block, [`Error::InvalidCiphertextBlockSize`] when it is not a whole number
/// of blocks, and [`Error::InvalidKeyLength`] unless `key` is 24 bytes long.
fn des3_cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < DES3_BLOCK_SIZE {
        return Err(Error::CiphertextTooShort {
            minimum: DES3_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }
    if !ciphertext.len().is_multiple_of(DES3_BLOCK_SIZE) {
        return Err(Error::InvalidCiphertextBlockSize {
            block_size: DES3_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }

    let cipher = keyed_cipher::<TdesEde3>(key)?;
    let mut previous = [0; DES3_BLOCK_SIZE];
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.as_chunks::<DES3_BLOCK_SIZE>().0 {
        let mut block = *chunk;
        cipher.decrypt_block((&mut block).into());
        xor_in_place(&mut block, &previous);
        previous = *chunk;
        out.extend_from_slice(&block);
    }

    Ok(out)
}

/// RFC3961 DES3 random-to-key: stretch each 7-byte seed chunk into a DES key
/// with odd parity, then fix up weak keys.
///
/// # Errors
///
/// Returns [`Error::InvalidSeedLength`] unless `bytes` is 21 bytes long.
fn des3_random_to_key(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() != DES3_SEED_SIZE {
        return Err(Error::InvalidSeedLength {
            expected: DES3_SEED_SIZE,
            actual: bytes.len(),
        });
    }

    let mut key = Vec::with_capacity(DES3_KEY_SIZE);
    for seed in bytes.as_chunks::<DES3_SEED_CHUNK_SIZE>().0 {
        let mut block = des3_stretch_56_bits(*seed);
        des3_fix_weak_key(&mut block);
        key.extend_from_slice(&block);
    }
    Ok(key)
}

/// Stretch 56 key bits into an 8-byte DES key with odd parity bits.
///
/// The low bit of each seed byte moves into the eighth byte.
fn des3_stretch_56_bits(bytes: [u8; DES3_SEED_CHUNK_SIZE]) -> [u8; DES3_BLOCK_SIZE] {
    let mut out = [0; DES3_BLOCK_SIZE];
    let mut last_byte = 0;
    for (idx, (slot, byte)) in out.iter_mut().zip(bytes).enumerate() {
        let (lowest_bit, adjusted) = des3_calc_odd_parity(byte);
        *slot = adjusted;
        if lowest_bit != 0 {
            // `idx` is below 7, so the shift stays inside the byte.
            last_byte |= 1 << idx.saturating_add(1);
        }
    }

    let (_, adjusted_last) = des3_calc_odd_parity(last_byte);
    out[DES3_BLOCK_SIZE - 1] = adjusted_last;
    out
}

/// Return the low bit of `byte` and `byte` with its low bit set to make the
/// byte's parity odd.
const fn des3_calc_odd_parity(byte: u8) -> (u8, u8) {
    let lowest_bit = byte & 0x01;
    let adjusted = if (byte & 0xfe).count_ones().is_multiple_of(2) {
        byte | 0x01
    } else {
        byte & 0xfe
    };
    (lowest_bit, adjusted)
}

/// Flip a DES weak or semi-weak key into a usable one (RFC3961 section 6.3.1).
fn des3_fix_weak_key(block: &mut [u8; DES3_BLOCK_SIZE]) {
    if des3_is_weak_key(*block) {
        block[DES3_BLOCK_SIZE - 1] ^= 0xf0;
    }
}

/// Whether `block` is one of the 16 DES weak or semi-weak keys.
fn des3_is_weak_key(block: [u8; DES3_BLOCK_SIZE]) -> bool {
    /// DES weak and semi-weak keys, with odd parity.
    const WEAK_KEYS: [[u8; DES3_BLOCK_SIZE]; 16] = [
        [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
        [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
        [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
        [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
        [0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e],
        [0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01],
        [0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1],
        [0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01],
        [0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe],
        [0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01],
        [0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1],
        [0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e],
        [0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe],
        [0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e],
        [0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe],
        [0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1],
    ];

    WEAK_KEYS.contains(&block)
}

/// Append zero bytes until `bytes` is a whole number of `block_size` blocks.
fn zero_pad(bytes: &mut Vec<u8>, block_size: usize) {
    if let Some(padded_len) = bytes.len().checked_next_multiple_of(block_size) {
        bytes.resize(padded_len, 0);
    }
}

/// Swap the last two AES blocks of `bytes`; shorter input is left unchanged.
fn swap_last_two_blocks(bytes: &mut [u8]) {
    let start = bytes.len().saturating_sub(2 * AES_BLOCK_SIZE);
    if let Some(tail) = bytes.get_mut(start..)
        && let ([penultimate, last], _) = tail.as_chunks_mut::<AES_BLOCK_SIZE>()
    {
        mem::swap(penultimate, last);
    }
}

/// RFC3961 well-known constant for a key usage: the big-endian usage number
/// followed by the `suffix` byte (0x99 checksum, 0xaa encryption, 0x55
/// integrity).
const fn usage_constant(usage: u32, suffix: u8) -> [u8; 5] {
    let [first, second, third, fourth] = usage.to_be_bytes();
    [first, second, third, fourth, suffix]
}

/// Encode the RFC4757 message type for a Kerberos key usage.
///
/// Usages 3 and 9 map to 8 and usage 23 to 13. The value is written seven bits
/// per byte, low bits first, with the high bit set on each byte that is
/// followed by another.
fn rc4_hmac_usage_to_ms_msg_type(usage: u32) -> [u8; 4] {
    let mut remaining = match usage {
        3 | 9 => 8,
        23 => 13,
        _ => usage,
    };

    let mut out = [0; 4];
    for byte in &mut out {
        let [low_byte, ..] = remaining.to_le_bytes();
        if remaining < 0x80 {
            *byte = low_byte;
            break;
        }
        *byte = (low_byte & 0x7f) | 0x80;
        remaining >>= 7_u32;
    }
    out
}

/// Apply the RC4 keystream for `key` to `input`.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyLength`] when RC4 rejects the key length.
fn rc4_hmac_crypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut cipher = Rc4::new_from_slice(key).map_err(|InvalidLength| Error::InvalidKeyLength {
        expected: RC4_HMAC_KEY_SIZE,
        actual: key.len(),
    })?;
    let mut out = input.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

/// HMAC of `data` under a `key` of any length (RFC2104).
///
/// RFC2104 hashes a key longer than the hash block with `H` and zero-pads a
/// shorter one to the block size. Building that block-sized key here lets the
/// infallible `KeyInit::new` take it, with the same result as the fallible
/// slice constructor.
fn hmac_any_key<M, H>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    M: KeyInit + Mac,
    H: Digest,
{
    let mut block_key = Key::<M>::default();
    if key.len() > block_key.len() {
        copy_prefix(&mut block_key, &H::digest(key));
    } else {
        copy_prefix(&mut block_key, key);
    }

    let mut mac = <M as KeyInit>::new(&block_key);
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA1 of `data` truncated to 96 bits.
fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = hmac_sha1(key, data);
    mac.truncate(HMAC_SHA1_96_SIZE);
    mac
}

/// HMAC-SHA1 of `data`.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_any_key::<Hmac<Sha1>, Sha1>(key, data)
}

/// HMAC-MD5 of `data`.
fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_any_key::<Hmac<Md5>, Md5>(key, data)
}

/// HMAC-SHA256 of `data`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_any_key::<Hmac<Sha256>, Sha256>(key, data)
}

/// HMAC-SHA384 of `data`.
fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_any_key::<Hmac<Sha384>, Sha384>(key, data)
}

/// Compare two byte strings without stopping at the first difference.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0;
    for (left_byte, right_byte) in left.iter().zip(right) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

/// Rotate `bytes`, read as one big-endian bit string, right by `steps` bits.
fn rotate_right(bytes: &[u8], steps: usize) -> Vec<u8> {
    let bit_len = bytes.len().saturating_mul(8);
    let mut out = vec![0; bytes.len()];
    for position in 0..bit_len {
        if let Some(target) = position.saturating_add(steps).checked_rem(bit_len) {
            set_bit(&mut out, target, get_bit(bytes, position));
        }
    }
    out
}

/// Add two equal-length big-endian numbers in one's complement, folding the
/// final carry back into the least significant bit (RFC3961 n-fold).
fn ones_complement_addition(left: &[u8], right: &[u8]) -> Vec<u8> {
    debug_assert_eq!(
        left.len(),
        right.len(),
        "one's complement addition needs equal-length operands"
    );

    let mut out = vec![0; left.len()];
    let mut carry = 0_u8;
    for bit_index in (0..left.len().saturating_mul(8)).rev() {
        // Each operand is 0 or 1, so the sum is at most 3.
        let sum = get_bit(left, bit_index)
            .saturating_add(get_bit(right, bit_index))
            .saturating_add(carry);
        set_bit(&mut out, bit_index, sum & 1);
        carry = sum >> 1_u32;
    }

    if carry == 1 {
        let mut carry_array = vec![0; left.len()];
        if let Some(last) = carry_array.last_mut() {
            *last = 1;
        }
        return ones_complement_addition(&out, &carry_array);
    }

    out
}

/// Read bit `position` of `bytes` as 0 or 1, counting from the most
/// significant bit of the first byte; a position past the end reads as 0.
fn get_bit(bytes: &[u8], position: usize) -> u8 {
    let mask = 0x80_u8 >> position.rem_euclid(8);
    bytes
        .get(position.div_euclid(8))
        .map_or(0, |byte| u8::from(byte & mask != 0))
}

/// Set bit `position` of `bytes` when `value` is 1, counting as [`get_bit`]
/// does; a position past the end is ignored.
fn set_bit(bytes: &mut [u8], position: usize, value: u8) {
    if value != 0
        && let Some(byte) = bytes.get_mut(position.div_euclid(8))
    {
        *byte |= 0x80_u8 >> position.rem_euclid(8);
    }
}

/// Greatest common divisor of `left` and `right`.
const fn gcd(mut left: usize, mut right: usize) -> usize {
    while let Some(next) = left.checked_rem(right) {
        left = right;
        right = next;
    }
    left
}

/// Decode two hex digits into one byte.
///
/// # Errors
///
/// Returns [`Error::InvalidS2kParamsHex`] when either byte is not a hex digit.
fn hex_pair(high: u8, low: u8) -> Result<u8, Error> {
    Ok((hex_value(high)? << 4) | hex_value(low)?)
}

/// Decode one ASCII hex digit, either case.
///
/// # Errors
///
/// Returns [`Error::InvalidS2kParamsHex`] when `byte` is not a hex digit.
fn hex_value(byte: u8) -> Result<u8, Error> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
        .ok_or_else(|| Error::InvalidS2kParamsHex(char::from(byte)))
}

/// Encode `bytes` as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4_u32, byte & 0x0f] {
            // A nibble is below 16, so it is always a hex digit.
            if let Some(digit) = char::from_digit(u32::from(nibble), 16) {
                out.push(digit);
            }
        }
    }
    out
}
