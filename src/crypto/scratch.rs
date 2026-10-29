//! Internal zeroizing scratch ownership.

use core::{
    mem,
    ops::{Deref, DerefMut},
};

use zeroize::{Zeroize as _, Zeroizing};

/// Internal byte-buffer owner, erased on ordinary drop.
pub(super) struct SecretScratch(Zeroizing<Vec<u8>>);

impl SecretScratch {
    /// Adopt scratch storage without copying it.
    pub(super) fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Transfer the allocation to a caller that assumes cleanup responsibility.
    pub(super) fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut *self.0)
    }
}

impl Deref for SecretScratch {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretScratch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Drop audit: zeroing a heap buffer in place never blocks, allocates or panics
// (the erasure assertion and counter exist only under `cfg(test)`).
impl Drop for SecretScratch {
    /// Erase live bytes; the Zeroizing field also erases spare capacity on drop.
    fn drop(&mut self) {
        let bytes = self.0.as_mut_slice();
        bytes.zeroize();
        #[cfg(test)]
        {
            assert!(
                bytes.iter().all(|byte| *byte == 0),
                "scratch erasure failed"
            );
            super::tests::ERASED_SCRATCH_BYTES
                .with(|count| count.set(count.get().saturating_add(bytes.len())));
        }
    }
}
