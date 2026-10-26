//! Little-endian cursor over a PAC buffer.

use super::{Error, FileTime};

/// Bounds-checked little-endian cursor over a borrowed PAC buffer.
///
/// Invariant: `offset <= bytes.len()`; every method that moves the cursor
/// checks the new position first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Reader<'buffer> {
    /// Whole buffer being decoded.
    bytes: &'buffer [u8],
    /// Position of the next unread byte.
    offset: usize,
}

impl<'buffer> Reader<'buffer> {
    /// Starts a cursor at the beginning of `bytes`.
    pub(super) const fn new(bytes: &'buffer [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Number of bytes after the cursor.
    pub(super) const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Length of the whole buffer.
    pub(super) const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Unread bytes after the cursor.
    pub(super) fn remaining_bytes(&self) -> &'buffer [u8] {
        // The invariant `offset <= len` makes the range valid; an empty slice
        // is the only sensible answer if it were ever broken.
        self.bytes.get(self.offset..).unwrap_or_default()
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when the buffer is exhausted.
    pub(super) fn read_u8(&mut self) -> Result<u8, Error> {
        let [byte] = self.read_array::<1>()?;
        Ok(byte)
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than 2 bytes remain.
    pub(super) fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than 4 bytes remain.
    pub(super) fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than 8 bytes remain.
    pub(super) fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian Windows `FILETIME`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than 8 bytes remain.
    pub(super) fn read_filetime(&mut self) -> Result<FileTime, Error> {
        Ok(FileTime::from_ticks(self.read_u64()?))
    }

    /// Reads exactly `N` bytes into an array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] when fewer than `N` bytes remain.
    pub(super) fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let Some((array, rest)) = self.remaining_bytes().split_first_chunk::<N>() else {
            return Err(Error::Truncated {
                offset: self.offset,
                needed: N,
                remaining: self.remaining(),
            });
        };
        // `rest` is a suffix of `bytes`, so its length never exceeds the
        // buffer length and the subtraction cannot saturate.
        self.offset = self.bytes.len().saturating_sub(rest.len());
        Ok(*array)
    }

    /// Reads `len` bytes as a borrowed slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when `offset + len` overflows and
    /// [`Error::Truncated`] when fewer than `len` bytes remain.
    pub(super) fn read_bytes(&mut self, len: usize) -> Result<&'buffer [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::LengthOverflow)?;
        let Some(out) = self.bytes.get(self.offset..end) else {
            return Err(Error::Truncated {
                offset: self.offset,
                needed: len,
                remaining: self.remaining(),
            });
        };
        self.offset = end;
        Ok(out)
    }

    /// Advances the cursor to the next multiple of `alignment`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAlignment`] unless `alignment` is a non-zero
    /// power of two, [`Error::LengthOverflow`] when the aligned position
    /// overflows `usize`, and [`Error::Truncated`] when it lies past the end
    /// of the buffer.
    pub(super) fn align(&mut self, alignment: usize) -> Result<(), Error> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(Error::InvalidAlignment(alignment));
        }
        let aligned = self
            .offset
            .checked_next_multiple_of(alignment)
            .ok_or(Error::LengthOverflow)?;
        if aligned > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.offset,
                // `aligned >= offset` by construction.
                needed: aligned.saturating_sub(self.offset),
                remaining: self.remaining(),
            });
        }
        self.offset = aligned;
        Ok(())
    }
}
