//! I/O buffers that may be guest memory.
//!
//! A virtio request's data lives in guest RAM, which other vCPUs can change
//! while the request is served. Turning it into a Rust `&[u8]` or `&mut [u8]`
//! would assert that nobody else touches it, so these buffers carry a raw
//! pointer instead and are only accessed through system calls and
//! `ptr::copy_nonoverlapping`, never through Rust references.

use std::marker::PhantomData;
use std::ptr;

/// Destination of a read: `len` bytes the backend fills.
pub struct ReadBuf<'a> {
    ptr: *mut u8,
    len: usize,
    _life: PhantomData<&'a mut [u8]>,
}

/// Source of a write: `len` bytes the backend stores.
#[derive(Clone, Copy)]
pub struct WriteBuf<'a> {
    ptr: *const u8,
    len: usize,
    _life: PhantomData<&'a [u8]>,
}

impl<'a> ReadBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> ReadBuf<'a> {
        ReadBuf {
            ptr: buf.as_mut_ptr(),
            len: buf.len(),
            _life: PhantomData,
        }
    }

    /// A buffer over `len` bytes at `ptr`, typically guest RAM.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for writes of `len` bytes for `'a`, and no Rust
    /// reference may cover those bytes meanwhile.
    pub unsafe fn from_raw(ptr: *mut u8, len: usize) -> ReadBuf<'a> {
        ReadBuf {
            ptr,
            len,
            _life: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// The `len` bytes at `start`. Panics if they are out of range.
    pub fn sub(&mut self, start: usize, len: usize) -> ReadBuf<'_> {
        assert!(
            start.checked_add(len).is_some_and(|e| e <= self.len),
            "ReadBuf::sub out of range"
        );
        // SAFETY: in bounds (checked above), and the result borrows `self`
        // mutably, so the two never overlap in use.
        unsafe { ReadBuf::from_raw(self.ptr.add(start), len) }
    }

    /// Fill the buffer from `src`, which must have exactly `len` bytes.
    pub fn copy_from(&mut self, src: &[u8]) {
        assert_eq!(src.len(), self.len, "ReadBuf::copy_from length");
        // SAFETY: `self.ptr` is valid for `len` writes (constructor
        // contract); `src` is a distinct Rust slice of the same length.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), self.ptr, self.len) };
    }
}

impl<'a> WriteBuf<'a> {
    pub fn new(buf: &'a [u8]) -> WriteBuf<'a> {
        WriteBuf {
            ptr: buf.as_ptr(),
            len: buf.len(),
            _life: PhantomData,
        }
    }

    /// A buffer over `len` bytes at `ptr`, typically guest RAM.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for reads of `len` bytes for `'a`.
    pub unsafe fn from_raw(ptr: *const u8, len: usize) -> WriteBuf<'a> {
        WriteBuf {
            ptr,
            len,
            _life: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// The `len` bytes at `start`. Panics if they are out of range.
    pub fn sub(&self, start: usize, len: usize) -> WriteBuf<'a> {
        assert!(
            start.checked_add(len).is_some_and(|e| e <= self.len),
            "WriteBuf::sub out of range"
        );
        // SAFETY: in bounds (checked above); reads only.
        unsafe { WriteBuf::from_raw(self.ptr.add(start), len) }
    }

    /// Copy the buffer into `dst`, which must have exactly `len` bytes.
    pub fn copy_to(&self, dst: &mut [u8]) {
        assert_eq!(dst.len(), self.len, "WriteBuf::copy_to length");
        // SAFETY: `self.ptr` is valid for `len` reads (constructor
        // contract); `dst` is a distinct, exclusively borrowed Rust slice.
        unsafe { ptr::copy_nonoverlapping(self.ptr, dst.as_mut_ptr(), self.len) };
    }

    /// The bytes as a vector (tests and small reads).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = vec![0; self.len];
        self.copy_to(&mut v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_and_copies() {
        let mut dst = [0u8; 8];
        let mut r = ReadBuf::new(&mut dst);
        r.sub(2, 3).copy_from(&[1, 2, 3]);
        assert_eq!(r.len(), 8);
        assert_eq!(dst, [0, 0, 1, 2, 3, 0, 0, 0]);
        let src = [9u8, 8, 7, 6];
        let w = WriteBuf::new(&src);
        assert_eq!(w.sub(1, 2).to_vec(), [8, 7]);
        assert!(w.sub(4, 0).is_empty());
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn sub_out_of_range_panics() {
        let src = [0u8; 4];
        let _ = WriteBuf::new(&src).sub(3, 2);
    }
}
