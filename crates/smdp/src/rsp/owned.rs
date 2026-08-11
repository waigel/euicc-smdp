extern "C" {
    #[link_name = "free"]
    fn libc_free(p: *mut core::ffi::c_void);
}

/// A buffer euicc-rsp malloc'd and handed over. Freed here, once.
pub struct OwnedDer {
    ptr: *mut u8,
    len: usize,
}

impl OwnedDer {
    /// # Safety
    /// `ptr` must be a euicc-rsp out-parameter that nothing else frees.
    pub(crate) unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        OwnedDer { ptr, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        // Safety: the pointer and length come together out of one C
        // out-parameter pair and are immutable for this value's life.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for OwnedDer {
    fn drop(&mut self) {
        unsafe { libc_free(self.ptr as *mut core::ffi::c_void) }
    }
}

impl std::fmt::Debug for OwnedDer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnedDer({} bytes)", self.len)
    }
}
