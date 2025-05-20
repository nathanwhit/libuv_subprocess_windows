use std::ops::{Index, Range, RangeFrom, RangeTo};

pub struct WCString {
    buf: Box<[u16]>,
}

impl WCString {
    pub fn new(s: &str) -> Self {
        let mut buf = Vec::with_capacity(s.len());
        for c in s.encode_utf16() {
            buf.push(c);
        }
        buf.push(0);
        Self {
            buf: buf.into_boxed_slice(),
        }
    }

    pub fn from_vec(vec: Vec<u16>) -> Self {
        if vec.last().unwrap_or(&1) == &0 {
            Self {
                buf: vec.into_boxed_slice(),
            }
        } else {
            let mut buf = vec;
            buf.push(0);
            Self {
                buf: buf.into_boxed_slice(),
            }
        }
    }

    pub fn as_ptr(&self) -> *const u16 {
        self.buf.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u16 {
        self.buf.as_mut_ptr()
    }

    pub fn as_wcstr(&self) -> &WCStr {
        unsafe { WCStr::from_wchars(&self.buf) }
    }
}

#[repr(transparent)]
pub struct WCStr {
    buf: [u16],
}

impl WCStr {
    // pub fn new<B: ?Sized + AsRef<[u16]>(buf: &B) -> &Self {
    // }

    pub fn len(&self) -> usize {
        self.buf.len() - 1
    }

    pub unsafe fn from_wchars(wchars: &[u16]) -> &WCStr {
        unsafe { &*(wchars as *const [u16] as *const WCStr) }
    }

    pub fn as_ptr(&self) -> *const u16 {
        self.buf.as_ptr()
    }

    pub fn wchars_no_null(&self) -> &[u16] {
        &self.buf[..self.buf.len() - 1]
    }
}

impl Index<usize> for WCStr {
    type Output = u16;

    fn index(&self, index: usize) -> &Self::Output {
        &self.buf[index]
    }
}

impl Index<Range<usize>> for WCStr {
    type Output = [u16];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.buf[index]
    }
}

impl Index<RangeTo<usize>> for WCStr {
    type Output = [u16];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.buf[index]
    }
}

impl Index<RangeFrom<usize>> for WCStr {
    type Output = [u16];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.buf[index]
    }
}
