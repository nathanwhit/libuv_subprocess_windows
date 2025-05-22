use std::{ffi::c_int, mem::ManuallyDrop, ptr::null_mut};

use buffer::StdioBuffer;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_TYPE_REMOTE,
        FILE_TYPE_UNKNOWN, GetFileType, OPEN_EXISTING,
    },
    System::Threading::GetCurrentProcess,
};

use crate::process::{Error, uv_process_options};

const FOPEN: u8 = 0x01;
const FEOFLAG: u8 = 0x02;
const FCRLF: u8 = 0x04;
const FPIPE: u8 = 0x08;
const FNOINHERIT: u8 = 0x10;
const FAPPEND: u8 = 0x20;
const FDEV: u8 = 0x40;
const FTEXT: u8 = 0x80;

const fn child_stdio_size(count: usize) -> usize {
    (size_of::<c_int>() + size_of::<u8>() * count + size_of::<usize>() * count) as usize
}

unsafe fn child_stdio_count(buffer: *mut u8) -> usize {
    unsafe { *buffer.cast::<std::ffi::c_uint>() as usize }
}

unsafe fn child_stdio_handle(buffer: *mut u8, fd: i32) -> HANDLE {
    unsafe {
        buffer.add(
            size_of::<c_int>() + child_stdio_count(buffer) + size_of::<HANDLE>() * (fd as usize),
        )
    }
    .cast()
}

unsafe fn child_stdio_crt_flags(buffer: *mut u8, fd: i32) -> *mut u8 {
    unsafe { buffer.add(size_of::<c_int>() + fd as usize) }.cast()
}

unsafe fn uv_stdio_verify(buffer: *mut u8, size: u16) -> bool {
    if buffer.is_null() {
        return false;
    }

    if (size as usize) < child_stdio_size(0) {
        return false;
    }

    let count = unsafe { child_stdio_count(buffer) };
    if count > 256 {
        return false;
    }

    if (size as usize) < child_stdio_size(count) {
        return false;
    }

    true
}

unsafe fn uv_create_nul_handle(access: u32) -> Result<HANDLE, Error> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };

    let handle = unsafe {
        CreateFileW(
            windows_sys::w!("NUL"),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::UNKNOWN);
    }

    Ok(handle)
}

unsafe fn uv_stdio_noinherit(buffer: *mut u8) {
    let count = unsafe { child_stdio_count(buffer) };
    for i in 0..count {
        let handle = unsafe { uv_stdio_handle(buffer, i as i32) };
        if handle != INVALID_HANDLE_VALUE {
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}

pub(crate) unsafe fn uv_stdio_size(buffer: *mut u8) -> u16 {
    (child_stdio_size(unsafe { child_stdio_count(buffer) }) as u16).min(u16::MAX)
}

pub(crate) unsafe fn uv_stdio_handle(buffer: *mut u8, fd: i32) -> HANDLE {
    let mut handle = INVALID_HANDLE_VALUE;
    unsafe { copy_handle(child_stdio_handle(buffer, fd).cast::<HANDLE>().read_unaligned(), &mut handle) };
    handle
}

unsafe fn uv_duplicate_handle(handle: HANDLE) -> Result<HANDLE, Error> {
    if handle == INVALID_HANDLE_VALUE
        || handle == null_mut()
        || handle == ((-2i32) as usize as HANDLE)
    {
        return Err(Error::EINVAL);
    }

    let mut dup = INVALID_HANDLE_VALUE;
    let current_process = unsafe { GetCurrentProcess() };

    if unsafe {
        DuplicateHandle(
            current_process,
            handle,
            current_process,
            &mut dup,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(Error::UNKNOWN);
    }

    Ok(dup)
}

pub unsafe fn free_stdio_buffer(buffer: *mut u8) {
    let _ = unsafe { StdioBuffer::from_raw(buffer) };
}

/*INLINE static HANDLE uv__get_osfhandle(int fd)
{
  /* _get_osfhandle() raises an assert in debug builds if the FD is invalid.
   * But it also correctly checks the FD and returns INVALID_HANDLE_VALUE for
   * invalid FDs in release builds (or if you let the assert continue). So this
   * wrapper function disables asserts when calling _get_osfhandle. */

  HANDLE handle;
  UV_BEGIN_DISABLE_CRT_ASSERT();
  handle = (HANDLE) _get_osfhandle(fd);
  UV_END_DISABLE_CRT_ASSERT();
  return handle;
}
 */

unsafe fn uv_get_osfhandle(fd: i32) -> HANDLE {
    unsafe { libc::get_osfhandle(fd) as usize as HANDLE }
}

fn uv_duplicate_fd(fd: i32) -> Result<HANDLE, Error> {
    let handle = unsafe { uv_get_osfhandle(fd) };
    unsafe { uv_duplicate_handle(handle) }
}

unsafe fn copy_handle(handle: HANDLE, dest: *mut HANDLE) {
    unsafe { std::ptr::write_unaligned(dest, handle) };
}

#[derive(Debug, Clone, Copy)]
pub enum StdioContainer {
    Ignore,
    InheritFd(i32),
}

#[inline(never)]
pub(crate) fn uv_stdio_create(options: &uv_process_options) -> Result<StdioBuffer, Error> {
    eprintln!("uv_stdio_create");
    let mut count = options.stdio_count;
    if count < 0 || count > 255 {
        return Err(Error::EINVAL);
    } else if count < 3 {
        count = 3;
    }

    let mut buffer = StdioBuffer::new(count);

    for i in 0..count {
        let fdopt = if i < options.stdio_count {
            options.stdio[i]
        } else {
            StdioContainer::Ignore
        };

        match fdopt {
            StdioContainer::Ignore => unsafe {
                if i <= 2 {
                    let access = if i == 0 {
                        FILE_GENERIC_READ
                    } else {
                        FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES
                    };
                    let nul = unsafe { uv_create_nul_handle(access) }?;
                    buffer.set_handle(i as i32, nul);
                    buffer.set_flags(i as i32, FOPEN | FDEV);
                }
            },
            StdioContainer::InheritFd(fd) => {
                let handle = unsafe { uv_duplicate_fd(fd) };
                let handle = match handle {
                    Ok(handle) => handle,
                    Err(e) if fd <= 2 => {
                        unsafe { buffer.set_flags(fd, 0) };
                        unsafe { buffer.set_handle(fd, INVALID_HANDLE_VALUE) };
                        continue;
                    }
                    Err(e) => return Err(e),
                };

                match unsafe { GetFileType(handle) } {
                    FILE_TYPE_DISK => unsafe { buffer.set_flags(fd, FOPEN) },
                    FILE_TYPE_PIPE => unsafe { buffer.set_flags(fd, FOPEN | FPIPE) },
                    FILE_TYPE_CHAR | FILE_TYPE_REMOTE => unsafe {
                        buffer.set_flags(fd, FOPEN | FDEV)
                    },
                    FILE_TYPE_UNKNOWN => {
                        if unsafe { GetLastError() } != 0 {
                            unsafe { CloseHandle(handle) };
                            return Err(Error::UNKNOWN);
                        }
                        unsafe { buffer.set_flags(fd, FOPEN | FDEV) }
                    }
                    other => panic!("Unknown file type: {}", other),
                }

                unsafe { buffer.set_handle(fd, handle) }
            }
        }
    }

    Ok(buffer)
}

mod buffer {
    use super::*;
    #[repr(transparent)]
    pub struct StdioBuffer {
        ptr: *mut u8,
    }

    impl Drop for StdioBuffer {
        fn drop(&mut self) {
            let count = self.get_count();
            for i in 0..count {
                let handle = unsafe { self.get_handle(i as i32) };
                if handle != INVALID_HANDLE_VALUE {
                    unsafe { CloseHandle(handle) };
                }
            }

            unsafe {
                std::ptr::drop_in_place(self.ptr);
                std::alloc::dealloc(
                    self.ptr as *mut _,
                    std::alloc::Layout::array::<u8>(self.get_count()).unwrap(),
                );
                eprintln!("Dropped stdio buffer");
            }
        }
    }



    impl StdioBuffer {
        pub unsafe fn from_raw(ptr: *mut u8) -> Self {
            Self { ptr }
        }

        pub fn into_raw(self) -> *mut u8 {
            let ptr = self.ptr;
            std::mem::forget(self);
            ptr
        }

        fn create_raw(count: usize) -> Self {
            let layout = std::alloc::Layout::array::<u8>(child_stdio_size(count)).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };

            StdioBuffer { ptr }
        }
        pub fn new(count: usize) -> Self {
            let buffer = Self::create_raw(count);
            eprintln!("CREATING WITH COUNT: {}", count);

            unsafe {
                *buffer.ptr.cast::<std::ffi::c_uint>() = count as std::ffi::c_uint;
            }

            for i in 0..count {
                unsafe {
                    copy_handle(
                        INVALID_HANDLE_VALUE,
                        child_stdio_handle(buffer.ptr, i as i32).cast(),
                    );
                    std::ptr::write(child_stdio_crt_flags(buffer.ptr, i as i32), 0);
                }
            }

            buffer
        }

        pub fn get_count(&self) -> usize {
            unsafe { child_stdio_count(self.ptr) }
        }

        pub unsafe fn get_handle(&self, fd: i32) -> HANDLE {
            unsafe { uv_stdio_handle(self.ptr, fd) }
        }

        pub unsafe fn set_flags(&mut self, fd: i32, flags: u8) {
            debug_assert!(fd < unsafe { child_stdio_count(self.ptr) } as i32,);
            unsafe {
                *child_stdio_crt_flags(self.ptr, fd) = flags;
            }
        }

        pub unsafe fn set_handle(&mut self, fd: i32, handle: HANDLE) {
            unsafe {
                copy_handle(handle, child_stdio_handle(self.ptr, fd).cast());
            }
        }

        pub fn size(&self) -> usize {
            child_stdio_size(self.get_count())
        }
    }
}
