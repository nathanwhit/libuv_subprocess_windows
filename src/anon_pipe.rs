// Pulled from https://github.com/rust-lang/rust/blob/3e674b06b5c74adea662bd0b0b06450757994b16/library/std/src/sys/pal/windows/pipe.rs
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::prelude::*;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;

use nanorand::Rng;
use windows_sys::Win32::Foundation::{
    BOOL, DuplicateHandle, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, GetLastError,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

pub type Handle = std::os::windows::io::OwnedHandle;

////////////////////////////////////////////////////////////////////////////////
// Anonymous pipes
////////////////////////////////////////////////////////////////////////////////

pub struct AnonPipe {
    inner: Handle,
}

impl AnonPipe {
    // fn try_clone(&self) -> io::Result<AnonPipe> {
    //     let handle = handle_dup(&self.inner, 0, false, DUPLICATE_SAME_ACCESS)?;
    //     Ok(AnonPipe { inner: handle })
    // }
}
fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

pub struct Pipes {
    pub ours: AnonPipe,
    pub theirs: AnonPipe,
}

fn cvt(res: BOOL) -> io::Result<()> {
    if res == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn handle_dup(
    handle: &Handle,
    access: u32,
    inherit: bool,
    options: u32,
) -> io::Result<OwnedHandle> {
    let handle = handle.as_raw_handle();

    // `Stdin`, `Stdout`, and `Stderr` can all hold null handles, such as
    // in a process with a detached console. `DuplicateHandle` would fail
    // if we passed it a null handle, but we can treat null as a valid
    // handle which doesn't do any I/O, and allow it to be duplicated.
    if handle.is_null() {
        return unsafe { Ok(OwnedHandle::from_raw_handle(handle)) };
    }

    let mut ret = ptr::null_mut();
    cvt(unsafe {
        let cur_proc = GetCurrentProcess();
        DuplicateHandle(
            cur_proc,
            handle,
            cur_proc,
            &mut ret,
            access,
            inherit as BOOL,
            options,
        )
    })?;
    unsafe { Ok(OwnedHandle::from_raw_handle(ret)) }
}

/// Although this looks similar to `anon_pipe` in the Unix module it's actually
/// subtly different. Here we'll return two pipes in the `Pipes` return value,
/// but one is intended for "us" where as the other is intended for "someone
/// else".
///
/// Currently the only use case for this function is pipes for stdio on
/// processes in the standard library, so "ours" is the one that'll stay in our
/// process whereas "theirs" will be inherited to a child.
///
/// The ours/theirs pipes are *not* specifically readable or writable. Each
/// one only supports a read or a write, but which is which depends on the
/// boolean flag given. If `ours_readable` is `true`, then `ours` is readable and
/// `theirs` is writable. Conversely, if `ours_readable` is `false`, then `ours`
/// is writable and `theirs` is readable.
///
/// Also note that the `ours` pipe is always a handle opened up in overlapped
/// mode. This means that technically speaking it should only ever be used
/// with `OVERLAPPED` instances, but also works out ok if it's only ever used
/// once at a time (which we do indeed guarantee).
pub fn anon_pipe(ours_readable: bool, their_handle_inheritable: bool) -> io::Result<Pipes> {
    // A 64kb pipe capacity is the same as a typical Linux default.
    const PIPE_BUFFER_CAPACITY: u32 = 64 * 1024;

    // Note that we specifically do *not* use `CreatePipe` here because
    // unfortunately the anonymous pipes returned do not support overlapped
    // operations. Instead, we create a "hopefully unique" name and create a
    // named pipe which has overlapped operations enabled.
    //
    // Once we do this, we connect do it as usual via `CreateFileW`, and then
    // we return those reader/writer halves. Note that the `ours` pipe return
    // value is always the named pipe, whereas `theirs` is just the normal file.
    // This should hopefully shield us from child processes which assume their
    // stdout is a named pipe, which would indeed be odd!
    unsafe {
        let ours;
        let mut name;
        let mut tries = 0;
        loop {
            tries += 1;
            name = format!(
                r"\\.\pipe\__rust_anonymous_pipe1__.{}.{}",
                GetCurrentProcessId(),
                random_number(),
            );
            let wide_name = OsStr::new(&name)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let mut flags = FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
            if ours_readable {
                flags |= PIPE_ACCESS_INBOUND;
            } else {
                flags |= PIPE_ACCESS_OUTBOUND;
            }

            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_CAPACITY,
                PIPE_BUFFER_CAPACITY,
                0,
                ptr::null_mut(),
            );

            // We pass the `FILE_FLAG_FIRST_PIPE_INSTANCE` flag above, and we're
            // also just doing a best effort at selecting a unique name. If
            // `ERROR_ACCESS_DENIED` is returned then it could mean that we
            // accidentally conflicted with an already existing pipe, so we try
            // again.
            //
            // Don't try again too much though as this could also perhaps be a
            // legit error.
            if handle == INVALID_HANDLE_VALUE {
                eprintln!("Invalid handle VALUE");
                let error = get_last_error();
                if tries < 10 && error == ERROR_ACCESS_DENIED {
                    continue;
                } else {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
            }

            ours = Handle::from_raw_handle(handle);
            break;
        }

        // Connect to the named pipe we just created. This handle is going to be
        // returned in `theirs`, so if `ours` is readable we want this to be
        // writable, otherwise if `ours` is writable we want this to be
        // readable.
        //
        // Additionally we don't enable overlapped mode on this because most
        // client processes aren't enabled to work with that.
        let mut opts = OpenOptions::new();
        opts.write(ours_readable);
        opts.read(!ours_readable);
        opts.share_mode(0);
        let access = if ours_readable {
            GENERIC_WRITE
        } else {
            GENERIC_READ
        };
        let size = size_of::<SECURITY_ATTRIBUTES>();
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: size as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: their_handle_inheritable as i32,
        };
        let path_utf16 = OsStr::new(&name)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let handle2 = CreateFileW(
            path_utf16.as_ptr(),
            access,
            0,
            &mut sa,
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        let theirs = Handle::from_raw_handle(handle2);

        Ok(Pipes {
            ours: AnonPipe { inner: ours },
            theirs: AnonPipe { inner: theirs },
        })
    }
}

fn random_number() -> usize {
    static N: std::sync::atomic::AtomicUsize = AtomicUsize::new(0);
    loop {
        if N.load(Relaxed) != 0 {
            return N.fetch_add(1, Relaxed);
        }

        N.store(nanorand::tls_rng().generate_range(..), Relaxed);
    }
}

impl AnonPipe {
    // pub fn handle(&self) -> &Handle {
    //     &self.inner
    // }
    pub fn into_handle(self) -> Handle {
        self.inner
    }
}
