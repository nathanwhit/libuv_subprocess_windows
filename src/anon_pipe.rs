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
    BOOL, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, FALSE, GENERIC_READ,
    GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE, TRUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, ReadFileEx, WriteFileEx,
};
use windows_sys::Win32::System::IO::{LPOVERLAPPED_COMPLETION_ROUTINE, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, INFINITE, SleepEx,
};

pub type Handle = std::os::windows::io::OwnedHandle;

////////////////////////////////////////////////////////////////////////////////
// Anonymous pipes
////////////////////////////////////////////////////////////////////////////////

pub struct AnonPipe {
    inner: Handle,
}

impl AnonPipe {
    fn try_clone(&self) -> io::Result<AnonPipe> {
        let handle = handle_dup(&self.inner, 0, false, DUPLICATE_SAME_ACCESS)?;
        Ok(AnonPipe { inner: handle })
    }
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

fn handle_dup(
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

/// Takes an asynchronous source pipe and returns a synchronous pipe suitable
/// for sending to a child process.
///
/// This is achieved by creating a new set of pipes and spawning a thread that
/// relays messages between the source and the synchronous pipe.
pub fn spawn_pipe_relay(
    source: &AnonPipe,
    ours_readable: bool,
    their_handle_inheritable: bool,
) -> io::Result<AnonPipe> {
    // We need this handle to live for the lifetime of the thread spawned below.
    let source = source.try_clone()?;

    // create a new pair of anon pipes.
    let Pipes { theirs, ours } = anon_pipe(ours_readable, their_handle_inheritable)?;

    // Spawn a thread that passes messages from one pipe to the other.
    // Any errors will simply cause the thread to exit.
    let (reader, writer) = if ours_readable {
        (ours, source)
    } else {
        (source, ours)
    };
    std::thread::spawn(move || {
        let mut buf = [0_u8; 4096];
        'reader: while let Ok(len) = reader.read(&mut buf) {
            if len == 0 {
                break;
            }
            let mut start = 0;
            while let Ok(written) = writer.write(&buf[start..len]) {
                start += written;
                if start == len {
                    continue 'reader;
                }
            }
            break;
        }
    });

    // Return the pipe that should be sent to the child process.
    Ok(theirs)
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
    pub fn handle(&self) -> &Handle {
        &self.inner
    }
    pub fn into_handle(self) -> Handle {
        self.inner
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let result = unsafe {
            let len = std::cmp::min(buf.len(), u32::MAX as usize) as u32;
            let ptr = buf.as_mut_ptr();
            self.alertable_io_internal(|overlapped, callback| {
                ReadFileEx(self.inner.as_raw_handle(), ptr, len, overlapped, callback)
            })
        };

        match result {
            // The special treatment of BrokenPipe is to deal with Windows
            // pipe semantics, which yields this error when *reading* from
            // a pipe after the other end has closed; we interpret that as
            // EOF on the pipe.
            Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
            _ => result,
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = std::cmp::min(buf.len(), u32::MAX as usize) as u32;
            self.alertable_io_internal(|overlapped, callback| {
                WriteFileEx(
                    self.inner.as_raw_handle(),
                    buf.as_ptr(),
                    len,
                    overlapped,
                    callback,
                )
            })
        }
    }

    /// Synchronizes asynchronous reads or writes using our anonymous pipe.
    ///
    /// This is a wrapper around [`ReadFileEx`] or [`WriteFileEx`] that uses
    /// [Asynchronous Procedure Call] (APC) to synchronize reads or writes.
    ///
    /// Note: This should not be used for handles we don't create.
    ///
    /// # Safety
    ///
    /// `buf` must be a pointer to a buffer that's valid for reads or writes
    /// up to `len` bytes. The `AlertableIoFn` must be either `ReadFileEx` or `WriteFileEx`
    ///
    /// [`ReadFileEx`]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfileex
    /// [`WriteFileEx`]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefileex
    /// [Asynchronous Procedure Call]: https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
    unsafe fn alertable_io_internal(
        &self,
        io: impl FnOnce(&mut OVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE) -> BOOL,
    ) -> io::Result<usize> {
        // Use "alertable I/O" to synchronize the pipe I/O.
        // This has four steps.
        //
        // STEP 1: Start the asynchronous I/O operation.
        //         This simply calls either `ReadFileEx` or `WriteFileEx`,
        //         giving it a pointer to the buffer and callback function.
        //
        // STEP 2: Enter an alertable state.
        //         The callback set in step 1 will not be called until the thread
        //         enters an "alertable" state. This can be done using `SleepEx`.
        //
        // STEP 3: The callback
        //         Once the I/O is complete and the thread is in an alertable state,
        //         the callback will be run on the same thread as the call to
        //         `ReadFileEx` or `WriteFileEx` done in step 1.
        //         In the callback we simply set the result of the async operation.
        //
        // STEP 4: Return the result.
        //         At this point we'll have a result from the callback function
        //         and can simply return it. Note that we must not return earlier,
        //         while the I/O is still in progress.

        // The result that will be set from the asynchronous callback.
        let mut async_result: Option<AsyncResult> = None;
        struct AsyncResult {
            error: u32,
            transferred: u32,
        }

        // STEP 3: The callback.
        #[allow(nonstandard_style)]
        unsafe extern "system" fn callback(
            dwErrorCode: u32,
            dwNumberOfBytesTransferred: u32,
            lpOverlapped: *mut OVERLAPPED,
        ) {
            // Set `async_result` using a pointer smuggled through `hEvent`.
            // SAFETY:
            // At this point, the OVERLAPPED struct will have been written to by the OS,
            // except for our `hEvent` field which we set to a valid AsyncResult pointer (see below)
            unsafe {
                let result = AsyncResult {
                    error: dwErrorCode,
                    transferred: dwNumberOfBytesTransferred,
                };
                *(*lpOverlapped).hEvent.cast::<Option<AsyncResult>>() = Some(result);
            }
        }

        // STEP 1: Start the I/O operation.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // `hEvent` is unused by `ReadFileEx` and `WriteFileEx`.
        // Therefore the documentation suggests using it to smuggle a pointer to the callback.
        overlapped.hEvent = (&raw mut async_result) as *mut _;

        // Asynchronous read of the pipe.
        // If successful, `callback` will be called once it completes.
        let result = io(&mut overlapped, Some(callback));
        if result == FALSE {
            // We can return here because the call failed.
            // After this we must not return until the I/O completes.
            return Err(io::Error::last_os_error());
        }

        // Wait indefinitely for the result.
        let result = loop {
            // STEP 2: Enter an alertable state.
            // The second parameter of `SleepEx` is used to make this sleep alertable.
            unsafe { SleepEx(INFINITE, TRUE) };
            if let Some(result) = async_result {
                break result;
            }
        };
        // STEP 4: Return the result.
        // `async_result` is always `Some` at this point
        match result.error {
            windows_sys::Win32::Foundation::ERROR_SUCCESS => Ok(result.transferred as usize),
            error => Err(io::Error::from_raw_os_error(error as _)),
        }
    }
}
