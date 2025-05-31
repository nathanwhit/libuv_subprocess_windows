#![allow(nonstandard_style, dead_code)]
use std::{
    borrow::Cow,
    ffi::{CStr, OsStr, c_void},
    io, mem,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    pin::Pin,
    ptr::{self, null, null_mut},
    sync::OnceLock,
    task::Poll,
};

use futures_channel::oneshot;
use windows_sys::{
    Win32::{
        Foundation::{
            BOOL, BOOLEAN, CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
            ERROR_INVALID_PARAMETER, ERROR_OUTOFMEMORY, ERROR_SUCCESS, FALSE, GENERIC_WRITE,
            GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, STILL_ACTIVE, TRUE, WAIT_FAILED,
            WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Globalization::GetSystemDefaultLangID,
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
            FILE_DISPOSITION_INFO, FileDispositionInfo, GetShortPathNameW, SYNCHRONIZE,
            SetFileInformationByHandle,
        },
        System::{
            Com::CoTaskMemFree,
            Diagnostics::Debug::{
                FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
                FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageA, MINIDUMP_TYPE,
                MiniDumpIgnoreInaccessibleMemory, MiniDumpWithFullMemory, MiniDumpWriteDump,
                SymGetOptions, SymSetOptions,
            },
            Environment::{GetEnvironmentVariableW, NeedCurrentDirectoryForExePathW},
            ProcessStatus::GetModuleBaseNameW,
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RRF_RT_ANY, RegCloseKey, RegGetValueW,
                RegOpenKeyExW,
            },
            Threading::{
                CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
                CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS, GetCurrentProcess,
                GetExitCodeProcess, GetProcessId, INFINITE, OpenProcess, PROCESS_INFORMATION,
                PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, RegisterWaitForSingleObject,
                ResumeThread, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
                TerminateProcess, WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE, WaitForSingleObject,
            },
        },
        UI::{
            Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
            WindowsAndMessaging::{SW_HIDE, SW_SHOWDEFAULT},
        },
    },
    w,
};

use crate::{
    env::{CommandEnv, EnvKey},
    process_stdio::{StdioContainer, free_stdio_buffer, uv_stdio_create},
    widestr::{WCStr, WCString},
};

unsafe extern "C" {
    fn wcsncpy(dest: *mut u16, src: *const u16, count: usize);
    fn wcspbrk(str: *const u16, accept: *const u16) -> *const u16;
    fn wcslen(str: *const u16) -> usize;
}

#[repr(C)]
struct EnvVar {
    wide: *const u16,
    wide_eq: *const u16,
    len: usize,
}

unsafe impl Send for EnvVar {}
unsafe impl Sync for EnvVar {}

macro_rules! e_v {
    ($str:expr, $eq:expr) => {
        EnvVar {
            wide: w!($str),
            wide_eq: w!($eq),
            len: $str.len() * 2,
        }
    };
}

static REQUIRED_VARS: &[EnvVar] = &[
    e_v!("HOMEDRIVE", "HOMEDRIVE="),
    e_v!("HOMEPATH", "HOMEPATH="),
    e_v!("LOGONSERVER", "LOGONSERVER="),
    e_v!("PATH", "PATH="),
    e_v!("SYSTEMDRIVE", "SYSTEMDRIVE="),
    e_v!("SYSTEMROOT", "SYSTEMROOT="),
    e_v!("TEMP", "TEMP="),
    e_v!("USERDOMAIN", "USERDOMAIN="),
    e_v!("USERNAME", "USERNAME="),
    e_v!("USERPROFILE", "USERPROFILE="),
    e_v!("WINDIR", "WINDIR="),
];

struct GlobalJobHandle(HANDLE);
unsafe impl Send for GlobalJobHandle {}
unsafe impl Sync for GlobalJobHandle {}

static UV_GLOBAL_JOB_HANDLE: OnceLock<GlobalJobHandle> = OnceLock::new();

fn uv_fatal_error_with_no(syscall: &str, errno: Option<u32>) {
    let errno = errno.unwrap_or_else(|| unsafe { GetLastError() });
    let mut buf: *mut i8 = null_mut();
    unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            null_mut(),
            errno,
            GetSystemDefaultLangID().into(),
            (&raw mut buf).cast(),
            0,
            null_mut(),
        );
    }
    let errmsg = if buf.is_null() {
        "Unknown error"
    } else {
        unsafe { CStr::from_ptr(buf).to_str().unwrap() }
    };

    let msg = if syscall.is_empty() {
        format!("({}) {}", errno, errmsg)
    } else {
        format!("{}: ({}) {}", syscall, errno, errmsg)
    };
    if !buf.is_null() {
        unsafe { LocalFree(buf.cast()) };
    }
    panic!("{}", msg);
}

fn uv_fatal_error(syscall: &str) {
    uv_fatal_error_with_no(syscall, None)
}

fn uv_init_global_job_handle() {
    use windows_sys::Win32::System::JobObjects::*;
    UV_GLOBAL_JOB_HANDLE.get_or_init(|| {
        unsafe {
            // SAFETY: SECURITY_ATTRIBUTES is a POD type, repr(C)
            let mut attr = mem::zeroed::<SECURITY_ATTRIBUTES>();
            // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a POD type, repr(C)
            let mut info = mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            attr.bInheritHandle = FALSE;

            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK
                | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            // SAFETY: called with valid parameters
            let job = CreateJobObjectW(&attr, ptr::null());
            if job.is_null() {
                uv_fatal_error("CreateJobObjectW");
            }

            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &raw const info as _,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                uv_fatal_error("SetInformationJobObject");
            }

            if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
                let err = GetLastError();
                if err != ERROR_ACCESS_DENIED {
                    uv_fatal_error_with_no("AssignProcessToJobObject", Some(err));
                }
            }

            GlobalJobHandle(job)
        }
    });
}

#[repr(C)]
struct uv_req {
    data: *mut c_void,
}

pub struct uv_stdio_container {
    pub flags: u32,
    pub data: StdioData,
}

pub enum StdioData {
    Stream(*mut c_void), // Would be `uv_stream_t` in libuv
    Fd(i32),
}

// Define handle types
#[repr(i32)]
enum HandleType {
    Unknown = 0,
    Process = 10,
}

// Define request types
#[repr(i32)]
enum RequestType {
    Unknown = 0,
    ProcessExit = 9,
}

// Stub for uv_handle
struct uv_handle_t {
    data: *mut c_void,
    loop_handle: *mut uv_loop_t, // Would be `uv_loop_t`
    handle_type: HandleType,
    close_cb: Option<fn(*mut uv_handle_t)>,
}

// Stub for uv_loop
pub struct uv_loop_t {
    data: *mut c_void,
}

impl uv_loop_t {
    pub fn init() -> Self {
        Self { data: null_mut() }
    }
}

// pub struct uv_process {
//     pid: i32,
//     exit_cb: Option<fn(*const uv_process, u64, i32)>,
//     exit_signal: i32,
//     wait_handle: RawHandle,
//     process_handle: RawHandle,
//     exit_cb_pending: AtomicBool,
//     exit_req: uv_req,
//     waiting: Option<Waiting>,
// }

#[derive(Debug)]
struct Waiting {
    rx: oneshot::Receiver<()>,
    wait_object: HANDLE,
    tx: *mut Option<oneshot::Sender<()>>,
}

unsafe impl Sync for Waiting {}
unsafe impl Send for Waiting {}

pub struct SpawnOptions<'a> {
    // pub exit_cb: Option<fn(*const uv_process, u64, i32)>,
    pub flags: u32,
    pub file: Cow<'a, OsStr>,
    pub args: Vec<Cow<'a, OsStr>>,
    pub env: &'a CommandEnv,
    pub cwd: Option<Cow<'a, OsStr>>,
    pub stdio: Vec<super::process_stdio::StdioContainer>,
}

macro_rules! wchar {
    ($s: literal) => {{
        const INPUT: char = $s;
        const OUTPUT: u16 = {
            let len = INPUT.len_utf16();
            if len != 1 {
                panic!("wchar! macro requires a single UTF-16 character");
            }
            let mut buf = [0; 1];
            INPUT.encode_utf16(&mut buf);
            buf[0]
        };
        OUTPUT
    }};
}

fn quote_cmd_arg(src: &WCStr, target: &mut Vec<u16>) {
    let len = src.len();

    if len == 0 {
        // Need double quotation for empty argument
        target.push(wchar!('"'));
        target.push(wchar!('"'));
        return;
    }

    if unsafe { wcspbrk(src.as_ptr(), w!(" \t\"")) } == null() {
        // No quotation needed
        target.extend(src.wchars_no_null());
        return;
    }

    if unsafe { wcspbrk(src.as_ptr(), w!("\"\\")) } == null() {
        // No embedded double quotes or backlashes, so I can just wrap
        // quote marks around the whole thing.
        target.push(wchar!('"'));
        target.extend(src.wchars_no_null());
        target.push(wchar!('"'));
        return;
    }

    // Expected input/output:
    //   input : hello"world
    //   output: "hello\"world"
    //   input : hello""world
    //   output: "hello\"\"world"
    //   input : hello\world
    //   output: hello\world
    //   input : hello\\world
    //   output: hello\\world
    //   input : hello\"world
    //   output: "hello\\\"world"
    //   input : hello\\"world
    //   output: "hello\\\\\"world"
    //   input : hello world\
    //   output: "hello world\\"

    target.push(wchar!('"'));
    let start = target.len();
    let mut quote_hit = true;

    for i in (0..len).rev() {
        target.push(src[i]);

        if quote_hit && src[i] == wchar!('\\') {
            target.push(wchar!('\\'));
        } else if src[i] == wchar!('"') {
            quote_hit = true;
            target.push(wchar!('\\'));
        } else {
            quote_hit = false;
        }
    }

    target[start..].reverse();
    target.push(wchar!('"'));
}

fn make_program_args(args: &[&OsStr], verbatim_arguments: bool) -> Result<WCString, Error> {
    let mut dst_len = 0;
    let mut temp_buffer_len = 0;

    // Count the required size.
    for arg in args {
        let arg_len = arg.encode_wide().count();
        dst_len += arg_len;
        if arg_len > temp_buffer_len {
            temp_buffer_len = arg_len;
        }
    }

    // Adjust for potential quotes. Also assume the worst-case scenario that
    // every character needs escaping, so we need twice as much space.
    dst_len = dst_len * 2 + args.len() * 2;

    let mut dst = Vec::with_capacity(dst_len);
    let mut temp_buffer = Vec::with_capacity(temp_buffer_len);

    for (i, arg) in args.iter().enumerate() {
        temp_buffer.clear();
        temp_buffer.extend(arg.encode_wide());

        if verbatim_arguments {
            dst.extend(temp_buffer.as_slice());
        } else {
            // Add null terminator for WCStr, but only temporarily
            temp_buffer.push(0);
            quote_cmd_arg(unsafe { WCStr::from_wchars(&temp_buffer) }, &mut dst);
        }

        if i < args.len() - 1 {
            dst.push(wchar!(' '));
        }
    }

    let wcstring = WCString::from_vec(dst);
    Ok(wcstring)
}

fn cvt(result: BOOL) -> Result<(), std::io::Error> {
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct ChildProcess {
    pid: i32,
    exit_signal: Option<i32>,
    exit_code: Option<i64>,
    handle: OwnedHandle,
    waiting: Option<Waiting>,
}

impl crate::Kill for ChildProcess {
    fn kill(&mut self) -> std::io::Result<()> {
        process_kill(self.pid, SIGTERM)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

impl ChildProcess {
    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn try_wait(&mut self) -> Result<Option<i32>, std::io::Error> {
        unsafe {
            match WaitForSingleObject(self.handle.as_raw_handle(), 0) {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Ok(None),
                // TODO: io error probably
                _ => {
                    return Err(std::io::Error::last_os_error());
                }
            }

            let mut status = 0;
            cvt(GetExitCodeProcess(self.handle.as_raw_handle(), &mut status))?;
            Ok(Some(status as i32))
        }
    }

    pub fn wait(&mut self) -> Result<i32, std::io::Error> {
        unsafe {
            let res = WaitForSingleObject(self.handle.as_raw_handle(), INFINITE);
            if res != WAIT_OBJECT_0 {
                return Err(std::io::Error::last_os_error());
            }

            let mut status = 0;
            cvt(GetExitCodeProcess(self.handle.as_raw_handle(), &mut status))?;
            Ok(status as i32)
        }
    }
}

unsafe extern "system" fn callback(ptr: *mut std::ffi::c_void, _timer_fired: BOOLEAN) {
    let complete = unsafe { &mut *(ptr as *mut Option<oneshot::Sender<()>>) };
    let _ = complete.take().unwrap().send(());
}

impl Future for ChildProcess {
    type Output = Result<i32, std::io::Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let inner = Pin::get_mut(self);
        loop {
            if let Some(ref mut w) = inner.waiting {
                match Pin::new(&mut w.rx).poll(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(_)) => panic!("should not be canceled"),
                    Poll::Pending => return Poll::Pending,
                }
                let status = inner.try_wait()?.expect("not ready yet");
                return Poll::Ready(Ok(status));
            }

            if let Some(e) = inner.try_wait()? {
                return Poll::Ready(Ok(e));
            }
            let (tx, rx) = oneshot::channel();
            let ptr = Box::into_raw(Box::new(Some(tx)));
            let mut wait_object = null_mut();
            let rc = unsafe {
                RegisterWaitForSingleObject(
                    &mut wait_object,
                    inner.handle.as_raw_handle() as _,
                    Some(callback),
                    ptr as *mut _,
                    INFINITE,
                    WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
                )
            };
            if rc == 0 {
                let err = io::Error::last_os_error();
                drop(unsafe { Box::from_raw(ptr) });
                return Poll::Ready(Err(err));
            }
            inner.waiting = Some(Waiting {
                rx,
                wait_object,
                tx: ptr,
            });
        }
    }
}

pub fn spawn(options: &SpawnOptions) -> Result<ChildProcess, Error> {
    let mut startup = unsafe { mem::zeroed::<STARTUPINFOW>() };
    let mut info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };

    if options.flags & (uv_process_flags::SetUid | uv_process_flags::SetGid) != 0 {
        return Err(Error::ENOTSUP);
    }

    if options.file.is_empty() || options.args.is_empty() {
        return Err(Error::EINVAL);
    }

    // Convert file path to UTF-16
    let application = Some(WCString::new(&options.file));

    // Create command line arguments
    let args: Vec<&OsStr> = options.args.iter().map(|s| s.as_ref()).collect();
    let verbatim_arguments = (options.flags & uv_process_flags::WindowsVerbatimArguments) != 0;
    let arguments = make_program_args(&args, verbatim_arguments)?;

    // Create environment block if provided
    let env_saw_path = options.env.have_changed_path();
    let maybe_env = options.env.capture_if_changed();

    let child_paths = if env_saw_path {
        if let Some(env) = maybe_env.as_ref() {
            env.get(&EnvKey::new("PATH")).map(|s| s.as_os_str())
        } else {
            None
        }
    } else {
        None
    };

    // Handle current working directory
    let cwd = if let Some(cwd_option) = &options.cwd {
        // Explicit cwd
        WCString::new(cwd_option)
    } else {
        // Inherit cwd
        let cwd = std::env::current_dir().unwrap();
        WCString::new(cwd)
    };

    // If cwd is too long, shorten it
    let cwd = if cwd.len_no_nul() as usize >= windows_sys::Win32::Foundation::MAX_PATH as usize {
        unsafe {
            let cwd_ptr = cwd.as_ptr();
            let mut short_buf = vec![0u16; cwd.len_no_nul() as usize];
            let cwd_len =
                GetShortPathNameW(cwd_ptr, short_buf.as_mut_ptr(), cwd.len_no_nul() as u32);
            if cwd_len == 0 {
                return Err(translate_sys_error(GetLastError()));
            }
            WCString::from_vec(short_buf)
        }
    } else {
        cwd
    };

    // Get PATH environment variable
    let path = child_paths
        .map(|p| p.encode_wide().chain(Some(0)).collect::<Vec<_>>())
        .or_else(|| {
            // PATH not found in provided environment, get system PATH
            std::env::var_os("PATH").map(|p| p.encode_wide().chain(Some(0)).collect::<Vec<_>>())
        });

    // Create and set up stdio
    let child_stdio_buffer = uv_stdio_create(options)?;

    // Search for the executable
    let Some(application_path) = search_path(
        application.as_ref().map(|s| s.as_slice_no_nul()).unwrap(),
        cwd.as_slice_no_nul(),
        path.as_deref(),
        options.flags,
    ) else {
        return Err(translate_sys_error(ERROR_FILE_NOT_FOUND));
    };

    // Set up process creation
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.lpReserved = ptr::null_mut();
    startup.lpDesktop = ptr::null_mut();
    startup.lpTitle = ptr::null_mut();
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    startup.cbReserved2 = child_stdio_buffer.size() as u16;
    startup.hStdInput = unsafe { child_stdio_buffer.get_handle(0) };
    startup.hStdOutput = unsafe { child_stdio_buffer.get_handle(1) };
    startup.hStdError = unsafe { child_stdio_buffer.get_handle(2) };

    startup.lpReserved2 = child_stdio_buffer.into_raw();

    // Set up process flags
    let mut process_flags = CREATE_UNICODE_ENVIRONMENT;

    // Handle console window visibility
    if (options.flags & uv_process_flags::WindowsHideConsole) != 0
        || (options.flags & uv_process_flags::WindowsHide) != 0
    {
        // Avoid creating console window if stdio is not inherited
        let mut can_hide = true;
        for i in 0..options.stdio.len() {
            if matches!(options.stdio[i], StdioContainer::InheritFd(_)) {
                can_hide = false;
                break;
            }
        }
        if can_hide {
            process_flags |= CREATE_NO_WINDOW;
        }
    }

    // Set window show state
    if (options.flags & uv_process_flags::WindowsHideGui) != 0
        || (options.flags & uv_process_flags::WindowsHide) != 0
    {
        startup.wShowWindow = SW_HIDE as u16;
    } else {
        startup.wShowWindow = SW_SHOWDEFAULT as u16;
    }

    // Handle detached processes
    if (options.flags & uv_process_flags::Detached) != 0 {
        process_flags |= DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        process_flags |= CREATE_SUSPENDED;
    }

    // Create the process
    let app_path_ptr = application_path.as_ptr();
    let args_ptr = arguments.as_ptr();
    let (env_ptr, _data) = crate::env::make_envp(maybe_env).map_err(Error::Io)?;

    let cwd_ptr = cwd.as_ptr();

    let create_result = unsafe {
        CreateProcessW(
            app_path_ptr,         // Application path
            args_ptr as *mut u16, // Command line
            ptr::null(),          // Process attributes
            ptr::null(),          // Thread attributes
            TRUE,                 // Inherit handles
            process_flags,        // Creation flags
            env_ptr as *mut _,    // Environment
            cwd_ptr,              // Current directory
            &startup,             // Startup info
            &mut info,            // Process information
        )
    };

    if create_result == 0 {
        // CreateProcessW failed
        return Err(translate_sys_error(unsafe { GetLastError() }));
    }

    // If the process isn't spawned as detached, assign to the global job object
    if (options.flags & uv_process_flags::Detached) == 0 {
        uv_init_global_job_handle();
        let job_handle = UV_GLOBAL_JOB_HANDLE.get().unwrap().0;

        unsafe {
            if windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(
                job_handle,
                info.hProcess,
            ) == 0
            {
                // AssignProcessToJobObject might fail if this process is under job control
                // and the job doesn't have the JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK flag set,
                // on a Windows version that doesn't support nested jobs.
                let err = GetLastError();
                if err != ERROR_ACCESS_DENIED {
                    uv_fatal_error_with_no("AssignProcessToJobObject", Some(err));
                }
            }
        }
    }

    // Resume thread if it was suspended
    if (process_flags & CREATE_SUSPENDED) != 0 {
        unsafe {
            if ResumeThread(info.hThread) == u32::MAX {
                TerminateProcess(info.hProcess, 1);
                return Err(translate_sys_error(GetLastError()));
            }
        }
    }

    let child = ChildProcess {
        pid: info.dwProcessId as i32,
        exit_signal: None,
        exit_code: None,
        handle: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
        waiting: None,
    };

    // Close the thread handle as we don't need it
    unsafe { windows_sys::Win32::Foundation::CloseHandle(info.hThread) };

    if !startup.lpReserved2.is_null() {
        unsafe { free_stdio_buffer(startup.lpReserved2) };
    }

    Ok(child)
}

#[derive(Debug)]
pub enum Error {
    ENOTSUP,
    EINVAL,
    ENOMEM,
    ESRCH,
    ENOSYS,
    EACCES,
    UNKNOWN,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ENOTSUP => write!(f, "ENOTSUP"),
            Error::EINVAL => write!(f, "EINVAL"),
            Error::ENOMEM => write!(f, "ENOMEM"),
            Error::ESRCH => write!(f, "ESRCH"),
            Error::ENOSYS => write!(f, "ENOSYS"),
            Error::EACCES => write!(f, "EACCES"),
            Error::UNKNOWN => write!(f, "UNKNOWN"),
            Error::Io(e) => write!(f, "Io({})", e),
        }
    }
}

macro_rules! impl_bitops {
    ($t: ty : $other: ty) => {
        impl_bitops!(@help; $t, $other; out = $other);
        impl_bitops!(@help; $other, $t; out = $other);
        impl_bitops!(@help; $t, $t; out = $other);

        impl BitOrAssign<$t> for $other {
            fn bitor_assign(&mut self, rhs: $t) {
                *self |= rhs as $other;
            }
        }
        impl BitAndAssign<$t> for $other {
            fn bitand_assign(&mut self, rhs: $t) {
                *self &= rhs as $other;
            }
        }
    };
    (@help; $lhs: ty , $rhs: ty; out = $out: ty) => {
        impl BitOr<$rhs> for $lhs {
            type Output = $out;
            fn bitor(self, rhs: $rhs) -> Self::Output {
                self as $out | rhs as $out
            }
        }
        impl BitAnd<$rhs> for $lhs {
            type Output = $out;

            fn bitand(self, rhs: $rhs) -> Self::Output {
                self as $out & rhs as $out
            }
        }
    };
}

impl_bitops!(
    uv_process_flags : u32
);

#[repr(u32)]
pub enum uv_process_flags {
    /// Set the child process' user id.
    SetUid = 1 << 0,
    /// Set the child process' group id.
    SetGid = 1 << 1,
    /// Do not wrap any arguments in quotes, or perform any other escaping, when
    /// converting the argument list into a command line string. This option is
    /// only meaningful on Windows systems. On Unix it is silently ignored.
    WindowsVerbatimArguments = 1 << 2,
    /// Spawn the child process in a detached state - this will make it a process
    /// group leader, and will effectively enable the child to keep running after
    /// the parent exits. Note that the child process will still keep the
    /// parent's event loop alive unless the parent process calls uv_unref() on
    /// the child's process handle.
    Detached = 1 << 3,
    /// Hide the subprocess window that would normally be created. This option is
    /// only meaningful on Windows systems. On Unix it is silently ignored.
    WindowsHide = 1 << 4,
    /// Hide the subprocess console window that would normally be created. This
    /// option is only meaningful on Windows systems. On Unix it is silently
    /// ignored.
    WindowsHideConsole = 1 << 5,
    /// Hide the subprocess GUI window that would normally be created. This
    /// option is only meaningful on Windows systems. On Unix it is silently
    /// ignored.
    WindowsHideGui = 1 << 6,
    /// On Windows, if the path to the program to execute, specified in
    /// uv_process_options_t's file field, has a directory component,
    /// search for the exact file name before trying variants with
    /// extensions like '.exe' or '.cmd'.
    WindowsFilePathExactName = 1 << 7,
}

// Constants for stdio handle types
pub const UV_IGNORE: u32 = 0;
pub const UV_CREATE_PIPE: u32 = 1;
pub const UV_INHERIT_FD: u32 = 2;
pub const UV_INHERIT_STREAM: u32 = 4;

fn search_path_join_test(dir: &[u16], name: &[u16], ext: &[u16], cwd: &[u16]) -> Option<WCString> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };

    let dir_len = dir.len();
    let name_len = name.len();
    let ext_len = ext.len();
    let mut cwd_len = cwd.len();

    // Adjust cwd_len based on the path type
    if dir_len > 2
        && ((dir[0] == wchar!('\\') || dir[0] == wchar!('/'))
            && (dir[1] == wchar!('\\') || dir[1] == wchar!('/')))
    {
        // UNC path, ignore cwd
        cwd_len = 0;
    } else if dir_len >= 1 && (dir[0] == wchar!('/') || dir[0] == wchar!('\\')) {
        // Full path without drive letter, use cwd's drive letter only
        cwd_len = 2;
    } else if dir_len >= 2
        && dir[1] == wchar!(':')
        && (dir_len < 3 || (dir[2] != wchar!('/') && dir[2] != wchar!('\\')))
    {
        // Relative path with drive letter
        if cwd_len < 2 || dir[..2] != cwd[..2] {
            cwd_len = 0;
        } else {
            // Skip the drive letter part in dir
            let new_dir = &dir[2..];
            return search_path_join_test(new_dir, name, ext, cwd);
        }
    } else if dir_len > 2 && dir[1] == wchar!(':') {
        // Absolute path with drive letter, don't use cwd
        cwd_len = 0;
    }

    // Allocate buffer for output
    let mut result = Vec::with_capacity(128);

    // Copy cwd
    if cwd_len > 0 {
        result.extend_from_slice(&cwd[..cwd_len]);

        // Add path separator if needed
        if let Some(last) = result.last() {
            if !(*last == wchar!('\\') || *last == wchar!('/') || *last == wchar!(':')) {
                result.push(wchar!('\\'));
            }
        }
    }

    // Copy dir
    if dir_len > 0 {
        result.extend_from_slice(&dir[..dir_len]);

        // Add separator if needed
        if let Some(last) = result.last() {
            if !(*last == wchar!('\\') || *last == wchar!('/') || *last == wchar!(':')) {
                result.push(wchar!('\\'));
            }
        }
    }

    // Copy filename
    result.extend_from_slice(&name[..name_len]);

    if ext_len > 0 {
        // Add dot if needed
        if name_len > 0 && result.last() != Some(&wchar!('.')) {
            result.push(wchar!('.'));
        }

        // Copy extension
        result.extend_from_slice(&ext[..ext_len]);
    }

    // Create WCString and check if file exists
    let path = WCString::from_vec(result);
    let attrs = unsafe { GetFileAttributesW(path.as_ptr()) };

    if attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
        Some(path)
    } else {
        None
    }
}

fn search_path_walk_ext(
    dir: &[u16],
    name: &[u16],
    cwd: &[u16],
    name_has_ext: bool,
) -> Option<WCString> {
    // If the name itself has a nonempty extension, try this extension first
    if name_has_ext {
        if let Some(result) = search_path_join_test(dir, name, &[], cwd) {
            return Some(result);
        }
    }

    // Try .com extension
    if let Some(result) =
        search_path_join_test(dir, name, &[wchar!('c'), wchar!('o'), wchar!('m')], cwd)
    {
        return Some(result);
    }

    // Try .exe extension
    if let Some(result) =
        search_path_join_test(dir, name, &[wchar!('e'), wchar!('x'), wchar!('e')], cwd)
    {
        return Some(result);
    }

    None
}

/// Compares two environment variable strings, just comparing the part before the = sign.
///
/// This is case-insensitive as Windows environment variables are case-insensitive.
/// If `na` is negative, this function will find the equals sign in string `a`.
/// Otherwise, it will use `na-1` as the length to compare.
///
/// Returns negative if a < b, positive if a > b, 0 if they are equal.
fn env_strncmp(a: &[u16], na: isize, b: &[u16]) -> i32 {
    use windows_sys::Win32::Globalization::CSTR_EQUAL;
    use windows_sys::Win32::Globalization::CompareStringOrdinal;

    let na = if na < 0 {
        // Find the equals sign to determine variable name length
        let mut a_eq = None;
        for (i, &c) in a.iter().enumerate() {
            if c == wchar!('=') {
                a_eq = Some(i);
                break;
            }
        }
        assert!(a_eq.is_some());
        a_eq.unwrap()
    } else {
        // na is already the correct length minus 1
        (na - 1) as usize
    };

    // Find equals sign in b
    let mut b_eq = None;
    for (i, &c) in b.iter().enumerate() {
        if c == wchar!('=') {
            b_eq = Some(i);
            break;
        }
    }
    assert!(b_eq.is_some());
    let nb = b_eq.unwrap();

    // Compare the strings case-insensitively
    let r = unsafe {
        CompareStringOrdinal(
            a.as_ptr(),
            na as i32,
            b.as_ptr(),
            nb as i32,
            true as i32, // Case insensitive
        )
    };

    // Subtract CSTR_EQUAL to get the comparison result
    r - CSTR_EQUAL
}

/// Comparison function for sorting environment variables
///
/// This passes a -1 for `na` to env_strncmp, which will make it find the equals sign
/// in the first string.
fn qsort_wcscmp(a: &[u16], b: &[u16]) -> i32 {
    env_strncmp(a, -1, b)
}

/// Helper function to find PATH environment variable in the environment block
///
/// The environment block is a series of null-terminated strings, with an
/// additional null character at the end. This function traverses the block
/// looking for the PATH entry and returns the value portion (after the equals sign).
///
/// Returns None if no PATH is found.
fn find_path(env: &[u16]) -> Option<&[u16]> {
    let mut current = 0;

    while current < env.len() && env[current] != 0 {
        // Find length of current environment string
        let mut len = 0;
        while current + len < env.len() && env[current + len] != 0 {
            len += 1;
        }

        // Check if it's the PATH variable (case-insensitive)
        if len > 5
            && (env[current] == wchar!('P') || env[current] == wchar!('p'))
            && (env[current + 1] == wchar!('A') || env[current + 1] == wchar!('a'))
            && (env[current + 2] == wchar!('T') || env[current + 2] == wchar!('t'))
            && (env[current + 3] == wchar!('H') || env[current + 3] == wchar!('h'))
            && (env[current + 4] == wchar!('='))
        {
            // Return the value part (after '=')
            return Some(&env[current + 5..current + len]);
        }

        // Move to next environment string
        current += len + 1;
    }

    None
}

fn get_raw(wide: *const u16) -> Vec<u16> {
    let len = unsafe { wcslen(wide) };
    let mut parts = Vec::<u16>::with_capacity(len);
    unsafe {
        std::ptr::copy_nonoverlapping(wide, parts.as_mut_ptr(), len);
        parts.set_len(len);
    }
    parts
}

fn raw_str(wide: *const u16) -> String {
    String::from_utf16_lossy(get_raw(wide).as_slice())
}

trait RawToString {
    fn to_string(self) -> String;
}

impl RawToString for *const u16 {
    fn to_string(self) -> String {
        raw_str(self)
    }
}

pub struct FlatEnvBlock {
    pub env_block: Vec<u16>,
    pub env_block_count: usize,
    pub required_vars_value_len: Vec<usize>,
}

trait GetEnvVar {
    fn get_env_var_len(&self, name: &[u16]) -> Option<usize>;

    fn get_env_var(&self, name: &[u16], value: &mut [u16]);
}

struct Real;
impl GetEnvVar for Real {
    fn get_env_var_len(&self, name: &[u16]) -> Option<usize> {
        let len = unsafe { GetEnvironmentVariableW(name.as_ptr(), ptr::null_mut(), 0) };
        if len == 0 { None } else { Some(len as usize) }
    }

    fn get_env_var(&self, name: &[u16], value: &mut [u16]) {
        unsafe {
            GetEnvironmentVariableW(name.as_ptr(), value.as_mut_ptr(), (value.len() - 1) as u32)
        };
    }
}

fn search_path(file: &[u16], cwd: &[u16], path: Option<&[u16]>, _flags: u32) -> Option<WCString> {
    // If the caller supplies an empty filename,
    // we're not gonna return c:\windows\.exe -- GFY!
    if file.is_empty() || (file.len() == 1 && file[0] == wchar!('.')) {
        return None;
    }

    let file_len = file.len();

    // Find the start of the filename so we can split the directory from the name
    let mut file_name_start = file_len;
    while file_name_start > 0 {
        let prev = file[file_name_start - 1];
        if prev == wchar!('\\') || prev == wchar!('/') || prev == wchar!(':') {
            break;
        }
        file_name_start -= 1;
    }

    let file_has_dir = file_name_start > 0;

    // Check if the filename includes an extension
    let name_slice = &file[file_name_start..];
    let dot_pos = name_slice.iter().position(|&c| c == wchar!('.'));
    let name_has_ext = dot_pos.map_or(false, |pos| pos + 1 < name_slice.len());

    if file_has_dir {
        // The file has a path inside, don't use path
        return search_path_walk_ext(
            &file[..file_name_start],
            &file[file_name_start..],
            cwd,
            name_has_ext,
        );
    } else {
        // Check if we need to search in the current directory first
        let empty = [0u16; 1];
        let need_cwd = unsafe { NeedCurrentDirectoryForExePathW(empty.as_ptr()) != 0 };

        if need_cwd {
            // The file is really only a name; look in cwd first, then scan path
            if let Some(result) = search_path_walk_ext(&[], file, cwd, name_has_ext) {
                return Some(result);
            }
        }

        // If path is None, we've checked cwd and there's nothing else to do
        let path = match path {
            Some(p) => p,
            None => return None,
        };

        // Handle path segments
        let mut dir_end = 0;
        loop {
            // If we've reached the end of the path, stop searching
            if dir_end >= path.len() || path[dir_end] == 0 {
                break;
            }

            // Skip the separator that dir_end now points to
            if dir_end > 0 || path[0] == wchar!(';') {
                dir_end += 1;
            }

            // Next slice starts just after where the previous one ended
            let dir_start = dir_end;

            // Handle quoted paths
            let is_quoted = path[dir_start] == wchar!('"') || path[dir_start] == wchar!('\'');
            let quote_char = if is_quoted { path[dir_start] } else { 0 };

            // Find the end of this directory component
            if is_quoted {
                // Find closing quote
                dir_end = dir_start + 1;
                while dir_end < path.len() && path[dir_end] != quote_char {
                    dir_end += 1;
                }
                if dir_end == path.len() {
                    // No closing quote, treat rest as the path
                    dir_end = path.len();
                }
            }

            // Find next separator (;) or end
            while dir_end < path.len() && path[dir_end] != wchar!(';') && path[dir_end] != 0 {
                dir_end += 1;
            }

            // If the slice is zero-length, don't bother
            if dir_end == dir_start {
                continue;
            }

            // Determine actual directory path, handling quotes
            let mut dir_path = &path[dir_start..dir_end];

            // Adjust if the path is quoted.
            if is_quoted && dir_path.len() > 0 {
                dir_path = &dir_path[1..]; // Skip opening quote
                if dir_path.len() > 0 && (dir_path[dir_path.len() - 1] == quote_char) {
                    dir_path = &dir_path[..dir_path.len() - 1]; // Skip closing quote
                }
            }

            if let Some(result) = search_path_walk_ext(dir_path, file, cwd, name_has_ext) {
                return Some(result);
            }
        }
    }

    None
}

// Define signal values matching the ones in libuv
const SIGKILL: i32 = 9;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const SIGQUIT: i32 = 3;

// Define total number of signals
const NSIG: i32 = 32;

// Define the dump options constant missing in the Windows crate
const AVX_XSTATE_CONTEXT: MINIDUMP_TYPE = 0x00200000;

/// Kill a process identified by process handle with a specific signal
///
/// Returns 0 on success, or a negative error code.
fn uv__kill(process_handle: HANDLE, signum: i32) -> Result<(), std::io::Error> {
    // Validate signal number
    if signum < 0 || signum >= NSIG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid signal number",
        ));
    }

    // Create a dump file for SIGQUIT
    if signum == SIGQUIT {
        unsafe {
            // Local variables
            let mut registry_key = 0;
            let pid = GetProcessId(process_handle);
            let mut basename_buf = [0u16; 260]; // MAX_PATH

            // Get target process name
            GetModuleBaseNameW(
                process_handle,
                ptr::null_mut(), // No module handle, want process name
                basename_buf.as_mut_ptr(),
                basename_buf.len() as u32,
            );

            // Get LocalDumps directory path
            let registry_result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!("SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"),
                0,
                KEY_QUERY_VALUE,
                &mut registry_key as *mut _ as *mut HKEY,
            );

            if registry_result == ERROR_SUCCESS {
                let mut dump_folder = [0u16; 260]; // MAX_PATH
                let mut dump_name = [0u16; 260]; // MAX_PATH
                let mut dump_folder_len = dump_folder.len() as u32 * 2; // Size in bytes
                let mut key_type = 0;

                // Try to get DumpFolder from registry
                let ret = RegGetValueW(
                    registry_key as HKEY,
                    ptr::null(),
                    w!("DumpFolder"),
                    RRF_RT_ANY,
                    &mut key_type,
                    dump_folder.as_mut_ptr() as *mut _,
                    &mut dump_folder_len,
                );

                if ret != ERROR_SUCCESS {
                    // Default value for dump_folder is %LOCALAPPDATA%\CrashDumps
                    let mut localappdata: *mut u16 = ptr::null_mut();
                    SHGetKnownFolderPath(
                        &FOLDERID_LocalAppData,
                        0,
                        ptr::null_mut(),
                        &mut localappdata,
                    );

                    let localappdata_len = wcslen(localappdata);
                    wcsncpy(dump_folder.as_mut_ptr(), localappdata, localappdata_len);

                    let crashdumps = w!("\\CrashDumps");
                    let crashdumps_len = wcslen(crashdumps);
                    wcsncpy(
                        dump_folder.as_mut_ptr().add(localappdata_len),
                        crashdumps,
                        crashdumps_len,
                    );

                    // Null-terminate
                    dump_folder[localappdata_len + crashdumps_len] = 0;

                    // Free the memory allocated by SHGetKnownFolderPath
                    CoTaskMemFree(localappdata as _);
                }

                // Close registry key
                RegCloseKey(registry_key as HKEY);

                // Create dump folder if it doesn't already exist
                CreateDirectoryW(dump_folder.as_ptr(), ptr::null());

                // Construct dump filename from process name and PID
                // Find the null terminator in basename
                let mut basename_len = 0;
                while basename_len < basename_buf.len() && basename_buf[basename_len] != 0 {
                    basename_len += 1;
                }

                // Copy dump_folder to dump_name
                let mut dump_folder_len = 0;
                while dump_folder_len < dump_folder.len() && dump_folder[dump_folder_len] != 0 {
                    dump_name[dump_folder_len] = dump_folder[dump_folder_len];
                    dump_folder_len += 1;
                }

                // Add path separator if needed
                if dump_folder_len > 0 && dump_name[dump_folder_len - 1] != wchar!('\\') {
                    dump_name[dump_folder_len] = wchar!('\\');
                    dump_folder_len += 1;
                }

                // Concatenate basename
                for i in 0..basename_len {
                    dump_name[dump_folder_len + i] = basename_buf[i];
                }
                dump_folder_len += basename_len;

                // Add dot and PID
                dump_name[dump_folder_len] = wchar!('.');
                dump_folder_len += 1;

                // Convert PID to characters
                let mut pid_remaining = pid;
                let mut pid_digits = [0u16; 10]; // Enough for 32-bit number
                let mut pid_len = 0;

                // Handle zero case explicitly
                if pid_remaining == 0 {
                    pid_digits[0] = wchar!('0');
                    pid_len = 1;
                } else {
                    // Extract digits in reverse order
                    while pid_remaining > 0 {
                        pid_digits[pid_len] = wchar!('0') + (pid_remaining % 10) as u16;
                        pid_remaining /= 10;
                        pid_len += 1;
                    }

                    // Reverse the digits
                    for i in 0..pid_len / 2 {
                        let temp = pid_digits[i];
                        pid_digits[i] = pid_digits[pid_len - 1 - i];
                        pid_digits[pid_len - 1 - i] = temp;
                    }
                }

                // Add PID digits to dump_name
                for i in 0..pid_len {
                    dump_name[dump_folder_len + i] = pid_digits[i];
                }
                dump_folder_len += pid_len;

                // Add .dmp extension
                let dmp_ext = w!(".dmp");
                let dmp_ext_len = wcslen(dmp_ext);
                wcsncpy(
                    dump_name.as_mut_ptr().add(dump_folder_len),
                    dmp_ext,
                    dmp_ext_len,
                );
                // Set null terminator
                dump_name[dump_folder_len + dmp_ext_len] = 0;

                // Create dump file
                let h_dump_file = CreateFileW(
                    dump_name.as_ptr(),
                    GENERIC_WRITE,
                    0,
                    ptr::null(),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                );

                if h_dump_file != INVALID_HANDLE_VALUE {
                    // Check against INVALID_HANDLE_VALUE
                    // If something goes wrong while writing it out, delete the file
                    let delete_on_close = FILE_DISPOSITION_INFO { DeleteFile: 1 }; // 1 = TRUE for DeleteFile
                    SetFileInformationByHandle(
                        h_dump_file,
                        FileDispositionInfo,
                        &delete_on_close as *const _ as *const _,
                        std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                    );

                    // Tell wine to dump ELF modules as well
                    let sym_options = SymGetOptions();
                    SymSetOptions(sym_options | 0x40000000);

                    // We default to a fairly complete dump
                    let dump_options: MINIDUMP_TYPE = MiniDumpWithFullMemory
                        | MiniDumpIgnoreInaccessibleMemory
                        | AVX_XSTATE_CONTEXT;

                    let success = MiniDumpWriteDump(
                        process_handle,
                        pid,
                        h_dump_file,
                        dump_options,
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                    );

                    if success != 0 {
                        // Don't delete the file on close if we successfully wrote it out
                        let dont_delete_on_close = FILE_DISPOSITION_INFO { DeleteFile: 0 }; // 0 = FALSE for DeleteFile
                        SetFileInformationByHandle(
                            h_dump_file,
                            FileDispositionInfo,
                            &dont_delete_on_close as *const _ as *const _,
                            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                        );
                    }

                    // Restore symbol options
                    SymSetOptions(sym_options);

                    // Close dump file
                    CloseHandle(h_dump_file);
                }
            }
        }
    }

    // Handle different signal cases
    match signum {
        SIGQUIT | SIGTERM | SIGKILL | SIGINT => {
            // Unconditionally terminate the process
            unsafe {
                if TerminateProcess(process_handle, 1) != 0 {
                    return Ok(());
                }

                // If the process already exited before TerminateProcess was called,
                // TerminateProcess will fail with ERROR_ACCESS_DENIED
                let err = GetLastError();
                if err == ERROR_ACCESS_DENIED {
                    // First check using GetExitCodeProcess() with status different from
                    // STILL_ACTIVE (259)
                    let mut status = 0;
                    if GetExitCodeProcess(process_handle, &mut status) != 0
                        && status != STILL_ACTIVE as u32
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Process not found",
                        ));
                    }

                    // But the process could have exited with code == STILL_ACTIVE, use
                    // WaitForSingleObject with timeout zero
                    if WaitForSingleObject(process_handle, 0) == WAIT_OBJECT_0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "Process not found",
                        ));
                    }
                }

                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
        }

        // Health check: is the process still alive?
        0 => unsafe {
            let mut status = 0;
            if GetExitCodeProcess(process_handle, &mut status) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            if status != STILL_ACTIVE as u32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Process not found",
                ));
            }

            match WaitForSingleObject(process_handle, 0) {
                WAIT_OBJECT_0 => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Process not found",
                    ));
                }
                WAIT_FAILED => return Err(std::io::Error::last_os_error()),
                WAIT_TIMEOUT => return Ok(()),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unknown error",
                    ));
                }
            }
        },

        // Unsupported signal
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unsupported signal",
            ));
        }
    }
}

/// Kill a process using its pid
pub fn process_kill(pid: i32, signum: i32) -> Result<(), std::io::Error> {
    unsafe {
        // Get process handle based on pid
        let process_handle = if pid == 0 {
            GetCurrentProcess()
        } else {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
                FALSE,
                pid as u32,
            )
        };

        if process_handle == ptr::null_mut() {
            // let err = GetLastError();
            // if err == ERROR_INVALID_PARAMETER {
            //     return Err(std::io::Error::new(
            //         std::io::ErrorKind::NotFound,
            //         "Process not found",
            //     ));
            // } else {
            //     return Err(std::io::Error::new(
            //         std::io::ErrorKind::Other,
            //         translate_sys_error(err),
            //     ));
            // }
            //
            return Err(std::io::Error::last_os_error());
        }

        let result = uv__kill(process_handle, signum);

        // Close the handle if we opened it
        if pid != 0 {
            CloseHandle(process_handle);
        }

        result
    }
}

// /// Kill a process owned by a uv_process_t handle
// pub fn uv_process_kill(process: &mut uv_process) -> i32 {
//     if process.process_handle == INVALID_HANDLE_VALUE {
//         return Error::EINVAL as i32;
//     }

//     let err = uv__kill(process.process_handle, SIGTERM);
//     if err != 0 {
//         return err; // err is already translated.
//     }

//     process.exit_signal = SIGTERM;
//     0
// }

// // Close a process handle
// pub fn uv__process_close(process: &mut uv_process) {
//     // Mark handle as closing
//     // uv__handle_closing(process);

//     if process.wait_handle != INVALID_HANDLE_VALUE {
//         // This blocks until either the wait was cancelled, or the callback has
//         // completed.
//         let r = unsafe { UnregisterWaitEx(process.wait_handle, INVALID_HANDLE_VALUE) };
//         if r == 0 {
//             // This should never happen, and if it happens, we can't recover...
//             uv_fatal_error("UnregisterWaitEx");
//         }

//         process.wait_handle = INVALID_HANDLE_VALUE;
//     }

//     if !process.exit_cb_pending.load(Ordering::Relaxed) {
//         // uv__want_endgame(loop, (uv_handle_t*)process);
//     }
// }

// // Process endgame (final cleanup)
// pub fn uv__process_endgame(process: &mut uv_process) {
//     assert!(!process.exit_cb_pending.load(Ordering::Relaxed));
//     // assert!(process.flags & UV_HANDLE_CLOSING);
//     // assert!(!(process.flags & UV_HANDLE_CLOSED));

//     // Clean-up the process handle
//     unsafe { CloseHandle(process.process_handle) };

//     // uv__handle_close(process);
// }

// Translate Windows system error to a UV error code
fn translate_sys_error(err: u32) -> Error {
    match err as u32 {
        ERROR_INVALID_PARAMETER => Error::EINVAL,
        ERROR_ACCESS_DENIED => Error::EACCES,
        ERROR_OUTOFMEMORY => Error::ENOMEM,
        ERROR_FILE_NOT_FOUND => Error::ESRCH,
        err => {
            eprintln!("Unknown error: {}", err);
            Error::UNKNOWN
        } // Default to UNKNOWN for other error codes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_quote_cmd_arg() {
        let cases = [
            ("hello\"world", r#""hello\"world""#),
            ("hello\"\"world", r#""hello\"\"world""#),
            ("hello\\world", "hello\\world"),
            ("hello\\\\world", "hello\\\\world"),
            ("hello\\\"world", r#""hello\\\"world""#),
            ("hello\\\\\"world", r#""hello\\\\\"world""#),
            ("hello world\\", r#""hello world\\""#),
        ];

        for (input, expected) in cases {
            let s = input.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let s = WCString::from_vec(s);
            let mut out = Vec::new();
            quote_cmd_arg(s.as_wcstr(), &mut out);
            let out_s = String::from_utf16_lossy(&out);
            assert_eq!(out_s, expected);
        }
    }

    #[test]
    fn test_make_program_args() {
        let args = ["hello", "world", "\"hello world\""]
            .into_iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>();
        let verbatim_arguments = false;
        let result = make_program_args(&args, verbatim_arguments).unwrap();
        assert_eq!(result, WCString::new("hello world \"\\\"hello world\\\"\""));
    }
}
