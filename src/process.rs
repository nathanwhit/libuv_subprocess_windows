#![allow(nonstandard_style)]
use std::{
    borrow::Cow,
    cell::UnsafeCell,
    ffi::{CStr, OsStr},
    marker::PhantomData,
    mem,
    ops::{BitAnd, BitOr},
    os::windows::raw::HANDLE,
    ptr::{self, null, null_mut},
    sync::{OnceLock, atomic::AtomicBool},
};

use windows_sys::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, FALSE, GetLastError, INVALID_HANDLE_VALUE, LocalFree},
        Globalization::GetSystemDefaultLangID,
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::Debug::{
                FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
                FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageA,
            },
            Threading::{GetCurrentProcess, PROCESS_INFORMATION, STARTUPINFOW},
        },
    },
    w,
};

use crate::widestr::{WCStr, WCString};

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

struct uv_process {
    pid: i32,
    exit_cb: Option<fn(*const uv_process, u64, i32)>,
    exit_signal: i32,
    wait_handle: HANDLE,
    process_handle: HANDLE,
    exit_cb_pending: AtomicBool,
    // maybe uv_req?
}

struct uv_process_options<'a> {
    exit_cb: Option<fn(*const uv_process, u64, i32)>,
    flags: u32,
    file: Cow<'a, str>,
    args: *const *const u8,
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

    target.push(wchar!('\0'));
    let len = target.len();
    target[start..len - 1].reverse();

    target.push(wchar!('"'));
}

fn make_program_args(args: &[&str], verbatim_arguments: bool) -> Result<WCString, Error> {
    let mut dst_len = 0;
    let mut temp_buffer_len = 0;

    // Count the required size.
    for arg in args {
        let arg_len = arg.chars().map(|c| c.len_utf16()).sum::<usize>();
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
        temp_buffer.extend(arg.encode_utf16());

        if verbatim_arguments {
            dst.extend(temp_buffer.as_slice());
        } else {
            quote_cmd_arg(unsafe { WCStr::from_wchars(&temp_buffer) }, &mut dst);
        }

        if i < args.len() - 1 {
            dst.push(wchar!(' '));
        }
    }

    let wcstring = WCString::from_vec(dst);
    Ok(wcstring)
}

impl uv_process {
    pub fn init() -> Self {
        Self {
            exit_cb: None,
            exit_signal: 0,
            pid: 0,
            wait_handle: INVALID_HANDLE_VALUE,
            process_handle: INVALID_HANDLE_VALUE,
            exit_cb_pending: AtomicBool::new(false),
        }
    }

    pub fn spawn(&mut self, options: &uv_process_options) -> Result<(), Error> {
        // let mut i = 0;
        // let mut err = 0;
        // let mut path = None;
        // let mut alloc_path = None;
        // let mut application_path = None;
        // let mut application = None;
        // let mut arguments = None;
        // let mut startup = unsafe { mem::zeroed::<STARTUPINFOW>() };
        // let mut info = unsafe { mem::zeroed::<PROCESS_INFORMATION>() };
        // let mut process_flags = 0;
        // let mut cwd_len = 0;
        // let mut child_stdio_buffer = None;

        // self.exit_cb = options.exit_cb;

        // if options.flags & (uv_process_flags::SetUid | uv_process_flags::SetGid) != 0 {
        //     return Err(Error::ENOTSUP);
        // }

        // if options.file == None || options.args == None {
        //     return Err(Error::EINVAL);
        // }

        todo!()
    }
}

enum Error {
    ENOTSUP,
    EINVAL,
}

impl BitOr for uv_process_flags {
    type Output = u32;

    fn bitor(self, rhs: Self) -> Self::Output {
        self as u32 | rhs as u32
    }
}

impl BitOr<u32> for uv_process_flags {
    type Output = u32;

    fn bitor(self, rhs: u32) -> Self::Output {
        self as u32 | rhs
    }
}

impl BitAnd<u32> for uv_process_flags {
    type Output = u32;

    fn bitand(self, rhs: u32) -> Self::Output {
        self as u32 & rhs
    }
}

impl BitAnd<uv_process_flags> for u32 {
    type Output = u32;

    fn bitand(self, rhs: uv_process_flags) -> Self::Output {
        self & rhs as u32
    }
}

impl BitAnd for uv_process_flags {
    type Output = u32;

    fn bitand(self, rhs: uv_process_flags) -> Self::Output {
        self as u32 & rhs as u32
    }
}

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
    let mut result = Vec::new();

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

fn search_path_walk_ext(dir: &[u16], name: &[u16], ext: &[u16], cwd: &[u16]) -> Option<WCString> {
    let name_has_ext = !ext.is_empty();

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

fn search_path(file: &[u16], cwd: &[u16], path: Option<&[u16]>, flags: u32) -> Option<WCString> {
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
        return search_path_walk_ext(&file[..file_name_start], &file[file_name_start..], &[], cwd);
    } else {
        // Check if we need to search in the current directory first
        use windows_sys::Win32::System::Environment::NeedCurrentDirectoryForExePathW;
        let empty = [0u16; 1];
        let need_cwd = unsafe { NeedCurrentDirectoryForExePathW(empty.as_ptr()) != 0 };

        if need_cwd {
            // The file is really only a name; look in cwd first, then scan path
            if let Some(result) = search_path_walk_ext(&[], file, &[], cwd) {
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

            if let Some(result) = search_path_walk_ext(dir_path, file, &[], cwd) {
                return Some(result);
            }
        }
    }

    None
}
