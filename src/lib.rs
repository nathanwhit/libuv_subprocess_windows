#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod process_stdio;

mod widestr;

#[cfg(windows)]
pub use foo::Command;
#[cfg(windows)]
pub use foo::Stdio;

#[cfg(windows)]
pub mod anon_pipe;

#[cfg(windows)]
mod foo {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::IntoRawHandle;
    use std::os::windows::io::OwnedHandle;
    use std::os::windows::raw::HANDLE;
    use std::process::ChildStderr;
    use std::process::ChildStdin;
    use std::process::ChildStdout;

    use crate::process::*;
    use crate::process_stdio::*;

    pub enum Stdio {
        Inherit,
        Pipe,
        Null,
    }

    impl From<Stdio> for std::process::Stdio {
        fn from(stdio: Stdio) -> Self {
            match stdio {
                Stdio::Inherit => std::process::Stdio::inherit(),
                Stdio::Pipe => std::process::Stdio::piped(),
                Stdio::Null => std::process::Stdio::null(),
            }
        }
    }

    pub struct Child {
        process: ChildProcess,
        pub stdin: Option<ChildStdin>,
        pub stdout: Option<ChildStdout>,
        pub stderr: Option<ChildStderr>,
    }

    impl Child {
        pub fn id(&self) -> i32 {
            self.process.pid()
        }

        pub fn wait(&mut self) -> Result<i32, std::io::Error> {
            self.process.wait()
        }

        pub fn try_wait(&mut self) -> Result<Option<i32>, std::io::Error> {
            self.process.try_wait()
        }
    }

    pub struct Command {
        program: String,
        args: Vec<String>,
        envs: HashMap<String, String>,
        env_clear: bool,
        detached: bool,
        cwd: Option<String>,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
        extra_handles: Vec<Option<HANDLE>>,
    }

    impl Command {
        pub fn new<S: AsRef<str>>(program: S) -> Self {
            Self {
                program: program.as_ref().to_string(),
                args: vec![program.as_ref().to_string()],
                envs: HashMap::new(),
                env_clear: false,
                detached: false,
                cwd: None,
                stdin: Stdio::Inherit,
                stdout: Stdio::Inherit,
                stderr: Stdio::Inherit,
                extra_handles: vec![],
            }
        }

        pub fn cwd<S: AsRef<str>>(&mut self, cwd: S) -> &mut Self {
            self.cwd = Some(cwd.as_ref().to_string());
            self
        }

        pub fn arg<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
            self.args.push(arg.as_ref().to_string());
            self
        }

        pub fn args<I: IntoIterator<Item = S>, S: AsRef<str>>(&mut self, args: I) -> &mut Self {
            self.args
                .extend(args.into_iter().map(|a| a.as_ref().to_string()));
            self
        }

        pub fn env<S: AsRef<str>>(&mut self, key: S, value: S) -> &mut Self {
            self.envs
                .insert(key.as_ref().to_string(), value.as_ref().to_string());
            self
        }

        pub fn detached(&mut self) -> &mut Self {
            self.detached = true;
            self
        }

        pub fn env_clear(&mut self) -> &mut Self {
            self.env_clear = true;
            self.envs.clear();
            self
        }

        pub fn stdin(&mut self, stdin: Stdio) -> &mut Self {
            self.stdin = stdin;
            self
        }

        pub fn stdout(&mut self, stdout: Stdio) -> &mut Self {
            self.stdout = stdout;
            self
        }

        pub fn stderr(&mut self, stderr: Stdio) -> &mut Self {
            self.stderr = stderr;
            self
        }

        pub fn extra_handle(&mut self, handle: Option<HANDLE>) -> &mut Self {
            self.extra_handles.push(handle);
            self
        }

        pub fn spawn(&mut self) -> Result<Child, std::io::Error> {
            let mut flags = 0;
            if self.detached {
                flags |= uv_process_flags::Detached;
            }

            let (stdin, child_stdin) = match self.stdin {
                Stdio::Pipe => {
                    let pipes = crate::anon_pipe::anon_pipe(false, true)?;
                    let child_stdin_handle = pipes.ours.into_handle();
                    let stdin_handle = pipes.theirs.into_handle().into_raw_handle();

                    (
                        StdioContainer::RawHandle(stdin_handle),
                        Some(ChildStdin::from(child_stdin_handle)),
                    )
                }
                Stdio::Null => (StdioContainer::Ignore, None),
                Stdio::Inherit => (StdioContainer::InheritFd(0), None),
            };
            let (stdout, child_stdout) = match self.stdout {
                Stdio::Pipe => {
                    let pipes = crate::anon_pipe::anon_pipe(true, true)?;
                    let child_stdout_handle = pipes.ours.into_handle();
                    let stdout_handle = pipes.theirs.into_handle().into_raw_handle();

                    (
                        StdioContainer::RawHandle(stdout_handle),
                        Some(ChildStdout::from(child_stdout_handle)),
                    )
                }
                Stdio::Null => (StdioContainer::Ignore, None),
                Stdio::Inherit => (StdioContainer::InheritFd(1), None),
            };
            let (stderr, child_stderr) = match self.stderr {
                Stdio::Pipe => {
                    let pipes = crate::anon_pipe::anon_pipe(true, true)?;
                    let child_stderr_handle = pipes.ours.into_handle();
                    let stderr_handle = pipes.theirs.into_handle().into_raw_handle();

                    (
                        StdioContainer::RawHandle(stderr_handle),
                        Some(ChildStderr::from(child_stderr_handle)),
                    )
                }
                Stdio::Null => (StdioContainer::Ignore, None),
                Stdio::Inherit => (StdioContainer::InheritFd(2), None),
            };

            let mut stdio = Vec::with_capacity(3 + self.extra_handles.len());
            stdio.extend([stdin, stdout, stderr]);
            stdio.extend(self.extra_handles.iter().map(|h| {
                h.map(|h| StdioContainer::RawHandle(h))
                    .unwrap_or(StdioContainer::Ignore)
            }));

            let res = crate::process::spawn(&uv_process_options {
                flags,
                file: Cow::Borrowed(&self.program),
                args: self
                    .args
                    .iter()
                    .map(|a| Cow::Borrowed(a.as_str()))
                    .collect(),
                env: if self.envs.is_empty() {
                    if self.env_clear { Some(vec![]) } else { None }
                } else {
                    let explicit_envs = self
                        .envs
                        .iter()
                        .map(|(k, v)| Cow::<str>::Owned(format!("{}={}", k, v)));
                    let env: Vec<Cow<str>> = if self.env_clear {
                        explicit_envs.collect()
                    } else {
                        explicit_envs
                            .chain(
                                std::env::vars().map(|(k, v)| Cow::Owned(format!("{}={}", k, v))),
                            )
                            .collect()
                    };
                    Some(env)
                },
                cwd: self.cwd.as_deref().map(Cow::Borrowed),
                stdio,
            })
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))
            .map(|process| Child {
                process,
                stdin: child_stdin,
                stdout: child_stdout,
                stderr: child_stderr,
            });

            res
        }
    }
}
