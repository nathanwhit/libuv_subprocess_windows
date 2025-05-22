#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod process_stdio;

pub mod widestr;

#[cfg(windows)]
pub use foo::Command;

#[cfg(windows)]
mod foo {
    use std::borrow::Cow;
    use std::ptr::null_mut;

    use crate::process::*;
    use crate::process_stdio::*;

    pub struct Command {
        program: String,
        args: Vec<String>,
    }

    impl Command {
        pub fn new<S: AsRef<str>>(program: S) -> Self {
            Self {
                program: program.as_ref().to_string(),
                args: vec![],
            }
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

        pub fn spawn(&mut self) -> Result<ChildProcess, Error> {
            uv_process::spawn(&uv_process_options {
                exit_cb: None,
                flags: 0,
                file: Cow::Borrowed(&self.program),
                args: self
                    .args
                    .iter()
                    .map(|a| Cow::Borrowed(a.as_str()))
                    .collect(),
                env: None,
                cwd: None,
                stdio_count: 3,
                stdio: vec![
                    StdioContainer::InheritFd(0),
                    StdioContainer::InheritFd(1),
                    StdioContainer::InheritFd(2),
                ],
            })
        }
    }
}
