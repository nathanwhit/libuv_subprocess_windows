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
    use std::collections::HashMap;

    use crate::process::*;
    use crate::process_stdio::*;

    pub struct Command {
        program: String,
        args: Vec<String>,
        envs: HashMap<String, String>,
        env_clear: bool,
        detached: bool,
    }

    impl Command {
        pub fn new<S: AsRef<str>>(program: S) -> Self {
            Self {
                program: program.as_ref().to_string(),
                args: vec![program.as_ref().to_string()],
                envs: HashMap::new(),
                env_clear: false,
                detached: false,
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

        pub fn spawn(&mut self) -> Result<ChildProcess, Error> {
            let mut flags = 0;
            if self.detached {
                flags |= uv_process_flags::Detached;
            }
            uv_process::spawn(&uv_process_options {
                exit_cb: None,
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
