use std::{
    io::{Read, Write},
    os::windows::io::IntoRawHandle,
};

use libuv_subprocess_windows::Command;
// use std::process::Command;

fn main() {
    let (r, mut w) = std::io::pipe().unwrap();
    let theirs = r.into_raw_handle();

    let theirs = unsafe { libuv_subprocess_windows::process_stdio::uv_duplicate_handle(theirs) };
    let theirs = theirs.unwrap();

    let mut cmd = Command::new("deno.exe");
    let mut child = cmd
        .arg("run")
        .arg("-A")
        // .detached()
        .arg("bar.ts")
        .arg("thing")
        .stdin(libuv_subprocess_windows::Stdio::Pipe)
        .stdout(libuv_subprocess_windows::Stdio::Pipe)
        .env("FORCE_COLOR", "1")
        // .stderr(libuv_subprocess_windows::Stdio::Inherit)
        .extra_handle(Some(theirs))
        .spawn()
        .unwrap();

    // let mut cmd = Command::new("node.exe");
    // let mut child = cmd
    //     // .arg("run")
    //     // .arg("-A")
    //     // .detached()
    //     .arg("baz.ts")
    //     .arg("thing")
    //     .stdin(libuv_subprocess_windows::Stdio::Pipe)
    //     .extra_handle(Some(theirs))
    //     .spawn()
    //     .unwrap();

    eprintln!("pid: {}", child.id());

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    w.write_all(b"hello world\n").unwrap();
    stdin.write_all(b"hello world\n").unwrap();

    let mut buf = Vec::new();

    // std::thread::sleep(Duration::from_millis(5000));
    let exit_code = child.wait().unwrap();
    stdout.read_to_end(&mut buf).unwrap();
    println!("stdout: {}", String::from_utf8(buf).unwrap());
    println!("exit_code: {:?}", exit_code);
}
