use std::io::{Read, Write};

use libuv_subprocess_windows::Command;
// use std::process::Command;

fn main() {
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
        .arg("\"hello world\"")
        .spawn()
        .unwrap();

    eprintln!("pid: {}", child.id());

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    stdin.write_all(b"hello world\n").unwrap();

    let mut buf = Vec::new();

    // std::thread::sleep(Duration::from_millis(5000));
    let exit_code = child.wait().unwrap();
    stdout.read_to_end(&mut buf).unwrap();
    println!("stdout: {}", String::from_utf8(buf).unwrap());

    println!("exit_code: {:?}", exit_code);
}
