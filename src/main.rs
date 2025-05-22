use libuv_subprocess_windows::Command;

fn main() {
    eprintln!("{:?}", std::env::args().collect::<Vec<_>>());
    let mut cmd = Command::new("deno.exe");
    cmd.arg("deno.exe")
        .arg("eval")
        .env("FOO", "bar")
        .arg("console.log('D:\\\\Work\\\\foo.txt', 'hi', Deno.env.get('FOO'))");
    let mut child = cmd.spawn().unwrap();
    let exit_code = child.wait().unwrap();
    println!("exit_code: {:?}", exit_code);
}
