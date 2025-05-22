use libuv_subprocess_windows::Command;

fn main() {
    let mut cmd = Command::new("deno");
    cmd.arg("eval")
        .arg("Deno.writeTextFileSync('D:\\Work\\foo.txt', 'hi')");
    let mut child = cmd.spawn().unwrap();
    let exit_code = child.wait().unwrap();
    println!("exit_code: {:?}", exit_code);
}
