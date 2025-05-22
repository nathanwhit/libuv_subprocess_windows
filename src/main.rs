use libuv_subprocess_windows::Command;

fn main() {
    let mut cmd = Command::new("deno");
    cmd.arg("eval")
        .arg("Deno.writeTextFileSync('D:\\Work\\foo.txt', 'hi')");
    cmd.spawn();
}
