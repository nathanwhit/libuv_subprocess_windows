use libuv_subprocess_windows::Command;

fn main() {
    eprintln!("{:?}", std::env::args().collect::<Vec<_>>());
    let mut cmd = Command::new("deno.exe");
    let mut child = cmd
        .arg("run")
        .arg("-A")
        // .detached()
        .arg("bar.ts")
        .arg("thing")
        .spawn()
        .unwrap();

    eprintln!("pid: {}", child.pid());

    // std::thread::sleep(Duration::from_millis(5000));
    let exit_code = child.wait().unwrap();
    println!("exit_code: {:?}", exit_code);
}
