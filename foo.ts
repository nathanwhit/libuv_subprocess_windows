import { spawn } from "node:child_process";

const child = spawn("deno.exe", ["eval", "console.log('Hello, world!');"], {
  stdio: "inherit",
});
child.on("exit", () => {
  console.log("exited");
});
