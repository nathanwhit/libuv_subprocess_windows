let i = 0;
const interval = setInterval(() => {
  Deno.writeTextFileSync("foo.txt", `Hello, world! ${i++}`);
}, 1000);

setTimeout(() => {
  clearInterval(interval);
}, 15000);
