console.log("hi world", Deno.args);

const buf = new Uint8Array(1024);
const n = Deno.stdin.readSync(buf);
if (n === null) {
  console.log("null");
} else {
  console.log("got from parent");
  console.log(n);
  console.log(new TextDecoder().decode(buf.slice(0, n)));
}
