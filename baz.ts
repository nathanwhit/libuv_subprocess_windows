import net from "node:net";
const sock = new net.Socket({ fd: 3 });

sock.on("data", (data) => {
  console.log("got data", data.toString());
});

// sock.write("hello");
