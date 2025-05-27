#!/usr/bin/env -S deno run -A
import TOML from "jsr:@nathanwhit/toml-edit";
import { dirname, fromFileUrl, join } from "jsr:@std/path";
import { parseArgs } from "jsr:@std/cli";

const tools = dirname(fromFileUrl(import.meta.url));
const root = join(tools, "..");
const pth = (...args: string[]) => join(root, ...args);

const cargoTOMLData = TOML.parse(Deno.readTextFileSync(pth("Cargo.toml")));

const args = parseArgs(Deno.args, {
  boolean: ["split"],
  alias: {
    s: "split",
  },
});

let processedArgs = [];
if (args.split) {
  processedArgs = args._.map((f) => f.toString()).join().split(",").map((f) =>
    f.trim().replaceAll(/^"|"$/g, "")
  );
} else {
  processedArgs = args._.map((f) => f.toString());
}
if (Deno.args.length === 0) {
  console.error("No features to add");
  Deno.exit(1);
}

for (const depTarget of ["x86_64-pc-windows-gnu", "x86_64-pc-windows-msvc"]) {
  const deps = cargoTOMLData.target[depTarget].dependencies;
  const feats = deps["windows-sys"].features;
  const featsToAdd = processedArgs.map((feat) => feat.trim()).filter(
    (feat) => feat.length > 0 && !feats.includes(feat),
  );

  if (featsToAdd.length === 0) {
    console.error(`Features already included for ${depTarget}`);
    continue;
  }

  feats.push(...featsToAdd);
}

Deno.writeTextFileSync(pth("Cargo.toml"), TOML.stringify(cargoTOMLData));
