#!/usr/bin/env node
import { main } from "../dist/src/cli.js";

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    const message = err instanceof Error ? err.message : "verification failed";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  },
);
