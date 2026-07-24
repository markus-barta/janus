import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const browserDir = import.meta.dirname;
const repo = path.dirname(browserDir);
const outputDir = path.join(browserDir, "test-results");
const cli = path.join(repo, "node_modules", "@playwright", "test", "cli.js");
const config = path.join(browserDir, "playwright.config.mjs");

const result = spawnSync(process.execPath, [cli, "test", "--config", config], {
  cwd: repo,
  env: process.env,
  stdio: "inherit",
});

let artifactSafe = true;
const files = [];
if (fs.existsSync(outputDir)) {
  const pending = [outputDir];
  while (pending.length > 0) {
    const item = pending.pop();
    const stat = fs.statSync(item);
    if (stat.isDirectory()) {
      for (const child of fs.readdirSync(item)) {
        pending.push(path.join(item, child));
      }
    } else {
      files.push(path.relative(outputDir, item));
    }
  }
}

if (files.length !== 1 || files[0] !== ".last-run.json") {
  artifactSafe = false;
} else {
  try {
    const receipt = JSON.parse(
      fs.readFileSync(path.join(outputDir, ".last-run.json"), "utf8"),
    );
    const keys = Object.keys(receipt).sort();
    artifactSafe =
      JSON.stringify(keys) === JSON.stringify(["failedTests", "status"]) &&
      ["passed", "failed"].includes(receipt.status) &&
      Array.isArray(receipt.failedTests) &&
      receipt.failedTests.every(
        (testId) =>
          typeof testId === "string" && /^[a-zA-Z0-9_-]{1,160}$/.test(testId),
      );
  } catch {
    artifactSafe = false;
  }
}

if (!artifactSafe) {
  console.error(
    "error: managed browser assurance produced an unreviewed failure artifact",
  );
}
if (result.error) {
  console.error("error: managed browser assurance process could not start");
}
process.exit(result.error || !artifactSafe ? 1 : (result.status ?? 1));
