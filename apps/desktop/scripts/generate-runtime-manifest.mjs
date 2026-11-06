import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rename, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REQUIRED_SIDECARS = [
  "cyberaudit-postgres",
  "cyberaudit-valkey",
  "cyberaudit-api",
  "cyberaudit-worker",
  "cyberaudit-web",
];

async function sha256(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

export async function generateRuntimeManifest(
  runtimeRoot,
  { windows = false } = {},
) {
  const root = resolve(runtimeRoot);
  const binaryRoot = join(root, "bin");
  const extension = windows ? ".exe" : "";
  const resources = [];

  for (const sidecar of REQUIRED_SIDECARS) {
    const name = `${sidecar}${extension}`;
    const path = join(binaryRoot, name);
    const metadata = await stat(path);
    if (!metadata.isFile()) throw new Error(`${name} is not a regular file`);
    resources.push({ name: basename(path), sha256: await sha256(path) });
  }

  const manifest = { version: 1, resources };
  const temporary = join(root, ".manifest.json.tmp");
  const destination = join(root, "manifest.json");
  await mkdir(root, { recursive: true });
  await writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, destination);
  return manifest;
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const runtimeRoot = process.argv[2];
  if (!runtimeRoot) {
    console.error(
      "Usage: generate-runtime-manifest.mjs <runtime-root> [--windows]",
    );
    process.exitCode = 2;
  } else {
    await generateRuntimeManifest(runtimeRoot, {
      windows: process.argv.includes("--windows"),
    });
  }
}
