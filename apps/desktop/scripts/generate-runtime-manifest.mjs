import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdir, readdir, rename, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
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

async function runtimeFiles(root, directory = root) {
  const files = [];
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    const path = join(directory, entry.name);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(
        `runtime resources cannot be symbolic links: ${entry.name}`,
      );
    }
    if (metadata.isDirectory()) {
      files.push(...(await runtimeFiles(root, path)));
      continue;
    }
    if (!metadata.isFile()) {
      throw new Error(`runtime resource is not a regular file: ${entry.name}`);
    }
    const resourcePath = relative(root, path).split(sep).join("/");
    if (
      resourcePath === "manifest.json" ||
      resourcePath === ".manifest.json.tmp"
    ) {
      continue;
    }
    files.push({ path: resourcePath, absolutePath: path });
  }
  return files;
}

export async function generateRuntimeManifest(
  runtimeRoot,
  { windows = false } = {},
) {
  const root = resolve(runtimeRoot);
  const binaryRoot = join(root, "bin");
  const extension = windows ? ".exe" : "";

  for (const sidecar of REQUIRED_SIDECARS) {
    const name = `${sidecar}${extension}`;
    const path = join(binaryRoot, name);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`${name} cannot be a symbolic link`);
    }
    if (!metadata.isFile()) throw new Error(`${name} is not a regular file`);
  }

  const files = await runtimeFiles(root);
  files.sort((left, right) => left.path.localeCompare(right.path, "en"));
  const resources = await Promise.all(
    files.map(async ({ path, absolutePath }) => ({
      path,
      sha256: await sha256(absolutePath),
    })),
  );
  const manifest = { version: 2, resources };
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
