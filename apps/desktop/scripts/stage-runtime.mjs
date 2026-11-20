import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { REQUIRED_SIDECARS } from "./generate-runtime-manifest.mjs";

async function digest(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function files(root, directory = root) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const metadata = await lstat(path);
    const name = relative(root, path).split(sep).join("/");
    if (metadata.isSymbolicLink())
      throw new Error(`runtime staging rejects symbolic links: ${name}`);
    if (metadata.isDirectory()) result.push(...(await files(root, path)));
    else if (metadata.isFile() && name !== "manifest.json")
      result.push({ name, path });
    else if (!metadata.isFile())
      throw new Error(`runtime staging rejects special files: ${name}`);
  }
  return result;
}

export async function verifyRuntime(root) {
  const manifestPath = join(root, "manifest.json");
  const metadata = await lstat(manifestPath);
  if (!metadata.isFile() || metadata.isSymbolicLink())
    throw new Error("runtime manifest must be a regular file");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (manifest?.version !== 2 || !Array.isArray(manifest.resources))
    throw new Error("runtime manifest schema is invalid");
  const expected = new Map();
  for (const resource of manifest.resources) {
    if (
      !resource ||
      Object.keys(resource).sort().join(",") !== "path,sha256" ||
      !/^[a-f0-9]{64}$/.test(resource.sha256) ||
      !/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\\]+$/.test(resource.path) ||
      expected.has(resource.path)
    )
      throw new Error("runtime manifest contains an invalid resource");
    expected.set(resource.path, resource.sha256);
  }
  const actual = await files(root);
  if (actual.length !== expected.size)
    throw new Error("runtime manifest does not cover the complete tree");
  for (const file of actual) {
    if ((await digest(file.path)) !== expected.get(file.name))
      throw new Error(`runtime resource failed integrity verification: ${file.name}`);
  }
  const names = new Set(actual.map(({ name }) => name));
  const unix = REQUIRED_SIDECARS.every((name) => names.has(`bin/${name}`));
  const windows = REQUIRED_SIDECARS.every((name) => names.has(`bin/${name}.exe`));
  if (!unix && !windows) throw new Error("runtime sidecar set is incomplete");
}

export async function stageRuntime(source, destination) {
  const input = resolve(source);
  const output = resolve(destination);
  if (input === output || output.startsWith(`${input}${sep}`))
    throw new Error("runtime staging destination must be separate from its source");
  await verifyRuntime(input);
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  const nonce = randomBytes(8).toString("hex");
  const staging = `${output}.staging-${nonce}`;
  const previous = `${output}.previous-${nonce}`;
  await cp(input, staging, { recursive: true, dereference: false, errorOnExist: true });
  try {
    await verifyRuntime(staging);
    let hadPrevious = false;
    try {
      await rename(output, previous);
      hadPrevious = true;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    try {
      await rename(staging, output);
    } catch (error) {
      if (hadPrevious) await rename(previous, output);
      throw error;
    }
    if (hadPrevious) await rm(previous, { recursive: true, force: true });
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const repositoryRoot = resolve(desktopRoot, "../..");
  const source = process.env.CYBERAUDIT_DESKTOP_RUNTIME_DIR;
  if (!source) throw new Error("CYBERAUDIT_DESKTOP_RUNTIME_DIR is required");
  await stageRuntime(
    resolve(repositoryRoot, source),
    join(desktopRoot, "src-tauri", "resources", "runtime"),
  );
}
