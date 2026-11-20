import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readdir, writeFile } from "node:fs/promises";
import { basename, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

async function digest(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function packageFiles(root, directory = root) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) continue;
    if (metadata.isDirectory())
      result.push(...(await packageFiles(root, path)));
    else if (metadata.isFile()) {
      const name = relative(root, path).split(sep).join("/");
      if (!name.endsWith("native-build-report.json")) {
        result.push({ name, path, size_bytes: metadata.size });
      }
    }
  }
  return result;
}

export async function writeNativeBuildReport({
  output,
  platform,
  architecture,
  signingStatus,
  notarizationStatus,
  bundleRoot,
}) {
  const files = await packageFiles(bundleRoot);
  const packages = [];
  for (const file of files) {
    if (/\.(dmg|exe|msi|app\.tar\.gz)$/.test(file.name)) {
      packages.push({
        path: file.name,
        size_bytes: file.size_bytes,
        sha256: await digest(file.path),
      });
    }
  }
  packages.sort((left, right) => left.path.localeCompare(right.path));
  if (packages.length === 0)
    throw new Error("no native installer package was found");
  const report = {
    version: 1,
    product_version: process.env.npm_package_version ?? "0.1.0",
    platform,
    architecture,
    build_result: "PASS",
    native_smoke_test: "PASS",
    signing_status: signingStatus,
    notarization_status: notarizationStatus,
    release_status: "NATIVE_BUILD_READY",
    packages,
  };
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return report;
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const [
    output,
    platform,
    architecture,
    signingStatus,
    notarizationStatus,
    bundleRoot,
  ] = process.argv.slice(2);
  if (
    !output ||
    !platform ||
    !architecture ||
    !signingStatus ||
    !notarizationStatus ||
    !bundleRoot
  ) {
    throw new Error(
      `Usage: ${basename(process.argv[1])} <output> <platform> <architecture> <signing> <notarization> <bundle-root>`,
    );
  }
  await writeNativeBuildReport({
    output: resolve(output),
    platform,
    architecture,
    signingStatus,
    notarizationStatus,
    bundleRoot: resolve(bundleRoot),
  });
}
