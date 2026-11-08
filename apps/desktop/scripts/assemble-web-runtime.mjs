import {
  chmod,
  cp,
  copyFile,
  lstat,
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED_NODE_VERSION = "v22.17.1";

async function requireRegularFile(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file`);
  }
}

async function requireDirectory(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular directory`);
  }
}

export async function assembleWebRuntime({
  runtimeRoot,
  standaloneRoot,
  staticRoot,
  publicRoot,
  nodeDistributionRoot,
  nextLicense,
  windows = false,
  smokeTestNode = false,
}) {
  const root = resolve(runtimeRoot);
  const webDestination = join(root, "web");
  const nodeDestinationRoot = join(root, "tools", "node");
  const nodeDestination = join(
    nodeDestinationRoot,
    "bin",
    windows ? "node.exe" : "node",
  );
  const nodeExecutable = join(
    nodeDistributionRoot,
    ...(windows ? ["node.exe"] : ["bin", "node"]),
  );
  const nodeLicense = join(nodeDistributionRoot, "LICENSE");
  await requireDirectory(standaloneRoot, "Next standalone output");
  await requireDirectory(staticRoot, "Next static output");
  await requireDirectory(publicRoot, "Next public assets");
  await requireDirectory(nodeDistributionRoot, "Node distribution");
  await requireRegularFile(nodeExecutable, "Node runtime");
  await requireRegularFile(nodeLicense, "Node license");
  await requireRegularFile(nextLicense, "Next license");
  if (smokeTestNode) validateNode(nodeExecutable, root, windows);

  for (const destination of [webDestination, nodeDestinationRoot]) {
    try {
      await lstat(destination);
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    throw new Error(
      `refusing to overwrite runtime destination: ${basename(destination)}`,
    );
  }

  await mkdir(dirname(nodeDestinationRoot), { recursive: true, mode: 0o700 });
  await mkdir(join(root, "licenses"), { recursive: true, mode: 0o700 });
  await cp(standaloneRoot, webDestination, {
    recursive: true,
    dereference: true,
    errorOnExist: true,
    force: false,
  });
  const applicationRoot = join(webDestination, "apps", "web");
  await mkdir(join(applicationRoot, ".next"), { recursive: true, mode: 0o700 });
  await cp(staticRoot, join(applicationRoot, ".next", "static"), {
    recursive: true,
    dereference: true,
    errorOnExist: true,
    force: false,
  });
  await cp(publicRoot, join(applicationRoot, "public"), {
    recursive: true,
    dereference: true,
    errorOnExist: true,
    force: false,
  });
  await cp(nodeDistributionRoot, nodeDestinationRoot, {
    recursive: true,
    dereference: true,
    errorOnExist: true,
    force: false,
  });
  if (windows) {
    await mkdir(dirname(nodeDestination), { recursive: true, mode: 0o700 });
    await copyFile(nodeExecutable, nodeDestination);
  }
  if (!windows) await chmod(nodeDestination, 0o700);
  if (smokeTestNode) validateNode(nodeDestination, root, windows);
  await copyFile(nodeLicense, join(root, "licenses", "node-LICENSE"));
  await copyFile(nextLicense, join(root, "licenses", "next-LICENSE"));
  await requireRegularFile(
    join(applicationRoot, "server.js"),
    "Next server entrypoint",
  );

  const buildId = (
    await readFile(join(applicationRoot, ".next", "BUILD_ID"), "utf8")
  ).trim();
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(buildId)) {
    throw new Error("Next build identifier is invalid");
  }
  const metadata = {
    version: 1,
    build_id: buildId,
    node_filename: basename(nodeDestination),
  };
  await writeFile(
    join(root, "web-runtime.json"),
    `${JSON.stringify(metadata, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600, flag: "wx" },
  );
  return metadata;
}

function validateNode(nodeExecutable, runtimeRoot, windows) {
  const environment = windows
    ? {
        SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
        WINDIR: process.env.WINDIR ?? "C:\\Windows",
      }
    : {};
  const result = spawnSync(nodeExecutable, ["--version"], {
    cwd: runtimeRoot,
    encoding: "utf8",
    env: environment,
    shell: false,
    timeout: 10_000,
    windowsHide: true,
  });
  if (result.status !== 0 || result.stdout.trim() !== EXPECTED_NODE_VERSION) {
    throw new Error(
      `Node runtime is not a portable ${EXPECTED_NODE_VERSION} distribution`,
    );
  }
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const [runtimeRoot, suppliedNodeRoot] = process.argv.slice(2);
  if (!runtimeRoot) {
    console.error(
      "Usage: assemble-web-runtime.mjs <runtime-root> [node-distribution-root] [--windows]",
    );
    process.exitCode = 2;
  } else {
    const repositoryRoot = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../../..",
    );
    const windows = process.argv.includes("--windows");
    const inferredNodeRoot = windows
      ? dirname(process.execPath)
      : resolve(dirname(process.execPath), "..");
    const nodeDistributionRoot =
      suppliedNodeRoot && !suppliedNodeRoot.startsWith("--")
        ? resolve(suppliedNodeRoot)
        : inferredNodeRoot;
    await assembleWebRuntime({
      runtimeRoot,
      standaloneRoot: join(repositoryRoot, "apps/web/.next/standalone"),
      staticRoot: join(repositoryRoot, "apps/web/.next/static"),
      publicRoot: join(repositoryRoot, "apps/web/public"),
      nodeDistributionRoot,
      nextLicense: join(
        repositoryRoot,
        "apps/web/node_modules/next/license.md",
      ),
      windows,
      smokeTestNode: true,
    });
  }
}
