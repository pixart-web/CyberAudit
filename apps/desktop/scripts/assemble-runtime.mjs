import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  access,
  chmod,
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { generateRuntimeManifest } from "./generate-runtime-manifest.mjs";

const COMPONENTS = {
  postgresql: {
    licenseNames: ["COPYRIGHT", "LICENSE"],
    versionPattern: /^16(?:\.\d+){0,2}$/,
  },
  valkey: {
    licenseNames: ["COPYING", "LICENSE"],
    versionPattern: /^(?:7|8|9)(?:\.\d+){1,2}$/,
  },
};

const HOST_SIDECARS = [
  "cyberaudit-postgres",
  "cyberaudit-valkey",
  "cyberaudit-web",
];
const PYTHON_SIDECARS = ["cyberaudit-api", "cyberaudit-worker"];

async function requireRegularFile(path, label) {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`${label} must be a regular file`);
    }
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file`);
  }
}

async function requireDirectory(path, label) {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`${label} must be a regular directory`);
    }
    throw error;
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular directory`);
  }
}

async function requireAbsent(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${label} already exists`);
}

function portablePath(path) {
  return path.split(sep).join("/");
}

async function validateContainedLinks(root, directory = root) {
  const canonicalRoot = await realpath(root);
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(directory, entry.name);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      const target = await realpath(path);
      const targetRelative = relative(canonicalRoot, target);
      if (
        targetRelative === "" ||
        (!targetRelative.startsWith(`..${sep}`) && targetRelative !== "..")
      ) {
        continue;
      }
      throw new Error(
        `runtime source link escapes its distribution: ${portablePath(relative(root, path))}`,
      );
    }
    if (metadata.isDirectory()) await validateContainedLinks(root, path);
    else if (!metadata.isFile()) {
      throw new Error(
        `runtime source contains a special file: ${portablePath(relative(root, path))}`,
      );
    }
  }
}

async function rejectOutputLinks(root, directory = root) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(directory, entry.name);
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(
        `assembled runtime cannot contain symbolic links: ${portablePath(relative(root, path))}`,
      );
    }
    if (metadata.isDirectory()) await rejectOutputLinks(root, path);
  }
}

async function loadProvenance(path, component, target) {
  await requireRegularFile(path, `${component} provenance`);
  const parsed = JSON.parse(await readFile(path, "utf8"));
  const expectedKeys = [
    "archive_sha256",
    "component",
    "license",
    "source_url",
    "target",
    "version",
  ];
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join("\0") !== expectedKeys.join("\0")
  ) {
    throw new Error(`${component} provenance has an invalid schema`);
  }
  if (parsed.component !== component || parsed.target !== target) {
    throw new Error(`${component} provenance does not match this build target`);
  }
  if (!COMPONENTS[component].versionPattern.test(parsed.version)) {
    throw new Error(`${component} provenance has an unsupported version`);
  }
  if (!/^https:\/\/[^\s]+$/.test(parsed.source_url)) {
    throw new Error(`${component} provenance requires an HTTPS source URL`);
  }
  if (!/^[a-f0-9]{64}$/.test(parsed.archive_sha256)) {
    throw new Error(
      `${component} provenance requires a SHA-256 archive digest`,
    );
  }
  if (typeof parsed.license !== "string" || parsed.license.length < 2) {
    throw new Error(`${component} provenance requires a license identifier`);
  }
  return parsed;
}

async function findLicense(distributionRoot, component) {
  for (const name of COMPONENTS[component].licenseNames) {
    const candidate = join(distributionRoot, name);
    try {
      const metadata = await lstat(candidate);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error(`${component} license must be a regular file`);
      }
      return candidate;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  throw new Error(`${component} distribution license is missing`);
}

function executableName(name, windows) {
  return windows ? `${name}.exe` : name;
}

async function validateDistribution({
  component,
  root,
  target,
  provenancePath,
  windows,
}) {
  await requireDirectory(root, `${component} distribution`);
  await validateContainedLinks(root);
  const binary = join(
    root,
    "bin",
    executableName(
      component === "postgresql" ? "postgres" : "valkey-server",
      windows,
    ),
  );
  await requireRegularFile(binary, `${component} server`);
  const license = await findLicense(root, component);
  const provenance = await loadProvenance(provenancePath, component, target);
  return { binary, license, provenance };
}

function smokeDistribution(component, binary, root, expectedVersion) {
  const environment =
    process.platform === "win32"
      ? {
          SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
          WINDIR: process.env.WINDIR ?? "C:\\Windows",
          PATH: join(root, "bin"),
        }
      : {
          PATH: join(root, "bin"),
          LD_LIBRARY_PATH: join(root, "lib"),
          DYLD_LIBRARY_PATH: join(root, "lib"),
        };
  const result = spawnSync(binary, ["--version"], {
    cwd: root,
    encoding: "utf8",
    env: environment,
    shell: false,
    timeout: 10_000,
    windowsHide: true,
  });
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (result.status !== 0 || !output.includes(expectedVersion)) {
    throw new Error(
      `${component} distribution failed its native version smoke test`,
    );
  }
}

async function copySidecars(sourceRoot, destination, names, windows) {
  for (const name of names) {
    const filename = executableName(name, windows);
    const source = join(sourceRoot, filename);
    await requireRegularFile(source, filename);
    await cp(source, join(destination, filename), {
      dereference: true,
      errorOnExist: true,
      force: false,
    });
    if (!windows) await chmod(join(destination, filename), 0o700);
  }
}

export async function assembleRuntime({
  runtimeRoot,
  webRuntimeRoot,
  runtimeHostRoot,
  pythonSidecarRoot,
  postgresqlDistributionRoot,
  postgresqlProvenance,
  valkeyDistributionRoot,
  valkeyProvenance,
  target,
  windows = false,
  smokeTestDistributions = false,
}) {
  if (!/^[a-z0-9]+-[a-z0-9_]+$/.test(target)) {
    throw new Error("runtime target must use the platform-architecture format");
  }
  const destination = resolve(runtimeRoot);
  const parent = dirname(destination);
  const staging = join(
    parent,
    `.${basename(destination)}.${randomBytes(8).toString("hex")}.tmp`,
  );
  await requireAbsent(destination, "runtime destination");
  await requireAbsent(staging, "runtime staging directory");

  await requireDirectory(webRuntimeRoot, "assembled web runtime");
  await validateContainedLinks(webRuntimeRoot);
  await requireRegularFile(
    join(webRuntimeRoot, "web-runtime.json"),
    "web runtime metadata",
  );
  await requireDirectory(runtimeHostRoot, "runtime host output");
  await requireDirectory(pythonSidecarRoot, "Python sidecar output");
  const postgres = await validateDistribution({
    component: "postgresql",
    root: postgresqlDistributionRoot,
    target,
    provenancePath: postgresqlProvenance,
    windows,
  });
  const valkey = await validateDistribution({
    component: "valkey",
    root: valkeyDistributionRoot,
    target,
    provenancePath: valkeyProvenance,
    windows,
  });
  if (smokeTestDistributions) {
    smokeDistribution(
      "postgresql",
      postgres.binary,
      postgresqlDistributionRoot,
      `PostgreSQL) ${postgres.provenance.version}`,
    );
    smokeDistribution(
      "valkey",
      valkey.binary,
      valkeyDistributionRoot,
      `v=${valkey.provenance.version}`,
    );
  }

  try {
    await mkdir(parent, { recursive: true, mode: 0o700 });
    await mkdir(staging, { recursive: false, mode: 0o700 });
    await cp(webRuntimeRoot, staging, {
      recursive: true,
      dereference: true,
      errorOnExist: false,
      force: false,
    });
    const bin = join(staging, "bin");
    await mkdir(bin, { recursive: true, mode: 0o700 });
    await copySidecars(runtimeHostRoot, bin, HOST_SIDECARS, windows);
    await copySidecars(pythonSidecarRoot, bin, PYTHON_SIDECARS, windows);

    const tools = join(staging, "tools");
    await mkdir(tools, { recursive: true, mode: 0o700 });
    await cp(postgresqlDistributionRoot, join(tools, "postgresql"), {
      recursive: true,
      dereference: true,
      errorOnExist: true,
      force: false,
    });
    await cp(valkeyDistributionRoot, join(tools, "valkey"), {
      recursive: true,
      dereference: true,
      errorOnExist: true,
      force: false,
    });

    const licenses = join(staging, "licenses");
    const provenance = join(staging, "provenance");
    await mkdir(licenses, { recursive: true, mode: 0o700 });
    await mkdir(provenance, { recursive: true, mode: 0o700 });
    await cp(postgres.license, join(licenses, "postgresql-LICENSE"), {
      errorOnExist: true,
      force: false,
    });
    await cp(valkey.license, join(licenses, "valkey-LICENSE"), {
      errorOnExist: true,
      force: false,
    });
    await writeFile(
      join(provenance, "postgresql.json"),
      `${JSON.stringify(postgres.provenance, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600, flag: "wx" },
    );
    await writeFile(
      join(provenance, "valkey.json"),
      `${JSON.stringify(valkey.provenance, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600, flag: "wx" },
    );
    await writeFile(
      join(staging, "runtime.json"),
      `${JSON.stringify(
        {
          version: 1,
          target,
          components: {
            postgresql: postgres.provenance.version,
            valkey: valkey.provenance.version,
          },
        },
        null,
        2,
      )}\n`,
      { encoding: "utf8", mode: 0o600, flag: "wx" },
    );
    await rejectOutputLinks(staging);
    const manifest = await generateRuntimeManifest(staging, { windows });
    await access(join(staging, "manifest.json"), constants.R_OK);
    await rename(staging, destination);
    return manifest;
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const [
    runtimeRoot,
    webRuntimeRoot,
    runtimeHostRoot,
    pythonSidecarRoot,
    postgresqlDistributionRoot,
    postgresqlProvenance,
    valkeyDistributionRoot,
    valkeyProvenance,
    target,
  ] = process.argv.slice(2).filter((argument) => !argument.startsWith("--"));
  if (
    !runtimeRoot ||
    !webRuntimeRoot ||
    !runtimeHostRoot ||
    !pythonSidecarRoot ||
    !postgresqlDistributionRoot ||
    !postgresqlProvenance ||
    !valkeyDistributionRoot ||
    !valkeyProvenance ||
    !target
  ) {
    console.error(
      "Usage: assemble-runtime.mjs <runtime-root> <web-runtime-root> <runtime-host-root> <python-sidecar-root> <postgresql-root> <postgresql-provenance.json> <valkey-root> <valkey-provenance.json> <target> [--windows] [--smoke]",
    );
    process.exitCode = 2;
  } else {
    await assembleRuntime({
      runtimeRoot,
      webRuntimeRoot,
      runtimeHostRoot,
      pythonSidecarRoot,
      postgresqlDistributionRoot,
      postgresqlProvenance,
      valkeyDistributionRoot,
      valkeyProvenance,
      target,
      windows: process.argv.includes("--windows"),
      smokeTestDistributions: process.argv.includes("--smoke"),
    });
  }
}
