import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  lstat,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import test from "node:test";
import { assembleRuntime } from "./assemble-runtime.mjs";

const DIGEST = "a".repeat(64);

async function writeProvenance(path, component, target, version) {
  await writeFile(
    path,
    `${JSON.stringify(
      {
        archive_sha256: DIGEST,
        component,
        license: component === "postgresql" ? "PostgreSQL" : "BSD-3-Clause",
        source_url: `https://downloads.example.invalid/${component}.tar.gz`,
        target,
        version,
      },
      null,
      2,
    )}\n`,
  );
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "cyberaudit-complete-runtime-"));
  const paths = {
    root,
    destination: join(root, "output", "runtime"),
    web: join(root, "web"),
    hosts: join(root, "hosts"),
    python: join(root, "python"),
    postgresql: join(root, "postgresql"),
    valkey: join(root, "valkey"),
    postgresqlProvenance: join(root, "postgresql.json"),
    valkeyProvenance: join(root, "valkey.json"),
  };
  await mkdir(join(paths.web, "web", "apps", "web"), { recursive: true });
  await mkdir(join(paths.web, "tools", "node", "bin"), { recursive: true });
  await writeFile(join(paths.web, "web-runtime.json"), "{}\n");
  await writeFile(join(paths.web, "web", "apps", "web", "server.js"), "");
  await writeFile(join(paths.web, "tools", "node", "bin", "node"), "node");
  await mkdir(paths.hosts, { recursive: true });
  await mkdir(paths.python, { recursive: true });
  await Promise.all(
    ["cyberaudit-postgres", "cyberaudit-valkey", "cyberaudit-web"].map((name) =>
      writeFile(join(paths.hosts, name), name),
    ),
  );
  await Promise.all(
    ["cyberaudit-api", "cyberaudit-worker"].map((name) =>
      writeFile(join(paths.python, name), name),
    ),
  );
  await mkdir(join(paths.postgresql, "bin"), { recursive: true });
  await mkdir(join(paths.postgresql, "lib"), { recursive: true });
  await writeFile(join(paths.postgresql, "bin", "postgres"), "postgres");
  await writeFile(join(paths.postgresql, "lib", "libpq.fixture"), "library");
  await writeFile(join(paths.postgresql, "COPYRIGHT"), "PostgreSQL license");
  await mkdir(join(paths.valkey, "bin"), { recursive: true });
  await writeFile(join(paths.valkey, "bin", "valkey-server"), "valkey");
  await writeFile(join(paths.valkey, "COPYING"), "Valkey license");
  await writeProvenance(
    paths.postgresqlProvenance,
    "postgresql",
    "macos-arm64",
    "16.14",
  );
  await writeProvenance(
    paths.valkeyProvenance,
    "valkey",
    "macos-arm64",
    "8.1.5",
  );
  return paths;
}

function options(paths) {
  return {
    runtimeRoot: paths.destination,
    webRuntimeRoot: paths.web,
    runtimeHostRoot: paths.hosts,
    pythonSidecarRoot: paths.python,
    postgresqlDistributionRoot: paths.postgresql,
    postgresqlProvenance: paths.postgresqlProvenance,
    valkeyDistributionRoot: paths.valkey,
    valkeyProvenance: paths.valkeyProvenance,
    target: "macos-arm64",
  };
}

test("atomically assembles every runtime component and its provenance", async () => {
  const paths = await fixture();
  try {
    const manifest = await assembleRuntime(options(paths));
    const resources = new Set(manifest.resources.map(({ path }) => path));
    for (const required of [
      "bin/cyberaudit-api",
      "bin/cyberaudit-postgres",
      "bin/cyberaudit-valkey",
      "bin/cyberaudit-web",
      "bin/cyberaudit-worker",
      "licenses/postgresql-LICENSE",
      "licenses/valkey-LICENSE",
      "provenance/postgresql.json",
      "provenance/valkey.json",
      "tools/node/bin/node",
      "tools/postgresql/bin/postgres",
      "tools/valkey/bin/valkey-server",
      "web/apps/web/server.js",
    ]) {
      assert.ok(resources.has(required), `manifest should include ${required}`);
    }
    const metadata = JSON.parse(
      await readFile(join(paths.destination, "runtime.json"), "utf8"),
    );
    assert.deepEqual(metadata, {
      version: 1,
      target: "macos-arm64",
      components: { postgresql: "16.14", valkey: "8.1.5" },
    });
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("assembles a large runtime without opening the complete tree concurrently", async () => {
  const paths = await fixture();
  try {
    const largeDirectory = join(paths.web, "web", "apps", "web", "chunks");
    await mkdir(largeDirectory, { recursive: true });
    for (let index = 0; index < 1_500; index += 1) {
      await writeFile(join(largeDirectory, `chunk-${index}.js`), `${index}\n`);
    }

    const manifest = await assembleRuntime(options(paths));

    assert.equal(
      manifest.resources.filter(({ path }) => path.includes("/chunks/chunk-"))
        .length,
      1_500,
    );
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("normalizes relative source paths before complete assembly", async () => {
  const paths = await fixture();
  try {
    const supplied = options(paths);
    for (const key of [
      "runtimeRoot",
      "webRuntimeRoot",
      "runtimeHostRoot",
      "pythonSidecarRoot",
      "postgresqlDistributionRoot",
      "postgresqlProvenance",
      "valkeyDistributionRoot",
      "valkeyProvenance",
    ]) {
      supplied[key] = relative(process.cwd(), supplied[key]);
    }
    const manifest = await assembleRuntime(supplied);
    assert.ok(manifest.resources.length > 0);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("refuses to overwrite an existing complete runtime", async () => {
  const paths = await fixture();
  try {
    await mkdir(paths.destination, { recursive: true });
    await assert.rejects(
      assembleRuntime(options(paths)),
      /runtime destination already exists/,
    );
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("rejects provenance that does not match the target", async () => {
  const paths = await fixture();
  try {
    await writeProvenance(
      paths.valkeyProvenance,
      "valkey",
      "windows-x64",
      "8.1.5",
    );
    await assert.rejects(
      assembleRuntime(options(paths)),
      /does not match this build target/,
    );
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("rejects a PostgreSQL distribution outside major version 16", async () => {
  const paths = await fixture();
  try {
    await writeProvenance(
      paths.postgresqlProvenance,
      "postgresql",
      "macos-arm64",
      "17.1",
    );
    await assert.rejects(
      assembleRuntime(options(paths)),
      /unsupported version/,
    );
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("rejects unrecognized provenance fields", async () => {
  const paths = await fixture();
  try {
    const provenance = JSON.parse(
      await readFile(paths.valkeyProvenance, "utf8"),
    );
    provenance.release_channel = "untrusted";
    await writeFile(paths.valkeyProvenance, `${JSON.stringify(provenance)}\n`);
    await assert.rejects(assembleRuntime(options(paths)), /invalid schema/);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("rejects distribution links that escape the supplied root", async () => {
  const paths = await fixture();
  try {
    await symlink(
      join(paths.root, "outside"),
      join(paths.valkey, "external-library"),
    );
    await writeFile(join(paths.root, "outside"), "outside");
    await assert.rejects(
      assembleRuntime(options(paths)),
      /source link escapes its distribution/,
    );
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});

test("fails closed when a required sidecar is not a regular file", async () => {
  const paths = await fixture();
  try {
    await rm(join(paths.python, "cyberaudit-worker"));
    await assert.rejects(
      assembleRuntime(options(paths)),
      /cyberaudit-worker must be a regular file/,
    );
    await assert.rejects(lstat(paths.destination), /ENOENT/);
  } finally {
    await rm(paths.root, { recursive: true, force: true });
  }
});
