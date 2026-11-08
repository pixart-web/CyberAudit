import assert from "node:assert/strict";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assembleWebRuntime } from "./assemble-web-runtime.mjs";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "cyberaudit-web-runtime-"));
  const standalone = join(root, "standalone");
  const staticRoot = join(root, "static");
  const publicRoot = join(root, "public");
  const nodeDistributionRoot = join(root, "node-distribution");
  const nextLicense = join(root, "next-license");
  await mkdir(join(standalone, "apps/web/.next"), { recursive: true });
  await mkdir(join(standalone, "shared"), { recursive: true });
  await mkdir(staticRoot, { recursive: true });
  await mkdir(publicRoot, { recursive: true });
  await mkdir(join(nodeDistributionRoot, "bin"), { recursive: true });
  await writeFile(join(standalone, "apps/web/server.js"), "server");
  await writeFile(
    join(standalone, "apps/web/.next/BUILD_ID"),
    "desktopBuild_1234\n",
  );
  await writeFile(join(standalone, "shared/module.js"), "module");
  await symlink(
    join(standalone, "shared/module.js"),
    join(standalone, "apps/web/module.js"),
  );
  await writeFile(join(staticRoot, "chunk.js"), "chunk");
  await writeFile(join(publicRoot, "asset.txt"), "asset");
  await writeFile(join(nodeDistributionRoot, "bin", "node"), "node");
  await writeFile(join(nodeDistributionRoot, "LICENSE"), "Node license");
  await writeFile(nextLicense, "Next license");
  return {
    root,
    runtime: join(root, "runtime"),
    standalone,
    staticRoot,
    publicRoot,
    nodeDistributionRoot,
    nextLicense,
  };
}

test("assembles regular standalone resources, assets, runtime and licenses", async () => {
  const item = await fixture();
  try {
    const metadata = await assembleWebRuntime({
      runtimeRoot: item.runtime,
      standaloneRoot: item.standalone,
      staticRoot: item.staticRoot,
      publicRoot: item.publicRoot,
      nodeDistributionRoot: item.nodeDistributionRoot,
      nextLicense: item.nextLicense,
      windows: false,
    });
    assert.equal(metadata.build_id, "desktopBuild_1234");
    assert.equal(
      await readFile(join(item.runtime, "web/apps/web/module.js"), "utf8"),
      "module",
    );
    assert.equal(
      (
        await lstat(join(item.runtime, "web/apps/web/module.js"))
      ).isSymbolicLink(),
      false,
    );
    assert.equal(
      await readFile(
        join(item.runtime, "web/apps/web/.next/static/chunk.js"),
        "utf8",
      ),
      "chunk",
    );
    assert.equal(
      await readFile(join(item.runtime, "licenses/node-LICENSE"), "utf8"),
      "Node license",
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test("refuses to overwrite an existing assembled web runtime", async () => {
  const item = await fixture();
  try {
    await mkdir(join(item.runtime, "web"), { recursive: true });
    await assert.rejects(
      assembleWebRuntime({
        runtimeRoot: item.runtime,
        standaloneRoot: item.standalone,
        staticRoot: item.staticRoot,
        publicRoot: item.publicRoot,
        nodeDistributionRoot: item.nodeDistributionRoot,
        nextLicense: item.nextLicense,
      }),
      /refusing to overwrite/,
    );
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});

test("rejects an invalid Node distribution before creating runtime files", async () => {
  const item = await fixture();
  try {
    await assert.rejects(
      assembleWebRuntime({
        runtimeRoot: item.runtime,
        standaloneRoot: item.standalone,
        staticRoot: item.staticRoot,
        publicRoot: item.publicRoot,
        nodeDistributionRoot: item.nodeDistributionRoot,
        nextLicense: item.nextLicense,
        smokeTestNode: true,
      }),
      /not a portable v22\.17\.1 distribution/,
    );
    await assert.rejects(lstat(item.runtime), { code: "ENOENT" });
  } finally {
    await rm(item.root, { recursive: true, force: true });
  }
});
