import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  generateRuntimeManifest,
  REQUIRED_SIDECARS,
} from "./generate-runtime-manifest.mjs";
import { stageRuntime, verifyRuntime } from "./stage-runtime.mjs";

async function fixture(root) {
  await mkdir(join(root, "bin"), { recursive: true });
  for (const name of REQUIRED_SIDECARS)
    await writeFile(join(root, "bin", name), name);
  await generateRuntimeManifest(root);
}

test("stages only a complete verified runtime", async () => {
  const root = await mkdtemp(join(tmpdir(), "cyberaudit-stage-"));
  const source = join(root, "source");
  const destination = join(root, "resources", "runtime");
  try {
    await fixture(source);
    await stageRuntime(source, destination);
    await verifyRuntime(destination);
    assert.equal(
      await readFile(join(destination, "bin", "cyberaudit-api"), "utf8"),
      "cyberaudit-api",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a runtime changed after manifest generation", async () => {
  const root = await mkdtemp(join(tmpdir(), "cyberaudit-stage-tampered-"));
  try {
    await fixture(root);
    await writeFile(join(root, "bin", "cyberaudit-api"), "tampered");
    await assert.rejects(verifyRuntime(root), /integrity verification/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
