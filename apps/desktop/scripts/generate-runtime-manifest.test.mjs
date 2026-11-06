import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  generateRuntimeManifest,
  REQUIRED_SIDECARS,
} from "./generate-runtime-manifest.mjs";

test("generates a deterministic manifest for the fixed sidecar allowlist", async () => {
  const root = await mkdtemp(join(tmpdir(), "cyberaudit-runtime-"));
  const bin = join(root, "bin");
  try {
    await mkdir(bin, { recursive: true });
    await Promise.all(
      REQUIRED_SIDECARS.map((name) => writeFile(join(bin, name), name)),
    );
    const manifest = await generateRuntimeManifest(root);
    const stored = JSON.parse(
      await readFile(join(root, "manifest.json"), "utf8"),
    );

    assert.deepEqual(stored, manifest);
    assert.deepEqual(
      manifest.resources.map(({ name }) => name),
      REQUIRED_SIDECARS,
    );
    assert.ok(
      manifest.resources.every(({ sha256 }) => /^[a-f0-9]{64}$/.test(sha256)),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("fails closed when a required sidecar is absent", async () => {
  const root = await mkdtemp(join(tmpdir(), "cyberaudit-runtime-missing-"));
  try {
    await assert.rejects(generateRuntimeManifest(root), /cyberaudit-postgres/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
