import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import test from "node:test";

import { writeNativeBuildReport } from "./write-native-build-report.mjs";

test("records package size and SHA-256 without claiming production readiness", async () => {
  const root = await mkdtemp(join(os.tmpdir(), "cyberaudit-native-report-"));
  const bundle = join(root, "bundle");
  await mkdir(join(bundle, "dmg"), { recursive: true });
  await writeFile(join(bundle, "dmg", "CyberAudit.dmg"), "fixture package");
  const output = join(bundle, "native-build-report.json");

  const report = await writeNativeBuildReport({
    output,
    platform: "macos",
    architecture: "arm64",
    signingStatus: "ad-hoc",
    notarizationStatus: "not-notarized",
    bundleRoot: bundle,
  });

  assert.equal(report.release_status, "NATIVE_BUILD_READY");
  assert.equal(report.signing_status, "ad-hoc");
  assert.equal(report.packages.length, 1);
  assert.match(report.packages[0].sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(JSON.parse(await readFile(output, "utf8")), report);
  await rm(root, { recursive: true, force: true });
});
