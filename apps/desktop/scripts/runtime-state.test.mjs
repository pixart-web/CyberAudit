import assert from "node:assert/strict";
import test from "node:test";
import {
  runtimeFailurePresentation,
  runtimePresentation,
} from "../ui/runtime-state.mjs";

test("shows verified resources as progress without claiming service readiness", () => {
  const result = runtimePresentation({
    ready: false,
    state: "resources_verified",
    missing_resources: [],
    invalid_resources: [],
  });
  assert.equal(result.kind, "progress");
  assert.equal(result.retry, false);
  assert.match(result.message, /supervisor pode iniciar/);
});

test("shows resource verification and service readiness as progress", () => {
  const verifying = runtimePresentation({
    ready: false,
    state: "verifying_resources",
  });
  const ready = runtimePresentation({ ready: true, state: "ready" });

  assert.equal(verifying.kind, "progress");
  assert.equal(verifying.retry, false);
  assert.equal(ready.kind, "progress");
  assert.equal(ready.retry, false);
});

test("shows a sanitized recoverable error for missing or unknown resources", () => {
  const result = runtimePresentation({
    ready: false,
    state: "resources_invalid",
    missing_resources: ["cyberaudit-api", "../../private"],
    invalid_resources: ["manifest.json"],
  });
  assert.equal(result.kind, "error");
  assert.equal(result.retry, true);
  assert.deepEqual(result.resources, [
    "API CyberAudit",
    "Manifesto do runtime",
  ]);
});

test("native bridge failures do not expose exception details", () => {
  const result = runtimeFailurePresentation();
  assert.equal(result.kind, "error");
  assert.equal(result.retry, true);
  assert.deepEqual(result.resources, []);
});

test("legacy credentials require an explicit migration action", () => {
  const result = runtimePresentation({
    ready: false,
    state: "credential_migration_required",
  });

  assert.equal(result.kind, "error");
  assert.equal(result.retry, false);
  assert.equal(result.action, "migrate_credentials");
  assert.match(result.message, /não serão eliminados nem substituídos/);
});

test("successful migration requires restart without claiming runtime readiness", () => {
  const result = runtimePresentation({
    ready: false,
    state: "credentials_migrated_restart_required",
  });

  assert.equal(result.kind, "progress");
  assert.equal(result.action, null);
  assert.match(result.statusText, /Reinício necessário/);
});
