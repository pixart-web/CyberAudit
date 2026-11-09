import { afterEach, describe, expect, it } from "vitest";
import {
  DESKTOP_SESSION_HEADER,
  desktopApiTarget,
  desktopProxyConfiguration,
  desktopRequestAllowed,
  forwardedRequestHeaders,
  forwardedResponseHeaders,
} from "@/lib/desktop-proxy";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const originalEnvironment = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnvironment };
});

describe("desktop API proxy", () => {
  it("remains disabled in the normal server build", async () => {
    delete process.env.CYBERAUDIT_DESKTOP_API_URL;
    delete process.env.CYBERAUDIT_DESKTOP_SESSION_FILE;
    delete process.env.CYBERAUDIT_DESKTOP_WEB_ORIGIN;
    await expect(desktopProxyConfiguration()).resolves.toBeNull();
  });

  it("loads a server-only capability and only accepts loopback", async () => {
    const directory = await mkdtemp(join(tmpdir(), "cyberaudit-proxy-"));
    const secretFile = join(directory, "session");
    await writeFile(secretFile, "b".repeat(64), { mode: 0o600 });
    process.env.CYBERAUDIT_DESKTOP_API_URL = "http://127.0.0.1:48123/api/v1";
    process.env.CYBERAUDIT_DESKTOP_SESSION_FILE = secretFile;
    process.env.CYBERAUDIT_DESKTOP_WEB_ORIGIN = "http://127.0.0.1:48124";
    await expect(desktopProxyConfiguration()).resolves.toMatchObject({
      secret: "b".repeat(64),
      webOrigin: "http://127.0.0.1:48124",
    });
    process.env.CYBERAUDIT_DESKTOP_API_URL =
      "https://api.example.invalid/api/v1";
    await expect(desktopProxyConfiguration()).rejects.toThrow("loopback HTTP");
    await rm(directory, { recursive: true });
  });

  it("rejects cross-site and host-confused requests", () => {
    const allowed = new Request("http://127.0.0.1:48124/api/v1/assets", {
      headers: {
        origin: "http://127.0.0.1:48124",
        "sec-fetch-site": "same-origin",
      },
    });
    const crossSite = new Request("http://127.0.0.1:48124/api/v1/assets", {
      headers: {
        origin: "https://attacker.example",
        "sec-fetch-site": "cross-site",
      },
    });
    const equivalentLoopback = new Request(
      "http://localhost:48124/api/v1/assets",
    );
    const wrongPort = new Request("http://localhost:48125/api/v1/assets");
    const malformedOrigin = new Request(
      "http://127.0.0.1:48124/api/v1/assets",
      { headers: { origin: "not a URL" } },
    );

    expect(desktopRequestAllowed(allowed, "http://127.0.0.1:48124")).toBe(true);
    expect(desktopRequestAllowed(crossSite, "http://127.0.0.1:48124")).toBe(
      false,
    );
    expect(
      desktopRequestAllowed(equivalentLoopback, "http://127.0.0.1:48124"),
    ).toBe(true);
    expect(desktopRequestAllowed(wrongPort, "http://127.0.0.1:48124")).toBe(
      false,
    );
    expect(
      desktopRequestAllowed(malformedOrigin, "http://127.0.0.1:48124"),
    ).toBe(false);
  });

  it("forwards an allowlist of headers and preserves the query", () => {
    const request = new Request("http://localhost/api/v1/assets?page=2", {
      headers: {
        authorization: "Bearer token",
        "x-untrusted-header": "must-not-cross",
      },
    });
    const headers = forwardedRequestHeaders(request, "c".repeat(64));
    expect(headers.get("authorization")).toBe("Bearer token");
    expect(headers.get(DESKTOP_SESSION_HEADER)).toBe("c".repeat(64));
    expect(headers.has("x-untrusted-header")).toBe(false);
    expect(
      desktopApiTarget(new URL("http://127.0.0.1:48123/api/v1"), request, [
        "assets",
      ]).toString(),
    ).toBe("http://127.0.0.1:48123/api/v1/assets?page=2");
  });

  it("returns only safe upstream headers", () => {
    const headers = forwardedResponseHeaders(
      new Headers({
        "content-type": "application/json",
        "set-cookie": "backend=secret",
        server: "uvicorn",
      }),
    );
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("cache-control")).toBe("no-store");
    expect(headers.has("set-cookie")).toBe(false);
    expect(headers.has("server")).toBe(false);
  });
});
