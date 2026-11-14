import { readFile } from "node:fs/promises";

const FORWARDED_REQUEST_HEADERS = [
  "accept",
  "authorization",
  "content-type",
  "cookie",
  "x-csrf-token",
  "x-request-id",
] as const;

const FORWARDED_RESPONSE_HEADERS = [
  "content-disposition",
  "content-length",
  "content-type",
  "etag",
  "x-request-id",
] as const;

export const DESKTOP_SESSION_HEADER = "x-cyberaudit-desktop-session";

function loopbackHttpUrl(value: string, label: string) {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "http:" ||
    !["127.0.0.1", "localhost"].includes(parsed.hostname)
  ) {
    throw new Error(`${label} must use loopback HTTP`);
  }
  return parsed;
}

export async function desktopProxyConfiguration() {
  const apiUrl = process.env.CYBERAUDIT_DESKTOP_API_URL;
  const secretFile = process.env.CYBERAUDIT_DESKTOP_SESSION_FILE;
  const webOrigin = process.env.CYBERAUDIT_DESKTOP_WEB_ORIGIN;
  if (!apiUrl && !secretFile && !webOrigin) return null;
  if (!apiUrl || !secretFile || !webOrigin) {
    throw new Error("Desktop proxy configuration is incomplete");
  }
  const parsed = loopbackHttpUrl(apiUrl, "Desktop API URL");
  const parsedWebOrigin = loopbackHttpUrl(webOrigin, "Desktop web origin");
  if (parsedWebOrigin.pathname !== "/") {
    throw new Error("Desktop web origin cannot contain a path");
  }
  const secret = (await readFile(secretFile, "ascii")).trim();
  if (secret.length < 32 || /\s/.test(secret))
    throw new Error("Desktop session secret is malformed");
  return { apiUrl: parsed, secret, webOrigin: parsedWebOrigin.origin };
}

function sameLoopbackOrigin(left: string, right: string) {
  try {
    const first = new URL(left);
    const second = new URL(right);
    return (
      first.protocol === "http:" &&
      second.protocol === "http:" &&
      ["127.0.0.1", "localhost"].includes(first.hostname) &&
      ["127.0.0.1", "localhost"].includes(second.hostname) &&
      first.port === second.port
    );
  } catch {
    return false;
  }
}

export function desktopRequestAllowed(request: Request, webOrigin: string) {
  if (!sameLoopbackOrigin(new URL(request.url).origin, webOrigin)) return false;
  const origin = request.headers.get("origin");
  if (origin && !sameLoopbackOrigin(origin, webOrigin)) return false;
  const fetchSite = request.headers.get("sec-fetch-site");
  return !fetchSite || ["none", "same-origin"].includes(fetchSite);
}

export function forwardedRequestHeaders(request: Request, secret: string) {
  const headers = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set(DESKTOP_SESSION_HEADER, secret);
  return headers;
}

export function forwardedResponseHeaders(source: Headers) {
  const headers = new Headers();
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = source.get(name);
    if (value) headers.set(name, value);
  }
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return headers;
}

export function desktopApiTarget(base: URL, request: Request, path: string[]) {
  const target = new URL(
    `${base.pathname.replace(/\/$/, "")}/${path.map(encodeURIComponent).join("/")}`,
    base,
  );
  target.search = new URL(request.url).search;
  return target;
}
