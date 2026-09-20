function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function createPkce(): Promise<{
  verifier: string;
  challenge: string;
  verifierHash: string;
}> {
  const random = crypto.getRandomValues(new Uint8Array(64));
  const verifier = base64Url(random);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  );
  return { verifier, challenge: base64Url(digest), verifierHash: hex(digest) };
}
