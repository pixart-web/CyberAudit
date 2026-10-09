const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

export function getToken() {
  return typeof window === "undefined" ? null : sessionStorage.getItem("access_token");
}

export class ApiError extends Error {
  /** Server-side validation messages keyed by field name (never includes submitted values). */
  fieldErrors: Record<string, string>;
  constructor(message: string, fieldErrors: Record<string, string> = {}) {
    super(message);
    this.fieldErrors = fieldErrors;
  }
}

function validationFields(details: unknown): Record<string, string> {
  if (!Array.isArray(details)) return {};
  const out: Record<string, string> = {};
  for (const item of details) {
    const loc = (item as { loc?: unknown[] })?.loc;
    const msg = (item as { msg?: unknown })?.msg;
    if (Array.isArray(loc) && typeof msg === "string") out[String(loc[loc.length - 1])] ??= msg;
  }
  return out;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const isForm = init.body instanceof FormData;
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { ...(!isForm ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...init.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    if (response.status === 403 && body?.error?.message === "PASSWORD_CHANGE_REQUIRED" && typeof window !== "undefined" && window.location.pathname !== "/account") {
      window.location.assign("/account");
    }
    const fields = validationFields(body?.error?.details);
    const summary = Object.entries(fields).map(([name, msg]) => `${name}: ${msg}`).join("; ");
    throw new ApiError(summary ? `Dados inválidos — ${summary}` : (body?.error?.message ?? "Não foi possível concluir o pedido."), fields);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

/** Authenticated file download (bearer token cannot be sent by a plain <a href>). */
export async function downloadFile(path: string, fallbackName: string): Promise<void> {
  const token = getToken();
  const response = await fetch(`${API_URL}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message ?? "Não foi possível exportar o ficheiro.");
  }
  const name = /filename="([^"]+)"/.exec(response.headers.get("content-disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
