const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

export function getToken() {
  return typeof window === "undefined" ? null : sessionStorage.getItem("access_token");
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
    throw new Error(body?.error?.message ?? "Não foi possível concluir o pedido.");
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
