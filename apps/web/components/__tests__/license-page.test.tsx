import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import LicensePage from "@/app/license/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/license" }));
let summary: Record<string, unknown>;
vi.mock("@/lib/api", () => ({ api: async (p: string) => (p === "/license/summary" ? summary : { items: [] }) }));
const wrap = () => render(<QueryClientProvider client={new QueryClient()}><LicensePage /></QueryClientProvider>);
const base = { edition: "community", state: "community", license_id: "community-x", capabilities: ["findings.read"], limits: {}, expires_at: null, grace_until: null, days_remaining: null, verified_at: null, read_only: false };

test("community server without trusted keys explains why import is disabled", async () => {
  summary = { ...base, trusted_keys_configured: false };
  wrap();
  expect(await screen.findByText(/Community/)).toBeInTheDocument();
  expect(screen.getByText(/LICENSE_TRUSTED_PUBLIC_KEYS/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /importar/i })).not.toBeInTheDocument();
});

test("expired license is shown read-only with the import form available", async () => {
  summary = { ...base, edition: "professional", state: "expired", license_id: "EVAL-1", expires_at: "2026-01-01T00:00:00Z", read_only: true, trusted_keys_configured: true };
  wrap();
  expect(await screen.findByText(/Expirada/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Verificar e importar" })).toBeInTheDocument();
});
