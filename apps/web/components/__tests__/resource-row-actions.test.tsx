import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { ResourcePage } from "../resource-page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/clients" }));

const calls: { path: string; init?: RequestInit }[] = [];
vi.mock("@/lib/api", () => ({
  api: async (path: string, init?: RequestInit) => {
    calls.push({ path, init });
    if (!init?.method || init.method === "GET") {
      if (path.startsWith("/auth/me")) return { name: "T", roles: [] };
      return { items: [{ id: "c1", name: "Northstar", email: "a@b.example.com" }], total: 1, page: 1, page_size: 20 };
    }
    return undefined;
  },
}));
beforeEach(() => { calls.length = 0; });

function view() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ResourcePage
        title="Clientes"
        endpoint="/clients"
        columns={[["name", "Nome"], ["email", "Email"]]}
        rowActions={{
          edit: {
            title: "Editar cliente",
            path: (id) => `/clients/${id}`,
            values: (item) => ({ name: String(item.name), email: String(item.email ?? "") }),
            fields: [{ name: "name", label: "Nome", required: true }, { name: "email", label: "Email", type: "email" }],
          },
          archive: { path: (id) => `/clients/${id}`, confirmTitle: "Arquivar?", confirmDescription: "Preserva dados." },
        }}
      />
    </QueryClientProvider>,
  );
}

test("edit sends only changed fields via PATCH (cleared optional field becomes null)", async () => {
  view();
  fireEvent.click(await screen.findByRole("button", { name: "Editar Northstar" }));
  expect(screen.getByLabelText(/Nome/)).toHaveValue("Northstar");
  fireEvent.change(screen.getByLabelText(/Nome/), { target: { value: "Northstar Renamed" } });
  fireEvent.change(screen.getByLabelText(/Email/), { target: { value: "" } });
  fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
  await waitFor(() => expect(calls.some((c) => c.init?.method === "PATCH")).toBe(true));
  const patch = calls.find((c) => c.init?.method === "PATCH")!;
  expect(patch.path).toBe("/clients/c1");
  expect(JSON.parse(String(patch.init!.body))).toEqual({ name: "Northstar Renamed", email: null });
});

test("archive requires confirmation, then DELETEs", async () => {
  view();
  fireEvent.click(await screen.findByRole("button", { name: "Arquivar Northstar" }));
  expect(calls.some((c) => c.init?.method === "DELETE")).toBe(false);
  fireEvent.click(await screen.findByRole("button", { name: "Arquivar" }));
  await waitFor(() => expect(calls.some((c) => c.init?.method === "DELETE" && c.path === "/clients/c1")).toBe(true));
});
