import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { CreateForm } from "../create-form";

afterEach(cleanup);

const calls: { path: string; init?: RequestInit }[] = [];
let failWith: string | null = null;

vi.mock("@/lib/api", () => ({
  api: async (path: string, init?: RequestInit) => {
    calls.push({ path, init });
    if (failWith && init?.method === "POST") throw new Error(failWith);
    if (path === "/roles") return { items: [{ name: "Auditor" }, { name: "Reviewer" }] };
    return { id: "new-1" };
  },
}));

beforeEach(() => {
  calls.length = 0;
  failWith = null;
});

function renderForm(onCreated = vi.fn()) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateForm
        title="Novo utilizador"
        endpoint="/users"
        onCreated={onCreated}
        fields={[
          { name: "name", label: "Nome", required: true },
          { name: "password", label: "Palavra-passe", type: "password", required: true, minLength: 14 },
          { name: "role", label: "Perfil", type: "select", optionsFrom: { path: "/roles", value: "name", label: "name" } },
        ]}
      />
    </QueryClientProvider>,
  );
  return onCreated;
}

test("validates required/min length client-side without calling the API", async () => {
  renderForm();
  fireEvent.change(screen.getByLabelText(/Palavra-passe/), { target: { value: "curta" } });
  fireEvent.click(screen.getByRole("button", { name: "Criar" }));
  expect(await screen.findByText("Campo obrigatório")).toBeInTheDocument();
  expect(screen.getByText("Mínimo de 14 caracteres")).toBeInTheDocument();
  expect(calls.some((c) => c.init?.method === "POST")).toBe(false);
});

test("POSTs real payload (dropping empty fields) and reports success", async () => {
  const onCreated = renderForm();
  fireEvent.change(screen.getByLabelText(/Nome/), { target: { value: "Maria" } });
  fireEvent.change(screen.getByLabelText(/Palavra-passe/), { target: { value: "Correct-Horse-Battery-9" } });
  await screen.findByRole("option", { name: "Reviewer" });
  fireEvent.change(screen.getByLabelText(/Perfil/), { target: { value: "Reviewer" } });
  fireEvent.click(screen.getByRole("button", { name: "Criar" }));
  await waitFor(() => expect(onCreated).toHaveBeenCalled());
  const post = calls.find((c) => c.init?.method === "POST")!;
  expect(post.path).toBe("/users");
  expect(JSON.parse(String(post.init!.body))).toEqual({ name: "Maria", password: "Correct-Horse-Battery-9", role: "Reviewer" });
  expect(screen.getByRole("status")).toHaveTextContent("Criado com sucesso");
});

test("shows the server's error instead of faking success", async () => {
  failWith = "A user with this e-mail already exists";
  renderForm();
  fireEvent.change(screen.getByLabelText(/Nome/), { target: { value: "Maria" } });
  fireEvent.change(screen.getByLabelText(/Palavra-passe/), { target: { value: "Correct-Horse-Battery-9" } });
  fireEvent.click(screen.getByRole("button", { name: "Criar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("already exists");
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
});

test("datetime fields are sent as ISO-8601 and empty generated fields are filled", async () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateForm
        title="Evento"
        endpoint="/security-events"
        fields={[
          { name: "occurred_at", label: "Ocorrido em", type: "datetime", required: true },
          { name: "external_id", label: "ID externo", generate: () => "manual-123" },
        ]}
      />
    </QueryClientProvider>,
  );
  fireEvent.change(screen.getByLabelText(/Ocorrido em/), { target: { value: "2026-10-08T10:30" } });
  fireEvent.click(screen.getByRole("button", { name: "Criar" }));
  await waitFor(() => expect(calls.some((c) => c.init?.method === "POST")).toBe(true));
  const body = JSON.parse(String(calls.find((c) => c.init?.method === "POST")!.init!.body));
  expect(body.external_id).toBe("manual-123");
  expect(body.occurred_at).toBe(new Date("2026-10-08T10:30").toISOString());
});
