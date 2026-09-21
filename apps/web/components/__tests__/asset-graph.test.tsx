import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import AssetGraphPage from "@/app/asset-graph/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/asset-graph" }));

const graphFixture = {
  nodes: [
    { id: "a1", label: "demo-edge", type: "host", risk_score: 82, exposure: "internet", criticality: "critical", confidence: 0.9 },
    { id: "a2", label: "internal-db", type: "database", risk_score: 40, exposure: "internal", criticality: "medium", confidence: 0.8 },
  ],
  edges: [
    { id: "e1", source: "a1", target: "a2", type: "connects_to", confidence: 0.75, reviewed: false },
  ],
  limit: 100,
  progressive: true,
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path.startsWith("/asset-graph")) return graphFixture;
    if (path.startsWith("/attack-paths")) return { items: [{ id: "path-1", name: "Lateral movement to db", severity: "high", overall_risk: 70 }] };
    return { items: [] };
  },
}));

test("renders bounded graph and accessible zoom controls", async () => {
  render(<QueryClientProvider client={new QueryClient()}><AssetGraphPage /></QueryClientProvider>);
  expect(await screen.findByRole("button", { name: "Selecionar nó demo-edge" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Aumentar zoom" }));
  expect(screen.getByText(/não representam exploração/i)).toBeInTheDocument();
});

test("search filters nodes by label, and reset restores the full graph", async () => {
  render(<QueryClientProvider client={new QueryClient()}><AssetGraphPage /></QueryClientProvider>);
  await screen.findByRole("button", { name: "Selecionar nó demo-edge" });
  expect(screen.getByRole("button", { name: "Selecionar nó internal-db" })).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Procurar nó por nome"), { target: { value: "edge" } });
  expect(screen.getByRole("button", { name: "Selecionar nó demo-edge" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Selecionar nó internal-db" })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Repor zoom e filtros" }));
  expect(screen.getByRole("button", { name: "Selecionar nó internal-db" })).toBeInTheDocument();
});

test("type filter narrows nodes to the selected type", async () => {
  render(<QueryClientProvider client={new QueryClient()}><AssetGraphPage /></QueryClientProvider>);
  await screen.findByRole("button", { name: "Selecionar nó demo-edge" });

  fireEvent.change(screen.getByLabelText("Filtrar por tipo"), { target: { value: "database" } });
  expect(screen.queryByRole("button", { name: "Selecionar nó demo-edge" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Selecionar nó internal-db" })).toBeInTheDocument();
});

test("table view provides a textual fallback with the same node data", async () => {
  render(<QueryClientProvider client={new QueryClient()}><AssetGraphPage /></QueryClientProvider>);
  await screen.findByRole("button", { name: "Selecionar nó demo-edge" });

  fireEvent.click(screen.getByRole("button", { name: "Ver como tabela" }));
  expect(screen.getByRole("table")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "demo-edge" })).toHaveAttribute("href", "/assets/a1");
});

test("selecting a node shows its details, relationships, and related attack paths", async () => {
  render(<QueryClientProvider client={new QueryClient()}><AssetGraphPage /></QueryClientProvider>);
  await screen.findByRole("button", { name: "Selecionar nó demo-edge" });

  fireEvent.click(screen.getByRole("button", { name: "Selecionar nó demo-edge" }));
  expect(await screen.findByText("Lateral movement to db")).toBeInTheDocument();
  expect(screen.getAllByText(/connects_to/).length).toBeGreaterThan(0);
  expect(screen.getByRole("link", { name: "Ver ativo completo" })).toHaveAttribute("href", "/assets/a1");
});
