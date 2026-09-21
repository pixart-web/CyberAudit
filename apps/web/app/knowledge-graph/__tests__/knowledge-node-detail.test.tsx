import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import KnowledgeNodeDetail from "../[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({
  usePathname: () => "/knowledge-graph/node-1",
  useParams: () => ({ id: "node-1" }),
}));

const fixtures: Record<string, unknown> = {
  "/knowledge-nodes/node-1": {
    node: {
      id: "node-1",
      node_type: "incident",
      source_id: "inc-1",
      label: "Atividade suspeita",
      facts: { severity: "high" },
      source_references: ["incident:inc-1"],
      confidence: 0.9,
      indexed_at: "2026-09-20T00:00:00Z",
    },
    outgoing_edges: [
      {
        id: "edge-1",
        source_node_id: "node-1",
        target_node_id: "node-2",
        edge_type: "affects",
        confidence: 0.8,
        inferred: false,
        other_node: { label: "Servidor de Ficheiros", source_id: "asset-2" },
      },
    ],
    incoming_edges: [],
  },
  "/agents/knowledge_analyst/ask": {
    response: "A relação 'affects' liga este incidente ao ativo Servidor de Ficheiros com base em evidência registada.",
    citations: [{ node_id: "node-1", source_id: "inc-1" }],
    confidence: 0.75,
    limitations: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Knowledge node detail can explain a specific relationship, not just the node as a whole", async () => {
  wrapper(<KnowledgeNodeDetail />);
  expect(await screen.findByText(/affects/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Explicar relação affects" }));
  expect(await screen.findByText(/liga este incidente ao ativo/)).toBeInTheDocument();
});
