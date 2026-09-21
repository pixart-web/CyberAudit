import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import IocDetail from "@/app/threat-intelligence/[id]/page";
import KnowledgeNodeDetail from "@/app/knowledge-graph/[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ useParams: () => ({ id: "obj-1" }), usePathname: () => "/intel-test" }));

const fixtures: Record<string, unknown> = {
  "/iocs/obj-1": {
    indicator: {
      id: "obj-1",
      indicator_type: "ip",
      display_value: "198.51.100.7",
      confidence: 0.9,
      severity: "high",
      status: "active",
      valid_from: "2026-09-01T00:00:00Z",
      valid_until: null,
      labels: ["c2"],
      references: ["https://intel.example.invalid/report/1"],
    },
    feed: { id: "feed-1", name: "Community Feed", provider: "cyberaudit", trust_level: "verified" },
  },
  "/knowledge-nodes/obj-1": {
    node: {
      id: "obj-1",
      node_type: "finding",
      source_id: "finding-1",
      label: "Missing security headers",
      facts: { severity: "medium" },
      source_references: ["finding-1"],
      confidence: 0.95,
      indexed_at: "2026-09-20T00:00:00Z",
    },
    outgoing_edges: [{ id: "edge-1", source_node_id: "obj-1", target_node_id: "node-2", edge_type: "affects", confidence: 0.8, inferred: false }],
    incoming_edges: [],
  },
  "/agents/knowledge_analyst/ask": {
    response: "Este nó representa um finding com evidência associada.",
    citations: [{ node_id: "obj-1", source_id: "finding-1" }],
    confidence: 0.9,
    limitations: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("IOC detail shows its origin feed and trust level", async () => {
  wrapper(<IocDetail />);
  expect(await screen.findByText("198.51.100.7")).toBeInTheDocument();
  expect(screen.getByText("Community Feed")).toBeInTheDocument();
  expect(screen.getByText("verified")).toBeInTheDocument();
});

test("Knowledge Node detail renders facts as inert text and can call the real knowledge_analyst agent", async () => {
  wrapper(<KnowledgeNodeDetail />);
  expect(await screen.findByText("Missing security headers")).toBeInTheDocument();
  expect(screen.getByText(/"severity": "medium"/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Explicar este nó/ }));
  expect(await screen.findByText(/finding com evidência associada/)).toBeInTheDocument();
});
