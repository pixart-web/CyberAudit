import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import AttackPathDetail from "../[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({
  usePathname: () => "/attack-paths/path-1",
  useParams: () => ({ id: "path-1" }),
}));

const fixtures: Record<string, unknown> = {
  "/attack-paths/path-1": {
    path: {
      id: "path-1",
      name: "Lateral movement to db",
      description: "Entry via exposed host reaches internal db",
      entry_asset_id: "a1",
      target_asset_id: "a2",
      path_type: "lateral_movement",
      severity: "high",
      confidence: 0.8,
      overall_risk: 70,
      status: "candidate",
      generated_by: "rules",
    },
    steps: [
      {
        id: "step-1",
        sequence: 1,
        source_asset_id: "a1",
        target_asset_id: "a2",
        finding_id: null,
        condition: "network reachable",
        explanation: "host can reach db",
        confidence: 0.8,
        evidence: [],
        mitigation: "segment network",
      },
    ],
    automatic: true,
    fact_vs_inference: true,
  },
  "/agents/attack_path_analyst/ask": {
    response: "Este caminho explora acesso de rede não segmentado entre o host exposto e a base de dados interna.",
    citations: [{ source_id: "path-1" }],
    confidence: 0.7,
    limitations: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Attack Path detail shows graph facts and a distinct Cyber AI explanation via the real agent", async () => {
  wrapper(<AttackPathDetail />);

  expect(await screen.findByText("network reachable")).toBeInTheDocument();
  expect(screen.getByText(/gerado por regras determinísticas/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Explicar caminho de ataque" }));
  expect(await screen.findByText(/acesso de rede não segmentado/)).toBeInTheDocument();
});
