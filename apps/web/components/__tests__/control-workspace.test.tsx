import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { ControlWorkspace } from "../control-workspace";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/grc/controls/ctl-1" }));

const fixtures: Record<string, unknown> = {
  "/grc/controls/ctl-1": {
    id: "ctl-1",
    code: "CTL-1",
    title: "MFA everywhere",
    description: "test",
    domain: "identity",
    objective: "",
    status: "approved",
    maturity_level: 3,
    implementation_status: "partially_implemented",
    next_review_at: null,
  },
  "/grc/exceptions?subject_type=control&subject_id=ctl-1": {
    items: [
      {
        id: "exc-1",
        reason: "Vendor cannot support MFA until Q3",
        status: "approved",
        compensating_controls: ["network_segmentation"],
        expires_at: "2026-12-31T00:00:00Z",
        reviewed_at: "2026-09-01T00:00:00Z",
      },
    ],
  },
  "/agents/grc_analyst/ask": {
    response: "Este controlo está parcialmente implementado; falta cobertura para contas de serviço.",
    citations: [{ source_id: "ctl-1" }],
    confidence: 0.85,
    limitations: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Control Workspace shows exceptions as an accepted-risk, not a compliance claim", async () => {
  wrapper(<ControlWorkspace id="ctl-1" />);
  fireEvent.click(await screen.findByRole("tab", { name: "Exceções" }));
  expect(await screen.findByText(/Vendor cannot support MFA/)).toBeInTheDocument();
  expect(screen.getByText(/network_segmentation/)).toBeInTheDocument();
});

test("Control Workspace's Cyber AI tab explains the compliance gap via the real grc_analyst agent", async () => {
  wrapper(<ControlWorkspace id="ctl-1" />);
  fireEvent.click(await screen.findByRole("tab", { name: "Cyber AI" }));
  fireEvent.click(screen.getByRole("button", { name: /Explicar gap de conformidade/ }));
  expect(await screen.findByText(/parcialmente implementado/)).toBeInTheDocument();
});
