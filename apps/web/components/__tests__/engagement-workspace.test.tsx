import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { EngagementWorkspace } from "../engagement-workspace";

afterEach(cleanup);

vi.mock("next/navigation", () => ({ usePathname: () => "/engagements/eng-1" }));

const mocks: Record<string, unknown> = {
  "/engagements/eng-1": {
    id: "eng-1",
    code: "ACME-2026-01",
    name: "Avaliação de Superfície Interna",
    description: "Avaliação autorizada da superfície interna.",
    mode: "client",
    status: "active",
    risk_level: "high",
    start_date: null,
    end_date: null,
    client_id: "client-1",
  },
  "/scopes?engagement_id=eng-1": {
    items: [{ id: "scope-1", name: "Rede interna", status: "active", maximum_intensity: "normal", emergency_stop_enabled: true }],
    total: 1,
  },
  "/findings?engagement_id=eng-1": {
    items: [{ id: "finding-1", title: "Falta de MFA", category: "identity", technical_severity: "critical", status: "open" }],
    total: 1,
  },
  "/engagements/eng-1/timeline": {
    items: [{ id: "t-1", event_type: "scope_change", summary: "Âmbito atualizado", occurred_at: "2026-09-20T10:00:00Z" }],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path in mocks) return mocks[path];
    if (/^\/engagements\/[^/]+$/.test(path)) {
      throw new Error("Not found");
    }
    return { items: [] };
  },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("engagement workspace shows real overview data and scope/findings after tab switch", async () => {
  wrapper(<EngagementWorkspace id="eng-1" />);

  expect(await screen.findByRole("heading", { name: "Avaliação de Superfície Interna" })).toBeInTheDocument();
  expect(screen.getByText("Elevado")).toBeInTheDocument(); // risk_level SeverityBadge ("high")
  await waitFor(() => expect(screen.getAllByText("1").length).toBeGreaterThan(0)); // stats populated

  fireEvent.click(screen.getByRole("tab", { name: "Âmbito" }));
  expect(await screen.findByText("Rede interna")).toBeInTheDocument();
  expect(screen.getByText("Emergency stop")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Findings" }));
  expect(await screen.findByText("Falta de MFA")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Cronologia" }));
  expect(await screen.findByText("Âmbito atualizado")).toBeInTheDocument();
});

test("engagement workspace shows a Summarize Assessment action wired to the report endpoint", async () => {
  wrapper(<EngagementWorkspace id="eng-1" />);
  await screen.findByRole("heading", { name: "Avaliação de Superfície Interna" });
  expect(screen.getByRole("button", { name: /Summarize Assessment/ })).toBeInTheDocument();
});

test("engagement workspace shows an error state for an unauthorized or missing engagement", async () => {
  wrapper(<EngagementWorkspace id="not-authorized" />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Auditoria não encontrada ou sem autorização.");
});
