import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import Reports from "../page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/reports" }));

const fixtures: Record<string, unknown> = {
  "/findings?page_size=100": {
    items: [
      {
        id: "finding-1",
        title: "SMB exposed to the internet",
        category: "network",
        technical_severity: "high",
        affected_component: "fileserver01",
        simulated: true,
        imported: false,
      },
    ],
    total: 1,
  },
  "/agents/report_agent/ask": {
    response: "Um finding de rede de severidade elevada foi observado e permanece por corrigir.",
    citations: [{ source_id: "finding-1" }],
    confidence: 0.65,
    limitations: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Reports page can draft an executive summary via the real report_agent, grounded in the listed findings", async () => {
  wrapper(<Reports />);
  fireEvent.click(await screen.findByRole("button", { name: "Draft Executive Summary" }));
  expect(await screen.findByText(/severidade elevada/)).toBeInTheDocument();
});
