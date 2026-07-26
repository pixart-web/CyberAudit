import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import JobDetail from "@/app/jobs/[id]/page";

vi.mock("next/navigation", () => ({
  usePathname: () => "/jobs/job-1",
  useParams: () => ({ id: "job-1" }),
}));
vi.mock("@/lib/api", () => ({
  api: async (path: string) =>
    path.endsWith("/events")
      ? [{ id: "event-1", event_type: "progress", severity: "info", message: "Avaliação simulada", created_at: "2026-07-23T10:00:00Z", event_metadata: { progress: 54 } }]
      : path.endsWith("/results")
        ? { summary: {}, findings: [] }
        : path.startsWith("/evidence")
          ? { items: [] }
      : {
          id: "job-1", status: "running", progress: 54, status_message: "Avaliação simulada",
          engagement_id: "eng-1", scope_id: "scope-1", target_value: "10.20.0.10",
          adapter_code: "cyberaudit.demo_assessment", intensity: "normal",
          created_at: "2026-07-23T09:59:00Z", result_summary: {},
        },
}));

test("renders live job progress, events and cancellation action", async () => {
  render(<QueryClientProvider client={new QueryClient()}><JobDetail /></QueryClientProvider>);
  expect(await screen.findByText("54%")).toBeInTheDocument();
  expect((await screen.findAllByText("Avaliação simulada")).length).toBeGreaterThanOrEqual(2);
  expect(screen.getByRole("button", { name: /Cancelar/ })).toBeInTheDocument();
  expect(screen.getByText("cyberaudit.demo_assessment")).toBeInTheDocument();
});
