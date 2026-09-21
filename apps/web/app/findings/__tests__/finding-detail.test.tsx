import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import FindingDetail from "../[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({
  usePathname: () => "/findings/finding-1",
  useParams: () => ({ id: "finding-1" }),
}));

const fixtures: Record<string, unknown> = {
  "/findings/finding-1": {
    id: "finding-1",
    job_id: "job-1",
    title: "SMB exposed to the internet",
    description: "SMB port reachable from an untrusted network.",
    category: "network",
    technical_severity: "high",
    confidence: "confirmed",
    status: "open",
    affected_component: "fileserver01",
    technical_impact: "Remote code execution risk.",
    business_impact: "Potential data exposure.",
    remediation_summary: "Restrict port 445 to the internal segment.",
    validation_steps: ["Confirm port closed from the internet"],
    source_adapter: "network_scan",
    standards: [],
    references: [],
    remediation_effort: "low",
    remediation_priority: "high",
    imported: false,
    simulated: true,
    verification_status: "confirmed",
    first_seen_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-09-20T00:00:00Z",
  },
  "/evidence?finding_id=finding-1": { items: [] },
  "/agents/remediation_advisor/ask": {
    response: "Aplicar patch X e restringir a porta 445 ao segmento interno.",
    citations: [{ node_id: "n1", source_type: "finding", source_id: "finding-1" }],
    confidence: 0.6,
    limitations: [],
    required_human_approval: true,
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Finding detail's Cyber AI tab can recommend remediation via the real remediation_advisor agent, flagging human approval", async () => {
  wrapper(<FindingDetail />);
  fireEvent.click(await screen.findByRole("tab", { name: "Cyber AI" }));
  fireEvent.click(screen.getByRole("button", { name: "Recomendar remediação" }));
  expect(await screen.findByText(/restringir a porta 445/)).toBeInTheDocument();
  expect(screen.getByText(/Requer aprovação humana/)).toBeInTheDocument();
});
