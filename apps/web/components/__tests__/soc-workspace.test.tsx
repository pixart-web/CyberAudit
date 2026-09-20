import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import SecurityEventDetail from "@/app/security-events/[id]/page";
import DetectionAlertDetail from "@/app/detections/[id]/page";
import CaseDetail from "@/app/cases/[id]/page";
import HuntDetail from "@/app/hunts/[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ useParams: () => ({ id: "obj-1" }), usePathname: () => "/soc-workspace-test" }));

const fixtures: Record<string, unknown> = {
  "/security-events/obj-1": {
    event: {
      id: "obj-1",
      source: "edr",
      event_type: "login_failed",
      severity: "high",
      occurred_at: "2026-09-20T00:00:00Z",
      actor_ref: "user@example.invalid",
      asset_id: "asset-1",
      source_ip: "10.0.0.1",
      destination_ip: null,
      summary: "Repeated failed login",
      normalized: { attempts: 5 },
      labels: ["brute-force"],
      content_hash: "a".repeat(64),
      trusted: false,
    },
    alerts: [{ id: "alert-1", title: "Brute force detected", severity: "high", status: "open" }],
  },
  "/detections/alerts/obj-1": {
    alert: {
      id: "obj-1",
      title: "Brute force detected",
      severity: "high",
      status: "open",
      confidence: 0.8,
      fingerprint: "fp-1",
      incident_id: "incident-1",
      event_id: "event-1",
      reasons: ["5 failed logins in 60s"],
      mitre_techniques: ["T1110"],
      occurrence_count: 5,
      first_seen_at: "2026-09-20T00:00:00Z",
      last_seen_at: "2026-09-20T00:05:00Z",
    },
    rule: { id: "rule-1", name: "Brute force rule", description: "Detects repeated failures", severity: "high" },
    event: { id: "event-1", summary: "Repeated failed login", source: "edr" },
  },
  "/cases/obj-1": {
    case: {
      id: "obj-1",
      reference: "CASE-1",
      title: "Suspicious authentication activity",
      status: "open",
      lead_investigator_id: "analyst-1",
      members: ["analyst-1", "analyst-2"],
      hypothesis: "Credential stuffing attempt",
      conclusions: "",
      legal_hold: true,
      incident_id: "incident-1",
    },
    incident: { id: "incident-1", reference: "INC-1", title: "Anomalous auth activity", status: "investigating" },
  },
  "/hunts/obj-1": {
    id: "obj-1",
    name: "Brute force hunt",
    hypothesis: "Repeated login failures may indicate brute force",
    query: { event_type: "login_failed" },
    status: "draft",
    time_from: "2026-09-19T00:00:00Z",
    time_until: "2026-09-20T00:00:00Z",
    result_count: 0,
    findings: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Security Event detail shows real fields and renders normalized payload as inert text", async () => {
  wrapper(<SecurityEventDetail />);
  expect(await screen.findByText("Repeated failed login")).toBeInTheDocument();
  expect(screen.getByText("Brute force detected")).toBeInTheDocument();
  expect(screen.getByText(/"attempts": 5/)).toBeInTheDocument();
  expect(screen.getByText(/inerte/)).toBeInTheDocument();
});

test("Detection Alert detail joins its rule and originating event", async () => {
  wrapper(<DetectionAlertDetail />);
  expect(await screen.findByText("Brute force rule")).toBeInTheDocument();
  expect(screen.getByText("Repeated failed login")).toBeInTheDocument();
  expect(screen.getByText("T1110")).toBeInTheDocument();
});

test("Case detail links to its incident and shows investigation fields", async () => {
  wrapper(<CaseDetail />);
  expect(await screen.findByText("Suspicious authentication activity")).toBeInTheDocument();
  expect(screen.getByText("Credential stuffing attempt")).toBeInTheDocument();
  expect(screen.getByText("Legal hold")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /INC-1/ })).toHaveAttribute("href", "/incidents/incident-1");
});

test("Hunt detail exposes the declarative query and an execute action, never eval", async () => {
  wrapper(<HuntDetail />);
  expect(await screen.findByText("Brute force hunt")).toBeInTheDocument();
  expect(screen.getByText("login_failed")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Executar hunt/ })).toBeInTheDocument();
});
