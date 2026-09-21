/**
 * Phase 10.4.1 section 38: evidence, notes, IOC, threat intelligence, and
 * AI output are all potentially untrusted content and must never be
 * rendered as HTML. This proves it for the new surfaces built in this
 * phase (Security Event's normalized payload, Report's AI-generated
 * section body, Hunt's declarative query, Case's analyst-authored
 * hypothesis/conclusions) by feeding each one a script-tag payload and
 * asserting React rendered it as an inert text node (no
 * dangerouslySetInnerHTML anywhere in these files -- verified separately
 * by grep -- and no injected <script> ends up in the live DOM).
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import SecurityEventDetail from "@/app/security-events/[id]/page";
import CaseDetail from "@/app/cases/[id]/page";
import HuntDetail from "@/app/hunts/[id]/page";
import ReportDetail from "@/app/reports/[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ useParams: () => ({ id: "obj-1" }), usePathname: () => "/xss-test" }));

const PAYLOAD = '<script>window.__xss=1</script><img src=x onerror="window.__xss=1">';

const fixtures: Record<string, unknown> = {
  "/security-events/obj-1": {
    event: {
      id: "obj-1",
      source: "edr",
      event_type: "login_failed",
      severity: "high",
      occurred_at: "2026-09-20T00:00:00Z",
      actor_ref: PAYLOAD,
      asset_id: null,
      source_ip: null,
      destination_ip: null,
      summary: PAYLOAD,
      normalized: { note: PAYLOAD },
      labels: [PAYLOAD],
      content_hash: "a".repeat(64),
      trusted: false,
    },
    alerts: [],
  },
  "/cases/obj-1": {
    case: {
      id: "obj-1",
      reference: "CASE-1",
      title: PAYLOAD,
      status: "open",
      lead_investigator_id: null,
      members: [],
      hypothesis: PAYLOAD,
      conclusions: PAYLOAD,
      legal_hold: false,
      incident_id: "incident-1",
    },
    incident: null,
  },
  "/hunts/obj-1": {
    id: "obj-1",
    name: PAYLOAD,
    hypothesis: PAYLOAD,
    query: { event_type: PAYLOAD },
    status: "draft",
    time_from: "2026-09-19T00:00:00Z",
    time_until: "2026-09-20T00:00:00Z",
    result_count: 1,
    findings: [{ event_id: "e-1", summary: PAYLOAD, occurred_at: "2026-09-20T00:00:00Z" }],
  },
  "/reports/obj-1": {
    report: { id: "obj-1", engagement_id: "eng-1", report_type: "executive_summary", title: "Report", status: "draft", created_at: "2026-09-20T00:00:00Z" },
    sections: [
      {
        id: "sec-1",
        position: 0,
        heading: "Executive Summary",
        content_type: "ai_generated",
        body: PAYLOAD,
        source_references: [],
        ai_citations: [],
      },
    ],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

function assertNoScriptExecutedOrInjected(container: HTMLElement) {
  expect(container.querySelector("script")).toBeNull();
  expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
  // The payload's literal text must still be present -- proving it was
  // rendered as inert text, not silently stripped (which would also hide
  // a real rendering bug) and not executed.
  expect(container.textContent).toContain("<script>");
}

test("Security Event detail renders a malicious normalized payload as inert text", async () => {
  const { container } = wrapper(<SecurityEventDetail />);
  await screen.findByText(/login_failed/);
  assertNoScriptExecutedOrInjected(container);
});

test("Case detail renders malicious analyst-authored hypothesis/conclusions as inert text", async () => {
  const { container } = wrapper(<CaseDetail />);
  await screen.findByText("open");
  assertNoScriptExecutedOrInjected(container);
});

test("Hunt detail renders a malicious declarative query value and finding summary as inert text", async () => {
  const { container } = wrapper(<HuntDetail />);
  await screen.findByText("draft");
  assertNoScriptExecutedOrInjected(container);
});

test("Report detail renders AI-generated section body as inert text, never as HTML", async () => {
  const { container } = wrapper(<ReportDetail />);
  await screen.findByText("Executive Summary");
  assertNoScriptExecutedOrInjected(container);
});
