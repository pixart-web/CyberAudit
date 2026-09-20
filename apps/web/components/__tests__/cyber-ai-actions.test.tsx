import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { IncidentWorkspace } from "../incident-workspace";
import { IdentityWorkspace } from "../identity-workspace";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/cyber-ai-test" }));

const fixtures: Record<string, unknown> = {
  "/incidents/inc-1": {
    incident: {
      id: "inc-1",
      reference: "INC-1",
      title: "Atividade suspeita",
      description: "Descrição",
      severity: "high",
      status: "investigating",
      category: "security_event",
      business_impact: "",
      risk_score: 8,
      detected_at: "2026-09-20T00:00:00Z",
    },
    timeline: [],
  },
  "/agents/incident_analyst/ask": {
    response: "Cronologia reconstruída a partir de 2 eventos registados.",
    citations: [{ source_id: "inc-1" }],
    confidence: 0.85,
    limitations: [],
  },
  "/identity/users/identity-1": {
    id: "identity-1",
    username: "jdoe",
    display_name: "Jane Doe",
    email: null,
    identity_type: "user",
    enabled: true,
    privileged: true,
    guest: false,
    service_account: false,
    owner: null,
    department: null,
    job_title: null,
    mfa_state: "false",
    risk_state: "high",
    risk_score: 80,
    last_login_at: null,
    last_activity_at: null,
  },
  "/identity/users/identity-1/risk": {
    score: 80,
    reasons: ["privileged_identity", "mfa_not_enforced"],
    calculation_version: "identity-risk-1.0.0",
  },
  "/agents/identity_analyst/ask": {
    response: "Esta identidade é privilegiada e não tem MFA aplicado.",
    citations: [{ source_id: "identity-1" }],
    confidence: 0.8,
    limitations: [],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Incident Workspace's Cyber AI tab calls the real incident_analyst agent, never a frontend shortcut", async () => {
  wrapper(<IncidentWorkspace id="inc-1" />);
  fireEvent.click(await screen.findByRole("tab", { name: "Cyber AI" }));
  fireEvent.click(screen.getByRole("button", { name: /Analisar incidente/ }));
  expect(await screen.findByText(/Cronologia reconstruída/)).toBeInTheDocument();
});

test("Identity Workspace's Risk tab can explain risk via the real identity_analyst agent", async () => {
  wrapper(<IdentityWorkspace id="identity-1" />);
  fireEvent.click(await screen.findByRole("tab", { name: "Risco" }));
  fireEvent.click(await screen.findByRole("button", { name: /Explicar risco desta identidade/ }));
  expect(await screen.findByText(/privilegiada e não tem MFA aplicado/)).toBeInTheDocument();
});
