import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { IdentityWorkspace } from "../identity-workspace";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/identity/users/identity-1" }));

const fixtures: Record<string, unknown> = {
  "/identity/users/identity-1": {
    id: "identity-1",
    username: "jdoe",
    display_name: "Jane Doe",
    email: "jdoe@example.invalid",
    identity_type: "user",
    enabled: true,
    privileged: true,
    guest: false,
    service_account: false,
    owner: null,
    department: "Engineering",
    job_title: "SRE",
    mfa_state: "false",
    risk_state: "high",
    risk_score: 60,
    last_login_at: "2026-09-19T00:00:00Z",
    last_activity_at: "2025-01-01T00:00:00Z",
  },
  "/identity/users/identity-1/risk": {
    score: 90,
    reasons: ["privileged_identity", "mfa_not_enforced", "enabled_stale_identity", "owner_missing"],
    calculation_version: "identity-risk-1.0.0",
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Identity Workspace shows the real deterministic risk factors, never a fabricated privilege claim", async () => {
  wrapper(<IdentityWorkspace id="identity-1" />);

  expect(await screen.findByText("Jane Doe")).toBeInTheDocument();
  expect(screen.getByText("Privilegiada")).toBeInTheDocument();
  expect(screen.getByText("Sem responsável atribuído")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: "Risco" }));
  expect(await screen.findByText("90")).toBeInTheDocument();
  expect(screen.getByText("MFA não aplicado")).toBeInTheDocument();
  expect(screen.getByText("Conta ativa e inativa há mais de 90 dias")).toBeInTheDocument();
});
