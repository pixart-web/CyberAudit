import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import EnterpriseSettings from "@/app/settings/page";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings" }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path === "/operations/health") {
      return {
        status: "ok",
        environment: "development",
        configuration: "development",
        authentication: "local",
        secret_provider: "environment",
        object_storage: "filesystem",
        runner: "local_restricted",
        active_sessions: 1,
        backup_records: 0,
        backup_readiness: "unverified",
        restore_readiness: "unverified",
      };
    }
    if (path === "/feature-flags") {
      return {
        items: [
          {
            id: "flag-1",
            code: "enterprise_sso",
            description: "SSO controlado",
            enabled: false,
            environment: "development",
          },
        ],
        total: 1,
      };
    }
    if (path === "/operations/slos") {
      return {
        items: [
          { id: "slo-1", code: "api_availability", service: "api", target: 99.9, status: "unmeasured" },
        ],
        total: 1,
      };
    }
    if (path === "/operations/production-readiness") {
      return {
        state: "blocked",
        blockers: ["backup", "restore"],
        checks: [
          {
            code: "rls",
            status: "passed",
            observed_at: "2026-07-30T10:00:00Z",
            evidence_references: ["evidence://rls"],
          },
          { code: "backup", status: "missing" },
        ],
        environment: "production-like",
        application_version: "10.1.0-rc.1",
        evaluated_at: "2026-07-30T10:01:00Z",
        formal_approval_required: true,
      };
    }
    return { edition: "community", provider: "community", status: "active", capabilities: [] };
  },
}));

test("renders operational posture without exposing secret values", async () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <EnterpriseSettings />
    </QueryClientProvider>,
  );
  expect(await screen.findByText("enterprise_sso")).toBeInTheDocument();
  expect(await screen.findByText("Production Readiness Gate")).toBeInTheDocument();
  expect(screen.getByText("blocked")).toBeInTheDocument();
  expect(screen.getByText("rls")).toBeInTheDocument();
  expect(screen.getByText("api_availability")).toBeInTheDocument();
  expect(screen.queryByText("Telemetria")).not.toBeInTheDocument();
  expect(screen.queryByText(/password|token|private key/i)).not.toBeInTheDocument();
});
