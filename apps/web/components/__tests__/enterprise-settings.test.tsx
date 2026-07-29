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
  expect(screen.getByText("api_availability")).toBeInTheDocument();
  expect(screen.queryByText("Telemetria")).not.toBeInTheDocument();
  expect(screen.queryByText(/password|token|private key/i)).not.toBeInTheDocument();
});
