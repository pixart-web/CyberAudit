import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { AppSecCommandCenter } from "../appsec-command-center";

vi.mock("next/navigation", () => ({ usePathname: () => "/appsec" }));
vi.mock("@/lib/api", () => ({
  api: async () => ({
    applications: 3,
    internet_exposed: 1,
    apis: 4,
    repositories: 2,
    releases: 6,
    validated_sboms: 2,
    confirmed_secrets: 0,
    open_exceptions: 1,
    open_remediations: 2,
    generated_at: "2026-07-29T10:00:00Z",
  }),
}));

test("renders AppSec posture without exposing secret values", async () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <AppSecCommandCenter />
    </QueryClientProvider>,
  );
  expect(
    screen.getByRole("heading", { name: "AppSec Command Center" }),
  ).toBeInTheDocument();
  expect(await screen.findByText("SBOMs validados")).toBeInTheDocument();
  expect(screen.getByText("Sem execução de código submetido")).toBeInTheDocument();
  expect(screen.queryByText(/password=/i)).not.toBeInTheDocument();
});
