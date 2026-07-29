import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { DomainCommandCenter } from "../domain-command-center";

vi.mock("next/navigation", () => ({ usePathname: () => "/identity" }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path.startsWith("/identity/users")) {
      return {
        total: 2,
        items: [
          {
            id: "identity-1",
            display_name: "[DEMO] Administrator",
            identity_type: "user",
            privileged: true,
            risk_score: 92,
          },
        ],
      };
    }
    if (path === "/identity/posture") {
      return { total: 2, items: [] };
    }
    if (path.startsWith("/zero-trust/assessments")) {
      return { total: 1, items: [] };
    }
    return {
      score: 42,
      status: "weak",
      confidence: 0.75,
      unknown_factors: ["session.continuous_evaluation"],
    };
  },
}));

function renderCenter(component: React.ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>,
  );
}

test("identity center renders tenant inventory and read-only guardrail", async () => {
  renderCenter(<DomainCommandCenter kind="identity" />);
  expect(screen.getByRole("heading", { name: "Identity Security Center" })).toBeInTheDocument();
  expect(await screen.findByText("[DEMO] Administrator")).toBeInTheDocument();
  expect(screen.getAllByText("Read-only").length).toBeGreaterThan(0);
});

test("zero trust center renders deterministic confidence posture", async () => {
  renderCenter(<DomainCommandCenter kind="zero-trust" />);
  expect(screen.getByRole("heading", { name: "Zero Trust Center" })).toBeInTheDocument();
  expect(await screen.findByText("42/100")).toBeInTheDocument();
  expect(screen.getAllByText("Evidência antes de confiança").length).toBeGreaterThan(0);
});
