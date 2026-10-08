import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { OnboardingChecklist } from "../onboarding-checklist";

afterEach(cleanup);
let counts: Record<string, number> = {};
vi.mock("@/lib/api", () => ({
  api: async (path: string) => ({ total: counts[path.split("?")[0].slice(1)] ?? 0, items: [] }),
}));
const wrap = () => render(<QueryClientProvider client={new QueryClient()}><OnboardingChecklist /></QueryClientProvider>);

test("derives each step from real counts and links to the action", async () => {
  counts = { users: 1, clients: 1 };
  wrap();
  expect(await screen.findByText(/Primeiros passos \(1\/6\)/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Criar uma auditoria" })).toHaveAttribute("href", "/engagements/new");
});

test("disappears once every step has real data", async () => {
  counts = { users: 2, clients: 1, engagements: 1, scopes: 1, assets: 1, findings: 1 };
  const { container } = wrap();
  await new Promise((r) => setTimeout(r, 50));
  expect(container).toBeEmptyDOMElement();
});
