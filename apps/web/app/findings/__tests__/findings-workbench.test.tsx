import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import FindingsPage from "@/app/findings/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/findings" }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path.startsWith("/findings"))
      return {
        items: [
          {
            id: "finding-1",
            title: "MFA desativada",
            description: "Controlo não ativo.",
            category: "identity",
            affected_component: "demo-account",
            technical_severity: "high",
            confidence: "high",
            status: "open",
            source_adapter: "cyberaudit.demo",
            simulated: true,
            imported: false,
            last_seen_at: "2026-01-02T10:00:00Z",
          },
          {
            id: "finding-2",
            title: "Política conforme",
            description: "Sem desvio crítico.",
            category: "policy",
            affected_component: "demo-policy",
            technical_severity: "low",
            confidence: "medium",
            status: "resolved",
            source_adapter: "cyberaudit.demo",
            simulated: true,
            imported: false,
            last_seen_at: "2026-01-01T10:00:00Z",
          },
        ],
        total: 2,
        page: 1,
        page_size: 100,
      };
    return { items: [] };
  },
}));

function renderPage() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <FindingsPage />
    </QueryClientProvider>,
  );
}

test("findings workbench filters and opens an inspection panel without inventing data", async () => {
  renderPage();
  expect(await screen.findByText("MFA desativada")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Filtrar por severidade"), {
    target: { value: "low" },
  });
  expect(screen.queryByText("MFA desativada")).not.toBeInTheDocument();
  fireEvent.click(screen.getByText("Política conforme"));
  expect(
    screen.getByRole("complementary", {
      name: /Inspeção de Política conforme/,
    }),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "Abrir investigação completa" }),
  ).toHaveAttribute("href", "/findings/finding-2");
});

test("findings workbench supports keyboard selection", async () => {
  renderPage();
  const row = (await screen.findByText("MFA desativada")).closest("tr");
  expect(row).not.toBeNull();
  fireEvent.keyDown(row!, { key: "Enter" });
  expect(
    screen.getByRole("complementary", { name: /Inspeção de MFA desativada/ }),
  ).toBeInTheDocument();
});
