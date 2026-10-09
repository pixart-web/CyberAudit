import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import LoginPage from "@/app/login/page";
import { Shell } from "../shell";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/users", useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path === "/auth/me") return { name: "Tiago Santos", email: "t@x.example.com", roles: ["Platform Administrator"] };
    if (path.startsWith("/organizations")) return { items: [{ name: "Pixart Security" }] };
    return { items: [] };
  },
}));

const wrap = (node: React.ReactNode) => render(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);

test("shell shows the authenticated user and organization, never hardcoded demo identity", async () => {
  wrap(<Shell title="Utilizadores">x</Shell>);
  expect(await screen.findByText("Tiago Santos")).toBeInTheDocument();
  expect(screen.getByText("Platform Administrator")).toBeInTheDocument();
  expect((await screen.findAllByText("Pixart Security")).length).toBeGreaterThan(0);
  expect(screen.queryByText(/ACME-2026|CyberAudit Demo|Modo Cliente/)).not.toBeInTheDocument();
});

test("login form never ships prefilled credentials", () => {
  wrap(<LoginPage />);
  const email = screen.getByLabelText(/email/i, { selector: "input" }) as HTMLInputElement;
  expect(email.value).toBe("");
  for (const input of document.querySelectorAll("input")) {
    expect((input as HTMLInputElement).value).not.toMatch(/ChangeMe|admin@cyberaudit\.local|cyberaudit-demo/);
  }
});
