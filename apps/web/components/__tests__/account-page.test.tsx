import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import AccountPage from "@/app/account/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/account", useRouter: () => ({ push: vi.fn() }) }));
let forced = true;
vi.mock("@/lib/api", () => ({
  ApiError: class extends Error {},
  api: async (path: string) =>
    path === "/auth/me"
      ? { name: "Maria", email: "m@x.example.com", roles: ["Auditor"], must_change_password: forced, mfa_enabled: false, last_login_at: null }
      : { items: [] },
}));
const wrap = () => render(<QueryClientProvider client={new QueryClient()}><AccountPage /></QueryClientProvider>);

test("forces the change with an explicit alert and exposes the change form", async () => {
  forced = true;
  wrap();
  expect(await screen.findByRole("alert")).toHaveTextContent(/nova palavra-passe/);
  expect(screen.getByLabelText(/Palavra-passe atual/)).toBeInTheDocument();
  expect(screen.getByLabelText(/Nova palavra-passe/)).toHaveAttribute("autocomplete", "new-password");
});

test("no alert when no change is required", async () => {
  forced = false;
  wrap();
  expect(await screen.findByText("Maria")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
