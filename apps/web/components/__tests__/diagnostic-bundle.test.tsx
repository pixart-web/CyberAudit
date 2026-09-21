import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { DiagnosticBundlePanel } from "../diagnostic-bundle";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/diagnostics" }));

const bundle = {
  generated_at: "2026-09-20T00:00:00Z",
  app_version: "0.1.0",
  organization_id: "org-1",
  configuration: { environment: "development" },
  health: { hardware_profile: "standard" },
  ai_runtime: { backend: "disabled", healthy: false, installed_models: 0 },
  counts: { findings: 3, assets: 2, incidents: 0, controls: 1 },
  disclosure: "This bundle never contains finding, evidence, or report content.",
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path === "/diagnostics/bundle") return bundle;
    return {};
  },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

beforeEach(() => {
  global.URL.createObjectURL = vi.fn(() => "blob:mock");
  global.URL.revokeObjectURL = vi.fn();
});

test("diagnostic bundle panel generates and offers a download, never fabricating tenant data", async () => {
  wrapper(<DiagnosticBundlePanel />);

  fireEvent.click(screen.getByRole("button", { name: /Gerar e descarregar/ }));

  await waitFor(() => expect(screen.getByText("3")).toBeInTheDocument());
  expect(screen.getByText("findings")).toBeInTheDocument();
  expect(screen.getByText(/never contains finding/)).toBeInTheDocument();
  expect(URL.createObjectURL).toHaveBeenCalled();
});
