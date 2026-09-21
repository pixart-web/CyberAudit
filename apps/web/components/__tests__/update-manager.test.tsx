import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { UpdateManager } from "../update-manager";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/update-manager" }));

let lastBody: Record<string, unknown> | null = null;

vi.mock("@/lib/api", () => ({
  api: async (path: string, init?: RequestInit) => {
    if (path === "/updates/validate") {
      lastBody = JSON.parse(String(init?.body));
      return {
        accepted: false,
        bundle_id: "knowledge-pack-2026-09",
        bundle_type: "knowledge_pack",
        reasons: ["Signature does not match any trusted key"],
        checked_at: "2026-09-20T00:00:00Z",
      };
    }
    return {};
  },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("update manager never applies a bundle -- only reports validation results", async () => {
  wrapper(<UpdateManager />);
  expect(screen.getByRole("button", { name: "Validar bundle" })).toBeDisabled();

  const manifestFile = new File(['{"bundle_id":"x"}'], "manifest.json", { type: "application/json" });
  const signatureFile = new File([new Uint8Array([1, 2, 3])], "manifest.sig");

  fireEvent.change(screen.getByLabelText("Manifesto (JSON)"), { target: { files: [manifestFile] } });
  fireEvent.change(screen.getByLabelText("Assinatura Ed25519"), { target: { files: [signatureFile] } });

  await waitFor(() => expect(screen.getByRole("button", { name: "Validar bundle" })).not.toBeDisabled());
  fireEvent.click(screen.getByRole("button", { name: "Validar bundle" }));

  expect(await screen.findByText("knowledge-pack-2026-09", { exact: false })).toBeInTheDocument();
  expect(screen.getByText("Signature does not match any trusted key", { exact: false })).toBeInTheDocument();
  expect(lastBody?.manifest_json).toBe('{"bundle_id":"x"}');
  expect(typeof lastBody?.signature_base64).toBe("string");
  expect((lastBody?.signature_base64 as string).length).toBeGreaterThan(0);
});
