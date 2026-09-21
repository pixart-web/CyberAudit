import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { EvidenceLinksPanel } from "../evidence-links-panel";

afterEach(cleanup);

let lastPost: Record<string, unknown> | null = null;

vi.mock("@/lib/api", () => ({
  api: async (path: string, init?: RequestInit) => {
    if (path.startsWith("/grc/evidence-links") && (!init || init.method === undefined)) {
      return {
        items: [
          {
            id: "link-1",
            evidence_id: "evidence-1",
            purpose: "chain of custody",
            valid_until: null,
            verified_at: "2026-09-20T00:00:00Z",
            evidence: {
              id: "evidence-1",
              title: "Auth log export",
              evidence_type: "log",
              sensitivity: "internal",
              redacted: false,
              collected_at: "2026-09-20T00:00:00Z",
            },
          },
        ],
      };
    }
    if (init?.method === "POST") {
      lastPost = JSON.parse(String(init.body));
      return { id: "link-2" };
    }
    return { items: [] };
  },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("EvidenceLinksPanel shows associated evidence and can associate an existing one, never duplicating a record", async () => {
  wrapper(<EvidenceLinksPanel subjectType="incident" subjectId="inc-1" enabled={true} />);

  expect(await screen.findByText("Auth log export")).toBeInTheDocument();
  expect(screen.getByText("Verificado")).toBeInTheDocument();

  fireEvent.change(screen.getByPlaceholderText("ID de evidência existente"), { target: { value: "evidence-2" } });
  fireEvent.change(screen.getByPlaceholderText(/Finalidade/), { target: { value: "root cause" } });
  fireEvent.click(screen.getByRole("button", { name: "Associar" }));

  await waitFor(() => expect(lastPost).not.toBeNull());
  expect(lastPost).toMatchObject({
    evidence_id: "evidence-2",
    subject_type: "incident",
    subject_id: "inc-1",
    purpose: "root cause",
  });
});
