import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { GlobalSearch } from "../global-search";

afterEach(cleanup);

vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path.startsWith("/findings")) return { items: [{ id: "f-1", title: "Missing MFA" }] };
    if (path.startsWith("/incidents")) return { items: [{ id: "i-1", title: "Suspicious login" }] };
    if (path.startsWith("/engagements")) return { items: [] };
    return { items: [] };
  },
}));

test("global search shows grouped, authorized results after typing", async () => {
  render(<GlobalSearch />);
  const input = screen.getByLabelText("Pesquisar em CyberAudit");
  fireEvent.focus(input);
  fireEvent.change(input, { target: { value: "login" } });

  await waitFor(() => expect(screen.getByText("Missing MFA")).toBeInTheDocument());
  expect(screen.getByText("Suspicious login")).toBeInTheDocument();
  expect(screen.getByText("Findings")).toBeInTheDocument();
  expect(screen.getByText("Incidentes")).toBeInTheDocument();
});

test("global search does not query below the two-character threshold", async () => {
  render(<GlobalSearch />);
  const input = screen.getByLabelText("Pesquisar em CyberAudit");
  fireEvent.focus(input);
  fireEvent.change(input, { target: { value: "a" } });
  await new Promise((resolve) => setTimeout(resolve, 300));
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
});
