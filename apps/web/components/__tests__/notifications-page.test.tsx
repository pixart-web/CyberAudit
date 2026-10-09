import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import NotificationsPage from "@/app/notifications/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/notifications" }));
const posts: string[] = [];
vi.mock("@/lib/api", () => ({
  api: async (path: string, init?: RequestInit) => {
    if (init?.method === "POST") { posts.push(path); return {}; }
    if (path === "/notifications") return { items: [{ id: "n1", event_type: "job.failed", severity: "error", title: "Avaliação falhou", message: "adapter error", resource_type: "scan_job", resource_id: "j1", created_at: "2026-10-08T10:00:00Z", read_at: null }] };
    return { items: [] };
  },
}));

test("shows real notifications, links to the resource and marks as read", async () => {
  render(<QueryClientProvider client={new QueryClient()}><NotificationsPage /></QueryClientProvider>);
  expect(await screen.findByText("Avaliação falhou")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Abrir" })).toHaveAttribute("href", "/jobs/j1");
  fireEvent.click(screen.getByRole("button", { name: "Marcar como lida" }));
  await waitFor(() => expect(posts).toContain("/notifications/n1/read"));
});
