import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { expect, test, vi } from "vitest";
import { ResourcePage } from "../resource-page";

vi.mock("next/navigation", () => ({ usePathname: () => "/clients" }));
vi.mock("@/lib/api", () => ({ api: async () => ({ items: [], total: 0, page: 1, page_size: 20 }) }));

test("renders an accessible empty resource state", async () => {
  render(<QueryClientProvider client={new QueryClient()}><ResourcePage title="Clientes" endpoint="/clients" columns={[["name","Nome"]]}/></QueryClientProvider>);
  expect(screen.getByRole("heading", { name: "Clientes" })).toBeInTheDocument();
  expect(await screen.findByText("Ainda não existem registos.")).toBeInTheDocument();
});
