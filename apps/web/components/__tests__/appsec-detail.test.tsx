import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { Entity360 } from "../appsec-detail";

vi.mock("next/navigation", () => ({ usePathname: () => "/applications/app-1" }));
vi.mock("@/lib/api", () => ({
  api: async () => ({
    id: "app-1",
    name: "Synthetic Portal",
    internet_exposed: false,
    appsec_score: 82,
  }),
}));

test("renders an Application 360 summary", async () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Entity360
        title="Application 360"
        endpoint="/applications/app-1"
        fields={[
          ["name", "Aplicação"],
          ["internet_exposed", "Internet"],
          ["appsec_score", "AppSec score"],
        ]}
      />
    </QueryClientProvider>,
  );
  expect(await screen.findByText("Synthetic Portal")).toBeInTheDocument();
  expect(screen.getByText("82")).toBeInTheDocument();
  expect(screen.getByText("Não")).toBeInTheDocument();
});
