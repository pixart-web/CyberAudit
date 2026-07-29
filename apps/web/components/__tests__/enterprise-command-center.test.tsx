import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { AiAssistant, GrcCommandCenter, SocCommandCenter } from "../enterprise-command-center";

vi.mock("next/navigation", () => ({ usePathname: () => "/soc" }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path === "/soc/dashboard") {
      return { events: 42, open_alerts: 3, open_incidents: 2, critical_alerts: 1 };
    }
    if (path === "/grc/dashboard") {
      return {
        open_risks: 4,
        average_residual_risk: 6.5,
        controls: 12,
        implemented_controls: 8,
        control_coverage: 67,
      };
    }
    return {
      id: "request-1",
      response: "Síntese baseada em fontes internas.",
      facts: [{ source_id: "risk-1", label: "Risco de identidade" }],
      inferences: [],
      citations: [{ source_id: "risk-1", source_type: "risk" }],
      confidence: 0.8,
      limitations: ["Revisão humana obrigatória."],
      action_executed: false,
    };
  },
}));

function wrapper(component: React.ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>,
  );
}

test("renders live SOC metrics and defensive guardrail", async () => {
  wrapper(<SocCommandCenter />);
  expect(screen.getByRole("heading", { name: "SOC Command Center" })).toBeInTheDocument();
  expect(await screen.findByText("42")).toBeInTheDocument();
  expect(screen.getByText("Defensivo e passivo")).toBeInTheDocument();
});

test("renders unified GRC coverage", async () => {
  wrapper(<GrcCommandCenter />);
  expect(
    screen.getByRole("heading", { name: "Governance, Risk & Compliance" }),
  ).toBeInTheDocument();
  expect(await screen.findByText("Controlos unificados")).toBeInTheDocument();
  expect(await screen.findByText("67")).toBeInTheDocument();
});

test("AI assistant separates facts, sources and limitations", async () => {
  wrapper(<AiAssistant />);
  fireEvent.change(screen.getByLabelText("Pergunta"), {
    target: { value: "Explica o risco de identidade" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Analisar fontes" }));
  await waitFor(() =>
    expect(screen.getByText("Síntese baseada em fontes internas.")).toBeInTheDocument(),
  );
  expect(screen.getByText("Risco de identidade")).toBeInTheDocument();
  expect(screen.getByText("risk:risk-1")).toBeInTheDocument();
  expect(screen.getByText("Revisão humana obrigatória.")).toBeInTheDocument();
  expect(screen.getByText(/Não executa ações/)).toBeInTheDocument();
});
