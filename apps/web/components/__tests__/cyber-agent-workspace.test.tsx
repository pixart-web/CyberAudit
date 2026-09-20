import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { CyberAgentWorkspace } from "../cyber-agent-workspace";

vi.mock("next/navigation", () => ({ usePathname: () => "/cyber-agents" }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path === "/agents") {
      return {
        items: [
          {
            code: "security_analyst",
            name: "Security Analyst Agent",
            mission: "Explain findings, exposure and attack surface using only recorded evidence.",
            knowledge_scopes: ["finding", "asset", "risk"],
            allowed_tools: ["get_finding"],
          },
        ],
      };
    }
    if (path === "/ai-runtime/health") {
      return {
        backend: "disabled",
        healthy: false,
        message: "Local AI runtime is disabled",
        sovereign_default: true,
      };
    }
    if (path === "/ai-runtime/hardware") {
      return {
        os_name: "Linux",
        cpu_cores: 8,
        ram_total_mb: 16384,
        gpu_vendor: null,
        profile: "standard",
      };
    }
    return {
      agent_code: "security_analyst",
      correlation_id: "corr-1",
      response: "Síntese determinística baseada em 1 fonte(s) interna(s).",
      facts: [{ source_id: "risk-1", label: "Acesso sem MFA" }],
      citations: [{ source_id: "risk-1", source_type: "risk" }],
      confidence: 0.9,
      limitations: ["Resposta gerada sem modelo externo."],
      reproducibility_key: "abc",
      required_human_approval: false,
    };
  },
}));

function wrapper(component: React.ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>,
  );
}

test("cyber agent workspace shows the sovereign runtime status and answers a question", async () => {
  wrapper(<CyberAgentWorkspace />);
  expect(screen.getByRole("heading", { name: "Cyber AI Workspace" })).toBeInTheDocument();
  expect(await screen.findByText("disabled")).toBeInTheDocument();
  expect(await screen.findByText("standard")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Pergunta"), {
    target: { value: "Explica os riscos conhecidos" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Perguntar ao agente" }));

  await waitFor(() =>
    expect(
      screen.getByText("Síntese determinística baseada em 1 fonte(s) interna(s)."),
    ).toBeInTheDocument(),
  );
  expect(screen.getByText("Acesso sem MFA")).toBeInTheDocument();
  expect(screen.getByText("risk:risk-1")).toBeInTheDocument();
  expect(screen.getByText("Resposta gerada sem modelo externo.")).toBeInTheDocument();
});
