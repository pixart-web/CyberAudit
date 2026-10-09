import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { AgentAnswerView } from "../agent-answer";

afterEach(cleanup);

test("shows the facts the answer is grounded on, hides synthetic markers, flags low confidence", () => {
  render(
    <AgentAnswerView
      answer={{
        response: "Síntese determinística baseada em 1 fonte(s) interna(s).",
        facts: [{ source_id: "i1", label: "[DEMO] Incident A", facts: { severity: "high", status: "investigating", simulated: true } }],
        confidence: 0.9,
        limitations: ["Resposta gerada sem modelo externo."],
        required_human_approval: true,
      }}
    />,
  );
  expect(screen.getByText("[DEMO] Incident A")).toBeInTheDocument();
  expect(screen.getByText(/severity: high · status: investigating/)).toBeInTheDocument();
  expect(screen.queryByText(/simulated/)).not.toBeInTheDocument();
  expect(screen.getByText("Confiança: 90%")).toBeInTheDocument();
  expect(screen.getByText("Requer validação humana")).toBeInTheDocument();
  expect(screen.getByText(/sem modelo externo/)).toBeInTheDocument();
});

test("no sources means 0% confidence and an explicit empty state, never invented facts", () => {
  render(<AgentAnswerView answer={{ response: "Não existem fontes internas suficientes.", facts: [], confidence: 0, limitations: ["Sem fontes."] }} />);
  expect(screen.getByText("Confiança: 0%")).toBeInTheDocument();
  expect(screen.getByText("0 fonte(s) interna(s)")).toBeInTheDocument();
  expect(screen.queryByText(/Factos em que/)).not.toBeInTheDocument();
});
