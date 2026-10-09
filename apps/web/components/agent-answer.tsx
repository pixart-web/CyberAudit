"use client";

import { Badge } from "@cyberaudit/ui";

export type AgentFact = { source_id: string; label: string; facts: Record<string, unknown> };
export type AgentAnswerData = {
  response: string;
  citations?: { node_id?: string; source_id?: string }[];
  facts?: AgentFact[];
  confidence: number;
  limitations: string[];
  required_human_approval?: boolean;
};

const hidden = new Set(["simulated", "demo_data"]);

/** Shared, honest rendering of a grounded agent answer: facts used, confidence, limitations. */
export function AgentAnswerView({ answer }: { answer: AgentAnswerData }) {
  const facts = answer.facts ?? [];
  return (
    <div className="space-y-3 rounded-lg border border-border bg-surface p-4 text-sm" aria-live="polite">
      <p>{answer.response}</p>
      {facts.length > 0 && (
        <div>
          <p className="mb-1 text-xs font-semibold text-muted">Factos em que a resposta se baseia</p>
          <ul className="space-y-1">
            {facts.map((fact) => (
              <li key={fact.source_id} className="text-xs">
                <b>{fact.label}</b>
                <span className="text-muted">
                  {" — "}
                  {Object.entries(fact.facts)
                    .filter(([key]) => !hidden.has(key))
                    .map(([key, value]) => `${key}: ${String(value)}`)
                    .join(" · ")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
        <Badge tone={answer.confidence >= 0.7 ? "success" : answer.confidence > 0 ? "warning" : "danger"}>
          Confiança: {Math.round(answer.confidence * 100)}%
        </Badge>
        {answer.required_human_approval && <Badge tone="warning">Requer validação humana</Badge>}
        <span>{facts.length} fonte(s) interna(s)</span>
      </div>
      {answer.limitations.length > 0 && (
        <ul className="list-disc pl-4 text-xs text-muted">
          {answer.limitations.map((limitation, index) => (
            <li key={index}>{limitation}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
