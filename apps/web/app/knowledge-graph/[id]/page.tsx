"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Node = {
  id: string;
  node_type: string;
  source_id: string;
  label: string;
  facts: Record<string, unknown>;
  source_references: string[];
  confidence: number;
  indexed_at: string;
};
type Edge = { id: string; source_node_id: string; target_node_id: string; edge_type: string; confidence: number; inferred: boolean };
type NodeDetail = { node: Node; outgoing_edges: Edge[]; incoming_edges: Edge[] };
type AgentAnswer = {
  response: string;
  citations: { node_id: string; source_id: string }[];
  confidence: number;
  limitations: string[];
};

export default function KnowledgeNodeDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["knowledge-node", id],
    queryFn: () => api<NodeDetail>(`/knowledge-nodes/${id}`),
    retry: false,
  });

  const explain = useMutation({
    mutationFn: () =>
      api<AgentAnswer>("/agents/knowledge_analyst/ask", {
        method: "POST",
        body: JSON.stringify({
          question: "Explica o que se sabe sobre este nó e as relações mais relevantes.",
          source_ids: data ? [data.node.source_id] : [],
        }),
      }),
  });

  if (isLoading) return <Shell title="Nó do Knowledge Graph"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Nó do Knowledge Graph">
        <ErrorState title="Nó não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { node, outgoing_edges, incoming_edges } = data;

  return (
    <Shell title={node.label} eyebrow={`Knowledge Graph · ${node.node_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="info">Confiança: {(node.confidence * 100).toFixed(0)}%</Badge>
        <Badge tone="neutral">Indexado: {new Date(node.indexed_at).toLocaleString("pt-PT")}</Badge>
        <button
          type="button"
          className="ml-auto inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50"
          onClick={() => explain.mutate()}
          disabled={explain.isPending}
        >
          <BrainCircuit size={16} className="text-primary" />
          {explain.isPending ? "A analisar…" : "Explicar este nó"}
        </button>
      </div>
      {explain.data && (
        <Card className="mb-4 p-5 text-sm">
          <p>{explain.data.response}</p>
          {explain.data.citations.length > 0 && (
            <p className="mt-2 text-xs text-muted">
              Fontes: {explain.data.citations.map((citation) => citation.source_id).join(", ")}
            </p>
          )}
          <p className="mt-1 text-xs text-muted">Confiança: {(explain.data.confidence * 100).toFixed(0)}%</p>
        </Card>
      )}
      <Card className="p-6">
        <h2 className="mb-3 font-semibold">Factos registados</h2>
        <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-background p-4 text-xs text-muted">
          {JSON.stringify(node.facts, null, 2)}
        </pre>
        <p className="mt-2 text-xs text-muted">Apresentado como texto inerte. HTML, JavaScript e SVG nunca são renderizados.</p>
      </Card>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Relações de saída</h2>
          {outgoing_edges.length === 0 && <EmptyState title="Sem relações de saída." />}
          <ul className="space-y-2">
            {outgoing_edges.map((edge) => (
              <li key={edge.id}>
                <Link href={`/knowledge-graph/${edge.target_node_id}`} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm hover:border-primary/40">
                  <span>{edge.edge_type}</span>
                  {edge.inferred && <Badge tone="warning">inferido</Badge>}
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Relações de entrada</h2>
          {incoming_edges.length === 0 && <EmptyState title="Sem relações de entrada." />}
          <ul className="space-y-2">
            {incoming_edges.map((edge) => (
              <li key={edge.id}>
                <Link href={`/knowledge-graph/${edge.source_node_id}`} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm hover:border-primary/40">
                  <span>{edge.edge_type}</span>
                  {edge.inferred && <Badge tone="warning">inferido</Badge>}
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </Shell>
  );
}
