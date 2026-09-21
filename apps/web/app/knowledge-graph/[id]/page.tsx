"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
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
type Edge = {
  id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  confidence: number;
  inferred: boolean;
  other_node: { label: string; source_id: string } | null;
};
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

  const [explainedEdgeId, setExplainedEdgeId] = useState<string | null>(null);
  const explainRelation = useMutation({
    mutationFn: (edge: Edge) =>
      api<AgentAnswer>("/agents/knowledge_analyst/ask", {
        method: "POST",
        body: JSON.stringify({
          question: `Explica a relação "${edge.edge_type}" entre estas entidades com base na evidência registada.`,
          source_ids: [data?.node.source_id, edge.other_node?.source_id].filter(Boolean),
        }),
      }),
    onSuccess: (_result, edge) => setExplainedEdgeId(edge.id),
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
              <RelationRow
                key={edge.id}
                edge={edge}
                targetId={edge.target_node_id}
                explainRelation={explainRelation}
                explainedEdgeId={explainedEdgeId}
              />
            ))}
          </ul>
        </Card>
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Relações de entrada</h2>
          {incoming_edges.length === 0 && <EmptyState title="Sem relações de entrada." />}
          <ul className="space-y-2">
            {incoming_edges.map((edge) => (
              <RelationRow
                key={edge.id}
                edge={edge}
                targetId={edge.source_node_id}
                explainRelation={explainRelation}
                explainedEdgeId={explainedEdgeId}
              />
            ))}
          </ul>
        </Card>
      </div>
    </Shell>
  );
}

function RelationRow({
  edge,
  targetId,
  explainRelation,
  explainedEdgeId,
}: {
  edge: Edge;
  targetId: string;
  explainRelation: ReturnType<typeof useMutation<AgentAnswer, Error, Edge>>;
  explainedEdgeId: string | null;
}) {
  const isPending = explainRelation.isPending && explainRelation.variables?.id === edge.id;
  return (
    <li>
      <div className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
        <Link href={`/knowledge-graph/${targetId}`} className="hover:text-primary">
          {edge.edge_type} {edge.other_node ? `→ ${edge.other_node.label}` : ""}
        </Link>
        <div className="flex items-center gap-2">
          {edge.inferred && <Badge tone="warning">inferido</Badge>}
          <button
            type="button"
            aria-label={`Explicar relação ${edge.edge_type}`}
            className="rounded-md border border-border px-2 py-1 text-xs hover:border-primary disabled:opacity-50"
            onClick={() => explainRelation.mutate(edge)}
            disabled={isPending}
          >
            <BrainCircuit size={12} className="mr-1 inline text-primary" />
            {isPending ? "A explicar…" : "Explicar"}
          </button>
        </div>
      </div>
      {explainedEdgeId === edge.id && explainRelation.data && (
        <div className="mt-2 rounded-lg border border-border bg-surface p-3 text-xs">
          <p>{explainRelation.data.response}</p>
          <p className="mt-1 text-muted">Confiança: {(explainRelation.data.confidence * 100).toFixed(0)}%</p>
        </div>
      )}
    </li>
  );
}
