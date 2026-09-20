"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Minus, Plus, RotateCcw } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Node = { id: string; node_type: string; label: string; confidence: number };
type Edge = {
  id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  confidence: number;
  inferred: boolean;
};
type Graph = { nodes: Node[]; edges: Edge[] };

export default function KnowledgeGraphPage() {
  const [zoom, setZoom] = useState(1);
  const { data, error } = useQuery({
    queryKey: ["knowledge-graph"],
    queryFn: () => api<Graph>("/knowledge-graph"),
  });

  return (
    <Shell title="Knowledge Graph" eyebrow="Intelligence">
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-4">
          <Badge tone="info">PostgreSQL knowledge repository</Badge>
          <span className="text-xs text-muted">{data?.nodes.length ?? 0} nós · {data?.edges.length ?? 0} relações</span>
          <div className="ml-auto flex gap-2">
            <button className="icon-button" aria-label="Reduzir zoom" onClick={() => setZoom(Math.max(0.7, zoom - 0.1))}>
              <Minus size={16} />
            </button>
            <button className="icon-button" aria-label="Repor zoom" onClick={() => setZoom(1)}>
              <RotateCcw size={16} />
            </button>
            <button className="icon-button" aria-label="Aumentar zoom" onClick={() => setZoom(Math.min(1.4, zoom + 0.1))}>
              <Plus size={16} />
            </button>
          </div>
        </div>
        {error ? (
          <p className="p-8 text-red-300">Não foi possível construir o grafo.</p>
        ) : (
          <div className="graph-canvas min-h-[560px] overflow-auto p-8">
            <div
              className="mx-auto grid max-w-5xl grid-cols-2 gap-14 md:grid-cols-3 xl:grid-cols-4"
              style={{ transform: `scale(${zoom})`, transformOrigin: "top center" }}
            >
              {data?.nodes.map((node, index) => (
                <Link
                  href={`/knowledge-graph/${node.id}`}
                  key={node.id}
                  className={`graph-node relative rounded-xl border border-border p-4 text-center ${index % 3 === 1 ? "md:translate-y-12" : ""}`}
                >
                  <span className="mx-auto mb-3 block h-3 w-3 rounded-full bg-primary" />
                  <b className="block truncate text-sm">{node.label}</b>
                  <small className="text-muted">{node.node_type} · confiança {Math.round(node.confidence * 100)}%</small>
                </Link>
              ))}
            </div>
            {data && data.edges.length > 0 && (
              <div className="mx-auto mt-24 grid max-w-5xl gap-2 md:grid-cols-2">
                {data.edges.map((edge) => (
                  <div key={edge.id} className="flex items-center gap-2 rounded-lg border border-border/80 bg-card/90 px-3 py-2 text-xs">
                    <span className="truncate">{data.nodes.find((node) => node.id === edge.source_node_id)?.label ?? edge.source_node_id}</span>
                    <span className="text-cyan">→ {edge.edge_type} →</span>
                    <span className="truncate">{data.nodes.find((node) => node.id === edge.target_node_id)?.label ?? edge.target_node_id}</span>
                    {edge.inferred && <Badge tone="warning">inferido</Badge>}
                    <span className="ml-auto text-muted">{Math.round(edge.confidence * 100)}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="border-t border-border p-4 text-xs text-muted">
          Nós e relações refletem factos indexados a partir de dados já registados (findings, ativos, avaliações);
          relações inferidas são explicitamente marcadas e nunca apresentadas como facto confirmado.
        </div>
      </Card>
    </Shell>
  );
}
