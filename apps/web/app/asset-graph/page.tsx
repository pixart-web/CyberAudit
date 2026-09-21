"use client";

import { Badge, Card, EmptyState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { List, Minus, Network as NetworkIcon, Plus, RotateCcw, Search } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Node = {
  id: string;
  label: string;
  type: string;
  criticality: string;
  exposure: string;
  risk_score: number;
  confidence: number;
};
type Edge = { id: string; source: string; target: string; type: string; confidence: number; reviewed: boolean };
type Graph = { nodes: Node[]; edges: Edge[]; limit: number; progressive: boolean };
type AttackPathSummary = { id: string; name: string; severity: string; overall_risk: number };

export default function AssetGraphPage() {
  const [zoom, setZoom] = useState(1);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [exposureFilter, setExposureFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");

  const { data, error } = useQuery({
    queryKey: ["asset-graph"],
    queryFn: () => api<Graph>("/asset-graph?max_nodes=100"),
  });

  const nodeTypes = useMemo(() => Array.from(new Set(data?.nodes.map((node) => node.type) ?? [])), [data]);
  const exposures = useMemo(() => Array.from(new Set(data?.nodes.map((node) => node.exposure) ?? [])), [data]);

  const filteredNodes = useMemo(() => {
    if (!data) return [];
    return data.nodes.filter((node) => {
      if (search && !node.label.toLowerCase().includes(search.toLowerCase())) return false;
      if (typeFilter && node.type !== typeFilter) return false;
      if (exposureFilter && node.exposure !== exposureFilter) return false;
      return true;
    });
  }, [data, search, typeFilter, exposureFilter]);

  const filteredIds = useMemo(() => new Set(filteredNodes.map((node) => node.id)), [filteredNodes]);
  const filteredEdges = useMemo(
    () => data?.edges.filter((edge) => filteredIds.has(edge.source) || filteredIds.has(edge.target)) ?? [],
    [data, filteredIds],
  );

  const selectedNode = data?.nodes.find((node) => node.id === selectedId) ?? null;
  const relatedEdges = data?.edges.filter((edge) => edge.source === selectedId || edge.target === selectedId) ?? [];

  const attackPaths = useQuery({
    queryKey: ["asset-graph-attack-paths", selectedId],
    queryFn: () => api<{ items: AttackPathSummary[] }>(`/attack-paths?asset_id=${selectedId}`),
    enabled: Boolean(selectedId),
  });

  function resetFilters() {
    setSearch("");
    setTypeFilter("");
    setExposureFilter("");
    setZoom(1);
  }

  return (
    <Shell title="Cyber Asset Graph" eyebrow="Asset Intelligence">
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-4">
          <Badge tone="info">PostgreSQL graph repository</Badge>
          <span className="text-xs text-muted">
            {filteredNodes.length}/{data?.nodes.length ?? 0} nós · {filteredEdges.length} relações
          </span>
          <label className="relative">
            <Search size={14} className="absolute left-2 top-2.5 text-muted" />
            <input
              className="field h-8 w-48 pl-7 text-xs"
              placeholder="Procurar por nome…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Procurar nó por nome"
            />
          </label>
          <select
            className="field h-8 w-32 text-xs"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            aria-label="Filtrar por tipo"
          >
            <option value="">Todos os tipos</option>
            {nodeTypes.map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
          <select
            className="field h-8 w-36 text-xs"
            value={exposureFilter}
            onChange={(event) => setExposureFilter(event.target.value)}
            aria-label="Filtrar por exposição"
          >
            <option value="">Toda a exposição</option>
            {exposures.map((exposure) => (
              <option key={exposure} value={exposure}>{exposure}</option>
            ))}
          </select>
          <div className="ml-auto flex gap-2">
            <button
              className="icon-button"
              aria-label={viewMode === "graph" ? "Ver como tabela" : "Ver como grafo"}
              onClick={() => setViewMode(viewMode === "graph" ? "table" : "graph")}
            >
              {viewMode === "graph" ? <List size={16} /> : <NetworkIcon size={16} />}
            </button>
            <button className="icon-button" aria-label="Reduzir zoom" onClick={() => setZoom(Math.max(0.7, zoom - 0.1))}>
              <Minus size={16} />
            </button>
            <button className="icon-button" aria-label="Repor zoom e filtros" onClick={resetFilters}>
              <RotateCcw size={16} />
            </button>
            <button className="icon-button" aria-label="Aumentar zoom" onClick={() => setZoom(Math.min(1.4, zoom + 0.1))}>
              <Plus size={16} />
            </button>
          </div>
        </div>
        {error ? (
          <p className="p-8 text-red-300">Não foi possível construir o grafo.</p>
        ) : viewMode === "table" ? (
          <div className="overflow-x-auto p-4">
            <table className="table">
              <caption className="sr-only">Nós do grafo de ativos com tipo, criticidade, exposição e risco</caption>
              <thead>
                <tr>
                  <th>Nó</th>
                  <th>Tipo</th>
                  <th>Criticidade</th>
                  <th>Exposição</th>
                  <th>Risco</th>
                  <th>Confiança</th>
                </tr>
              </thead>
              <tbody>
                {filteredNodes.map((node) => (
                  <tr key={node.id}>
                    <td>
                      <Link href={`/assets/${node.id}`} className="text-cyan hover:underline">{node.label}</Link>
                    </td>
                    <td>{node.type}</td>
                    <td><SeverityBadge state={node.criticality} /></td>
                    <td>{node.exposure === "internet" ? <Badge tone="danger">internet</Badge> : node.exposure}</td>
                    <td>{node.risk_score.toFixed(0)}</td>
                    <td>{Math.round(node.confidence * 100)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredNodes.length === 0 && <EmptyState title="Sem nós correspondentes aos filtros." />}
          </div>
        ) : (
          <div className="graph-canvas min-h-[560px] overflow-auto p-8">
            {filteredNodes.length === 0 ? (
              <EmptyState title="Sem nós correspondentes aos filtros." />
            ) : (
              <div
                className="mx-auto grid max-w-5xl grid-cols-2 gap-14 md:grid-cols-3 xl:grid-cols-4"
                style={{ transform: `scale(${zoom})`, transformOrigin: "top center" }}
              >
                {filteredNodes.map((node, index) => (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => setSelectedId(node.id)}
                    aria-label={`Selecionar nó ${node.label}`}
                    className={`graph-node relative rounded-xl border p-4 text-center ${node.exposure === "internet" ? "border-critical/40" : "border-border"} ${node.id === selectedId ? "ring-2 ring-primary" : ""} ${index % 3 === 1 ? "md:translate-y-12" : ""}`}
                  >
                    <span className={`mx-auto mb-3 block h-3 w-3 rounded-full ${node.risk_score >= 80 ? "bg-critical" : node.risk_score >= 60 ? "bg-high" : "bg-primary"}`} />
                    <b className="block truncate text-sm">{node.label}</b>
                    <small className="text-muted">{node.type} · risco {node.risk_score.toFixed(0)}</small>
                  </button>
                ))}
              </div>
            )}
            {filteredEdges.length > 0 && (
              <div className="mx-auto mt-24 grid max-w-5xl gap-2 md:grid-cols-2">
                {filteredEdges.map((edge) => (
                  <div key={edge.id} className="flex items-center gap-2 rounded-lg border border-border/80 bg-card/90 px-3 py-2 text-xs">
                    <span className="truncate">{data?.nodes.find((node) => node.id === edge.source)?.label ?? edge.source}</span>
                    <span className="text-cyan">→ {edge.type} →</span>
                    <span className="truncate">{data?.nodes.find((node) => node.id === edge.target)?.label ?? edge.target}</span>
                    {!edge.reviewed && <Badge tone="warning">não revisto</Badge>}
                    <span className="ml-auto text-muted">{Math.round(edge.confidence * 100)}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="border-t border-border p-4 text-xs text-muted">
          <p className="mb-2">
            <span className="mr-3"><span className="mr-1 inline-block h-2 w-2 rounded-full bg-critical align-middle" /> risco ≥ 80</span>
            <span className="mr-3"><span className="mr-1 inline-block h-2 w-2 rounded-full bg-high align-middle" /> risco ≥ 60</span>
            <span className="mr-3"><span className="mr-1 inline-block h-2 w-2 rounded-full bg-primary align-middle" /> risco &lt; 60</span>
            <span className="border-l-2 border-critical/40 pl-2">borda vermelha = exposto à internet</span>
          </p>
          As ligações representam relações observadas ou inferidas; não representam exploração.
          {data && data.nodes.length >= data.limit && " Vista limitada progressivamente — refine a pesquisa para ver mais nós."}
        </div>
      </Card>

      {selectedNode && (
        <Card className="mt-4 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-semibold">{selectedNode.label}</h2>
            <button className="text-xs text-muted hover:text-foreground" onClick={() => setSelectedId(null)}>
              Fechar
            </button>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <p className="mb-2 text-xs font-semibold text-muted">Detalhes do nó</p>
              <dl className="space-y-1 text-sm">
                <div className="flex justify-between"><dt className="text-muted">Tipo</dt><dd>{selectedNode.type}</dd></div>
                <div className="flex justify-between"><dt className="text-muted">Criticidade</dt><dd><SeverityBadge state={selectedNode.criticality} /></dd></div>
                <div className="flex justify-between"><dt className="text-muted">Exposição</dt><dd>{selectedNode.exposure}</dd></div>
                <div className="flex justify-between"><dt className="text-muted">Risco</dt><dd>{selectedNode.risk_score.toFixed(1)}</dd></div>
                <div className="flex justify-between"><dt className="text-muted">Confiança</dt><dd>{Math.round(selectedNode.confidence * 100)}%</dd></div>
              </dl>
              <Link href={`/assets/${selectedNode.id}`} className="mt-3 inline-block text-sm text-cyan hover:underline">
                Ver ativo completo
              </Link>
            </div>
            <div>
              <p className="mb-2 text-xs font-semibold text-muted">Relações ({relatedEdges.length})</p>
              {relatedEdges.length === 0 && <p className="text-sm text-muted">Sem relações registadas.</p>}
              <ul className="space-y-1 text-sm">
                {relatedEdges.map((edge) => {
                  const otherId = edge.source === selectedId ? edge.target : edge.source;
                  const other = data?.nodes.find((node) => node.id === otherId);
                  return (
                    <li key={edge.id} className="truncate">
                      {edge.type} → {other?.label ?? otherId}
                    </li>
                  );
                })}
              </ul>
            </div>
            <div>
              <p className="mb-2 text-xs font-semibold text-muted">Attack Paths envolvendo este ativo</p>
              {attackPaths.data?.items.length === 0 && <p className="text-sm text-muted">Nenhum identificado.</p>}
              <ul className="space-y-1 text-sm">
                {attackPaths.data?.items.map((path) => (
                  <li key={path.id}>
                    <Link href={`/attack-paths/${path.id}`} className="text-cyan hover:underline">{path.name}</Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Card>
      )}
    </Shell>
  );
}
