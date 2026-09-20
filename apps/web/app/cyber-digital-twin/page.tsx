"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Cloud, Fingerprint, Network, Server } from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Graph = { nodes: { id: string; type: string; label: string; risk?: number }[]; edges: unknown[]; truncated: boolean };

export default function Page() {
  const identity = useQuery({ queryKey: ["twin", "identity"], queryFn: () => api<Graph>("/identity/graph?limit=100") });
  const cloud = useQuery({ queryKey: ["twin", "cloud"], queryFn: () => api<Graph>("/cloud/graph?limit=100") });
  const nodes = [...(identity.data?.nodes ?? []), ...(cloud.data?.nodes ?? [])];
  return <Shell title="Cyber Digital Twin" eyebrow="Enterprise / Knowledge">
    <div className="mb-5 rounded-xl border border-cyan/20 bg-cyan/5 p-4 text-sm text-muted">
      Vista defensiva incremental, limitada a 200 nós. Relações inferidas são apresentadas como hipóteses e requerem validação humana.
    </div>
    <section className="grid gap-4 md:grid-cols-3">
      <Card><p className="text-xs uppercase text-muted">Nós carregados</p><p className="mt-2 text-3xl font-semibold">{nodes.length}</p></Card>
      <Card><p className="text-xs uppercase text-muted">Identidades</p><p className="mt-2 text-3xl font-semibold text-primary">{identity.data?.nodes.length ?? 0}</p></Card>
      <Card><p className="text-xs uppercase text-muted">Cloud</p><p className="mt-2 text-3xl font-semibold text-cyan">{cloud.data?.nodes.length ?? 0}</p></Card>
    </section>
    <Card className="mt-5 overflow-hidden">
      <div className="border-b border-border p-4"><h2 className="font-semibold">Explorador limitado por domínio e risco</h2></div>
      <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
        {nodes.map((node) => {
          const Icon = node.type === "identity" ? Fingerprint : node.type.includes("network") ? Network : node.type.includes("cloud") ? Cloud : Server;
          return <article key={`${node.type}:${node.id}`} className="flex items-center gap-3 rounded-lg border border-border bg-white/[.015] p-3">
            <Icon size={17} className="text-primary"/><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{node.label}</p><p className="text-xs text-muted">{node.type}</p></div>
            <Badge tone={(node.risk ?? 0) >= 70 ? "warning" : "success"}>{node.risk ?? "observado"}</Badge>
          </article>;
        })}
        {!identity.isLoading && !cloud.isLoading && nodes.length === 0 && <p className="p-6 text-sm text-muted">Sem nós disponíveis.</p>}
      </div>
    </Card>
  </Shell>;
}
