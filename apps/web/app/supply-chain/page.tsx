"use client";

import { Card, Badge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Boxes, GitBranch } from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type PageData = { items: { id: string; component_count: number; dependency_count: number; document_hash: string; validated: boolean }[] };

export default function Page() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["supply-chain"],
    queryFn: () => api<PageData>("/sboms?page_size=100"),
  });
  return <Shell title="Supply Chain Graph" eyebrow="Application Security">
    <Card className="p-5">
      <div className="mb-5 flex items-center justify-between">
        <div><h2 className="font-semibold">Mapa de SBOMs e dependências</h2><p className="mt-1 text-sm text-muted">Visão agregada, sem instalar ou executar componentes.</p></div>
        <GitBranch className="text-primary" />
      </div>
      {error ? <p className="text-red-300">Não foi possível carregar a cadeia de fornecimento.</p> :
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {data?.items.map((sbom) => <div key={sbom.id} className="rounded-xl border border-border bg-background/60 p-4">
            <div className="mb-3 flex items-center gap-2"><Boxes size={16} className="text-cyan"/><span className="font-medium">SBOM {sbom.document_hash.slice(0, 10)}…</span></div>
            <p className="text-sm text-muted">{sbom.component_count} componentes · {sbom.dependency_count} relações</p>
            <Badge className="mt-3" tone={sbom.validated ? "success" : "warning"}>{sbom.validated ? "Validado" : "Requer validação"}</Badge>
          </div>)}
          {!isLoading && !data?.items.length && <p className="text-muted">Ainda não existem SBOMs.</p>}
          {isLoading && <p className="text-muted">A carregar…</p>}
        </div>}
    </Card>
  </Shell>;
}
