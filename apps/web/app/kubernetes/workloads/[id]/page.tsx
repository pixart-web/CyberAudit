"use client";

import { Badge, Card, ErrorState, LoadingState } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type KubernetesObject = {
  id: string;
  object_type: string;
  namespace: string;
  name: string;
  privileged: boolean;
  public_exposure: boolean;
  risk_score: number;
  configuration_hash: string;
};
type KubernetesCluster = { id: string; name: string; provider: string; version: string | null } | null;
type WorkloadDetail = { workload: KubernetesObject; cluster: KubernetesCluster };

export default function KubernetesWorkloadDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["kubernetes-workload", id],
    queryFn: () => api<WorkloadDetail>(`/kubernetes/workloads/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Workload Kubernetes"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Workload Kubernetes">
        <ErrorState title="Workload não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { workload, cluster } = data;

  return (
    <Shell title={workload.name} eyebrow={`Kubernetes · ${workload.namespace} · ${workload.object_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        {workload.privileged && <Badge tone="danger">Privilegiado</Badge>}
        {workload.public_exposure && <Badge tone="warning">Exposição pública</Badge>}
        <Badge tone="info">Risco: {workload.risk_score.toFixed(0)}</Badge>
      </div>
      <Card className="p-6">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <Row label="Namespace" value={workload.namespace} />
          <Row label="Tipo" value={workload.object_type} />
          <Row label="Hash de configuração" value={workload.configuration_hash} />
        </dl>
      </Card>
      <Card className="mt-4 p-6">
        <h2 className="mb-3 font-semibold">Cluster</h2>
        {cluster ? (
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Row label="Nome" value={cluster.name} />
            <Row label="Provider" value={cluster.provider} />
            <Row label="Versão" value={cluster.version ?? "—"} />
          </dl>
        ) : (
          <p className="text-sm text-muted">Cluster de origem não disponível.</p>
        )}
      </Card>
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold text-muted">{label}</dt>
      <dd className="mt-1 break-all">{value}</dd>
    </div>
  );
}
