"use client";

import { Badge, Button, Card, EmptyState, LoadingState, ErrorState } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Hunt = {
  id: string;
  name: string;
  hypothesis: string;
  query: Record<string, string>;
  status: string;
  time_from: string;
  time_until: string;
  result_count: number;
  findings: { event_id: string; summary: string; occurred_at: string }[];
};

export default function HuntDetail() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const { data, error, isLoading } = useQuery({
    queryKey: ["hunt", id],
    queryFn: () => api<Hunt>(`/hunts/${id}`),
    retry: false,
  });

  const execute = useMutation({
    mutationFn: () => api<Hunt>(`/hunts/${id}/execute`, { method: "POST" }),
    onSuccess: (result) => queryClient.setQueryData(["hunt", id], result),
  });

  if (isLoading) return <Shell title="Threat Hunt"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Threat Hunt">
        <ErrorState title="Hunt não encontrado ou sem autorização." />
      </Shell>
    );
  }

  return (
    <Shell title={data.name} eyebrow="Threat Hunting">
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="neutral">{data.status}</Badge>
        <Badge tone="info">
          {new Date(data.time_from).toLocaleDateString("pt-PT")} — {new Date(data.time_until).toLocaleDateString("pt-PT")}
        </Badge>
        <Button className="ml-auto gap-2" onClick={() => execute.mutate()} disabled={execute.isPending}>
          <Play size={15} />
          {execute.isPending ? "A executar…" : "Executar hunt"}
        </Button>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Hipótese</h2>
          <p className="text-sm">{data.hypothesis}</p>
          <p className="mb-2 mt-5 text-xs font-semibold text-muted">Filtro declarativo (equality, sem eval)</p>
          <dl className="space-y-2 text-sm">
            {Object.entries(data.query).map(([field, value]) => (
              <div key={field} className="flex justify-between rounded border border-border p-2">
                <dt className="text-muted">{field}</dt>
                <dd className="font-mono">{value}</dd>
              </div>
            ))}
          </dl>
        </Card>
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Resultados ({data.result_count})</h2>
          {data.findings.length === 0 && (
            <EmptyState
              title="Ainda não foi executado, ou não há eventos correspondentes."
              description='Use "Executar hunt" para correr o filtro contra os eventos registados na janela temporal definida.'
            />
          )}
          <ul className="space-y-2">
            {data.findings.map((finding) => (
              <li key={finding.event_id}>
                <Link
                  href={`/security-events/${finding.event_id}`}
                  className="block rounded-lg border border-border p-3 text-sm hover:border-primary/40"
                >
                  <p>{finding.summary}</p>
                  <p className="mt-1 text-xs text-muted">{new Date(finding.occurred_at).toLocaleString("pt-PT")}</p>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </Shell>
  );
}
