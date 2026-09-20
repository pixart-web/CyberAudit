"use client";

import { Badge, Card, ErrorState, LoadingState } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type CaseRecord = {
  id: string;
  reference: string;
  title: string;
  status: string;
  lead_investigator_id: string | null;
  members: string[];
  hypothesis: string;
  conclusions: string;
  legal_hold: boolean;
  incident_id: string;
};
type Incident = { id: string; reference: string; title: string; status: string } | null;
type CaseDetail = { case: CaseRecord; incident: Incident };

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["case", id],
    queryFn: () => api<CaseDetail>(`/cases/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Caso"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Caso">
        <ErrorState title="Caso não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { case: item, incident } = data;

  return (
    <Shell title={item.title} eyebrow={`Caso ${item.reference}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="neutral">{item.status}</Badge>
        {item.legal_hold && <Badge tone="warning">Legal hold</Badge>}
        {incident && (
          <Link href={`/incidents/${incident.id}`} className="ml-auto text-sm text-cyan hover:underline">
            Ver incidente {incident.reference}
          </Link>
        )}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Investigação</h2>
          <dl className="space-y-3 text-sm">
            <Row label="Investigador principal" value={item.lead_investigator_id ?? "Não atribuído"} />
            <Row label="Membros" value={item.members.length > 0 ? item.members.join(", ") : "—"} />
          </dl>
        </Card>
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Hipótese e conclusões</h2>
          <p className="text-xs font-semibold text-muted">Hipótese</p>
          <p className="mt-1 text-sm">{item.hypothesis || "—"}</p>
          <p className="mt-4 text-xs font-semibold text-muted">Conclusões</p>
          <p className="mt-1 text-sm">{item.conclusions || "Investigação em curso, sem conclusões registadas."}</p>
        </Card>
      </div>
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold text-muted">{label}</dt>
      <dd className="mt-1">{value}</dd>
    </div>
  );
}
