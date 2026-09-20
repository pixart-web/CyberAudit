"use client";

import { Badge, Button, Card, EmptyState, ErrorState, LoadingState, SeverityBadge, Tabs, TabPanel } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BrainCircuit, FileText, ShieldAlert } from "lucide-react";
import { FormEvent, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Engagement = {
  id: string;
  code: string;
  name: string;
  description: string | null;
  mode: string;
  status: string;
  risk_level: string;
  start_date: string | null;
  end_date: string | null;
  client_id: string;
};

type Items<T> = { items: T[]; total?: number };
type Scope = { id: string; name: string; status: string; maximum_intensity: string; emergency_stop_enabled: boolean };
type Finding = { id: string; title: string; category: string; technical_severity: string; status: string };
type Evidence = { id: string; title: string; evidence_type: string; collected_at: string };
type EngagementNote = { id: string; body: string; pinned: boolean; created_at: string };
type TimelineEntry = { id: string; event_type: string; summary: string; occurred_at: string };
type Report = { id: string; report_type: string; status: string; title: string; created_at: string };

const TABS = [
  { id: "overview", label: "Visão Geral" },
  { id: "scope", label: "Âmbito" },
  { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidência" },
  { id: "notes", label: "Notas" },
  { id: "timeline", label: "Cronologia" },
  { id: "reports", label: "Relatórios" },
];

export function EngagementWorkspace({ id }: { id: string }) {
  const [tab, setTab] = useState("overview");
  const queryClient = useQueryClient();

  const engagement = useQuery({
    queryKey: ["engagement", id],
    queryFn: () => api<Engagement>(`/engagements/${id}`),
    retry: false,
  });
  const scope = useQuery({
    queryKey: ["engagement-scope", id],
    queryFn: () => api<Items<Scope>>(`/scopes?engagement_id=${id}`),
    enabled: tab === "scope" || tab === "overview",
  });
  const findings = useQuery({
    queryKey: ["engagement-findings", id],
    queryFn: () => api<Items<Finding>>(`/findings?engagement_id=${id}`),
    enabled: tab === "findings" || tab === "overview",
  });
  const evidence = useQuery({
    queryKey: ["engagement-evidence", id],
    queryFn: () => api<Items<Evidence>>(`/evidence?engagement_id=${id}`),
    enabled: tab === "evidence",
  });
  const notes = useQuery({
    queryKey: ["engagement-notes", id],
    queryFn: () => api<Items<EngagementNote>>(`/engagements/${id}/notes`),
    enabled: tab === "notes",
  });
  const timeline = useQuery({
    queryKey: ["engagement-timeline", id],
    queryFn: () => api<Items<TimelineEntry>>(`/engagements/${id}/timeline`),
    enabled: tab === "timeline" || tab === "overview",
  });
  const reports = useQuery({
    queryKey: ["engagement-reports", id],
    queryFn: () => api<Items<Report>>(`/engagements/${id}/reports`),
    enabled: tab === "reports",
  });

  const addNote = useMutation({
    mutationFn: (body: string) =>
      api(`/engagements/${id}/notes`, { method: "POST", body: JSON.stringify({ body, pinned: false }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["engagement-notes", id] }),
  });

  const generateReport = useMutation({
    mutationFn: () =>
      api(`/engagements/${id}/reports`, {
        method: "POST",
        body: JSON.stringify({ report_type: "executive_summary", include_ai_summary: true }),
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["engagement-reports", id] }),
  });

  if (engagement.isLoading) return <Shell title="Auditoria"><LoadingState /></Shell>;
  if (engagement.error || !engagement.data) return <Shell title="Auditoria"><ErrorState title="Auditoria não encontrada ou sem autorização." /></Shell>;

  const item = engagement.data;

  return (
    <Shell title={item.name} eyebrow={`Auditoria ${item.code}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={item.status} />
        <Badge tone="info">{item.mode === "client" ? "Cliente" : "Laboratório"}</Badge>
        <SeverityBadge state={item.risk_level} />
        <Button
          className="ml-auto gap-2"
          onClick={() => generateReport.mutate()}
          disabled={generateReport.isPending}
        >
          <BrainCircuit size={16} />
          {generateReport.isPending ? "A resumir…" : "Summarize Assessment"}
        </Button>
      </div>
      <Card className="overflow-hidden">
        <Tabs items={TABS} active={tab} onChange={setTab} />
        <div className="p-5">
          <TabPanel id="overview" active={tab}>
            <div className="grid gap-4 md:grid-cols-3">
              <Stat label="Âmbito autorizado" value={String(scope.data?.total ?? scope.data?.items.length ?? "—")} />
              <Stat label="Findings" value={String(findings.data?.total ?? findings.data?.items.length ?? "—")} />
              <Stat label="Eventos na cronologia" value={String(timeline.data?.items.length ?? "—")} />
            </div>
            {item.description && <p className="mt-4 text-sm text-muted">{item.description}</p>}
            <p className="mt-4 text-xs text-muted">
              Um analista deve sempre saber sob que âmbito e autorização está a operar: consulte a
              secção &ldquo;Âmbito&rdquo; antes de qualquer avaliação.
            </p>
          </TabPanel>

          <TabPanel id="scope" active={tab}>
            {scope.isLoading && <LoadingState />}
            {scope.data?.items.length === 0 && (
              <EmptyState
                title="Sem âmbito autorizado."
                description="Nenhuma avaliação pode avançar sem um Scope ativo para esta auditoria."
              />
            )}
            <ul className="space-y-2">
              {scope.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span>{row.name}</span>
                  <div className="flex items-center gap-2">
                    <Badge tone="neutral">{row.maximum_intensity}</Badge>
                    <SeverityBadge state={row.status} />
                    {row.emergency_stop_enabled && <Badge tone="warning">Emergency stop</Badge>}
                  </div>
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="findings" active={tab}>
            {findings.isLoading && <LoadingState />}
            {findings.data?.items.length === 0 && <EmptyState title="Ainda não existem findings." />}
            <ul className="space-y-2">
              {findings.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span className="flex items-center gap-2"><ShieldAlert size={14} className="text-muted" />{row.title}</span>
                  <SeverityBadge state={row.technical_severity} />
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="evidence" active={tab}>
            {evidence.isLoading && <LoadingState />}
            {evidence.data?.items.length === 0 && <EmptyState title="Ainda não existe evidência registada." />}
            <ul className="space-y-2">
              {evidence.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span>{row.title}</span>
                  <Badge tone="neutral">{row.evidence_type}</Badge>
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="notes" active={tab}>
            <NoteForm onSubmit={(body) => addNote.mutate(body)} pending={addNote.isPending} />
            {notes.isLoading && <LoadingState />}
            {notes.data?.items.length === 0 && <EmptyState title="Ainda não existem notas." />}
            <ul className="mt-4 space-y-2">
              {notes.data?.items.map((row) => (
                <li key={row.id} className="rounded-lg border border-border p-3 text-sm">
                  <p>{row.body}</p>
                  <p className="mt-1 text-xs text-muted">{new Date(row.created_at).toLocaleString("pt-PT")}</p>
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="timeline" active={tab}>
            {timeline.isLoading && <LoadingState />}
            {timeline.data?.items.length === 0 && <EmptyState title="Sem eventos registados." />}
            <ol className="space-y-3 border-l border-border pl-4">
              {timeline.data?.items.map((row) => (
                <li key={row.id} className="relative text-sm">
                  <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-primary" />
                  <p className="font-medium">{row.summary}</p>
                  <p className="text-xs text-muted">
                    {row.event_type} · {new Date(row.occurred_at).toLocaleString("pt-PT")}
                  </p>
                </li>
              ))}
            </ol>
          </TabPanel>

          <TabPanel id="reports" active={tab}>
            {reports.isLoading && <LoadingState />}
            {reports.data?.items.length === 0 && (
              <EmptyState
                title="Ainda não existem relatórios."
                description='Use "Summarize Assessment" para gerar um resumo executivo.'
              />
            )}
            <ul className="space-y-2">
              {reports.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span className="flex items-center gap-2"><FileText size={14} className="text-muted" />{row.title}</span>
                  <SeverityBadge state={row.status} />
                </li>
              ))}
            </ul>
          </TabPanel>
        </div>
      </Card>
    </Shell>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border p-4">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
    </div>
  );
}

function NoteForm({ onSubmit, pending }: { onSubmit: (body: string) => void; pending: boolean }) {
  const [value, setValue] = useState("");
  function submit(event: FormEvent) {
    event.preventDefault();
    if (value.trim().length === 0) return;
    onSubmit(value.trim());
    setValue("");
  }
  return (
    <form onSubmit={submit} className="mb-4 flex gap-2">
      <label className="flex-1">
        <span className="sr-only">Nova nota</span>
        <input
          className="field"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="Adicionar nota do analista…"
        />
      </label>
      <Button disabled={pending || value.trim().length === 0}>Adicionar</Button>
    </form>
  );
}
