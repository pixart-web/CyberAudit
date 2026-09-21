"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { BrainCircuit, FileCheck2, ShieldAlert, UserCheck } from "lucide-react";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Report = {
  id: string;
  engagement_id: string;
  report_type: string;
  title: string;
  status: string;
  created_at: string;
};
type ReportSection = {
  id: string;
  position: number;
  heading: string;
  content_type: "evidence" | "finding" | "analyst_conclusion" | "ai_generated";
  body: string;
  source_references: string[];
  ai_citations: { node_id?: string; source_id?: string }[];
};
type ReportDetail = { report: Report; sections: ReportSection[] };

const CONTENT_TYPE_META: Record<ReportSection["content_type"], { label: string; icon: typeof FileCheck2 }> = {
  evidence: { label: "Evidência", icon: FileCheck2 },
  finding: { label: "Finding", icon: ShieldAlert },
  analyst_conclusion: { label: "Conclusão do analista", icon: UserCheck },
  ai_generated: { label: "Gerado por IA", icon: BrainCircuit },
};

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["report", id],
    queryFn: () => api<ReportDetail>(`/reports/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Relatório"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Relatório">
        <ErrorState title="Relatório não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { report, sections } = data;

  return (
    <Shell title={report.title} eyebrow={`Relatório · ${report.report_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={report.status === "draft" ? "warning" : "healthy"} />
        <Badge tone="neutral">{new Date(report.created_at).toLocaleString("pt-PT")}</Badge>
      </div>
      {sections.length === 0 && (
        <Card className="p-8">
          <EmptyState title="Este relatório ainda não tem secções geradas." />
        </Card>
      )}
      <div className="space-y-4">
        {sections.map((section) => {
          const meta = CONTENT_TYPE_META[section.content_type];
          const Icon = meta.icon;
          return (
            <Card key={section.id} className="p-6">
              <div className="mb-3 flex items-center gap-2">
                <Icon size={16} className="text-primary" />
                <h2 className="font-semibold">{section.heading}</h2>
                <Badge tone={section.content_type === "ai_generated" ? "info" : "neutral"} className="ml-auto">
                  {meta.label}
                </Badge>
              </div>
              <p className="whitespace-pre-wrap text-sm text-muted">{section.body}</p>
              {section.content_type === "ai_generated" && section.ai_citations.length > 0 && (
                <p className="mt-3 text-xs text-muted">
                  Fontes: {section.ai_citations.map((citation) => citation.source_id ?? citation.node_id).join(", ")}
                </p>
              )}
              {section.source_references.length > 0 && (
                <p className="mt-3 text-xs text-muted">Referências: {section.source_references.join(", ")}</p>
              )}
            </Card>
          );
        })}
      </div>
      <p className="mt-6 text-xs text-muted">
        Secções de evidência e finding refletem dados já registados; conclusões do analista e conteúdo gerado por IA
        são identificados explicitamente e nunca se tornam evidência silenciosamente.
      </p>
    </Shell>
  );
}
