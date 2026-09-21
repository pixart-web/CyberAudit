"use client";

import { Badge, Button, EmptyState, LoadingState } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useState } from "react";
import { api } from "@/lib/api";

type EvidenceSummary = {
  id: string;
  title: string;
  evidence_type: string;
  sensitivity: string;
  redacted: boolean;
  collected_at: string;
} | null;
type EvidenceLink = {
  id: string;
  evidence_id: string;
  purpose: string;
  valid_until: string | null;
  verified_at: string | null;
  evidence: EvidenceSummary;
};
type Items<T> = { items: T[] };

/**
 * Shared evidence-links UI (section 9: one visual language for evidence
 * across Finding/Engagement/Incident/Case/Control). Reuses the existing
 * generic GrcEvidenceLink table (subject_type/subject_id) -- it never
 * copies an Evidence row, only associates an existing one, and every
 * write goes through the same tenant- and subject-authorized backend
 * endpoint (POST/DELETE /grc/evidence-links).
 */
export function EvidenceLinksPanel({
  subjectType,
  subjectId,
  enabled,
}: {
  subjectType: string;
  subjectId: string;
  enabled: boolean;
}) {
  const [evidenceId, setEvidenceId] = useState("");
  const [purpose, setPurpose] = useState("");
  const queryClient = useQueryClient();
  const queryKey = ["evidence-links", subjectType, subjectId];

  const links = useQuery({
    queryKey,
    queryFn: () => api<Items<EvidenceLink>>(`/grc/evidence-links?subject_type=${subjectType}&subject_id=${subjectId}`),
    enabled,
  });

  const link = useMutation({
    mutationFn: () =>
      api("/grc/evidence-links", {
        method: "POST",
        body: JSON.stringify({ evidence_id: evidenceId, subject_type: subjectType, subject_id: subjectId, purpose }),
      }),
    onSuccess: () => {
      setEvidenceId("");
      setPurpose("");
      queryClient.invalidateQueries({ queryKey });
    },
  });

  const unlink = useMutation({
    mutationFn: (linkId: string) => api(`/grc/evidence-links/${linkId}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey }),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!evidenceId.trim() || !purpose.trim()) return;
    link.mutate();
  }

  return (
    <div>
      <form onSubmit={submit} className="mb-4 grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
        <label>
          <span className="sr-only">ID da evidência existente</span>
          <input
            className="field"
            value={evidenceId}
            onChange={(event) => setEvidenceId(event.target.value)}
            placeholder="ID de evidência existente"
          />
        </label>
        <label>
          <span className="sr-only">Finalidade</span>
          <input
            className="field"
            value={purpose}
            onChange={(event) => setPurpose(event.target.value)}
            placeholder="Finalidade (ex.: cadeia de custódia)"
          />
        </label>
        <Button disabled={link.isPending || !evidenceId.trim() || !purpose.trim()}>
          {link.isPending ? "A associar…" : "Associar"}
        </Button>
      </form>
      {link.isError && <p className="mb-3 text-sm text-red-300">{(link.error as Error).message}</p>}

      {links.isLoading && <LoadingState />}
      {links.data?.items.length === 0 && (
        <EmptyState
          title="Sem evidência associada."
          description="Associa uma evidência já registada nesta auditoria em vez de duplicar o registo."
        />
      )}
      <ul className="space-y-2">
        {links.data?.items.map((row) => (
          <li key={row.id} className="rounded-lg border border-border p-3 text-sm">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium">{row.evidence?.title ?? "Evidência indisponível"}</span>
              <div className="flex items-center gap-2">
                {row.evidence?.redacted && <Badge tone="warning">Redigida</Badge>}
                <Badge tone={row.verified_at ? "success" : "warning"}>
                  {row.verified_at ? "Verificado" : "Pendente"}
                </Badge>
                <button
                  type="button"
                  className="text-xs text-muted hover:text-critical"
                  onClick={() => unlink.mutate(row.id)}
                  disabled={unlink.isPending}
                >
                  Remover
                </button>
              </div>
            </div>
            <p className="mt-1 text-xs text-muted">
              {row.purpose}
              {row.evidence && ` · ${row.evidence.evidence_type} · ${row.evidence.sensitivity}`}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
