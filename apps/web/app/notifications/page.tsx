"use client";

import { Badge, Card, EmptyState, ErrorState, SeverityBadge } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Item = {
  id: string;
  event_type: string;
  severity: string;
  title: string;
  message: string;
  resource_type: string | null;
  resource_id: string | null;
  created_at: string;
  read_at: string | null;
};

const LINKS: Record<string, string> = { report: "/reports", scan_job: "/jobs", external_import: "/imports" };

export default function NotificationsPage() {
  const queryClient = useQueryClient();
  const { data, error, isLoading } = useQuery({ queryKey: ["notifications"], queryFn: () => api<{ items: Item[] }>("/notifications") });
  const read = useMutation({
    mutationFn: (id: string) => api(`/notifications/${id}/read`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      queryClient.invalidateQueries({ queryKey: ["unread-notifications"] });
    },
  });
  return (
    <Shell title="Notificações">
      {error ? (
        <ErrorState title="Não foi possível carregar as notificações." />
      ) : (
        <Card className="overflow-hidden">
          <ul>
            {data?.items.map((n) => {
              const base = n.resource_type ? LINKS[n.resource_type] : undefined;
              return (
                <li key={n.id} className="flex flex-wrap items-center gap-3 border-b border-border p-4 text-sm last:border-0">
                  {!n.read_at && <Badge tone="info">Nova</Badge>}
                  <SeverityBadge state={n.severity === "error" ? "failed" : n.severity === "warning" ? "warning" : "informational"} />
                  <div className="min-w-0 flex-1">
                    <b className={n.read_at ? "font-medium text-muted" : ""}>{n.title}</b>
                    <p className="truncate text-xs text-muted">{n.message}</p>
                  </div>
                  {base && n.resource_id && <Link className="text-xs text-cyan hover:underline" href={`${base}/${n.resource_id}`}>Abrir</Link>}
                  <time className="text-xs text-muted" dateTime={n.created_at}>{new Date(n.created_at).toLocaleString("pt-PT")}</time>
                  {!n.read_at && (
                    <button type="button" className="text-xs text-cyan hover:underline" onClick={() => read.mutate(n.id)} disabled={read.isPending}>
                      Marcar como lida
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
          {!isLoading && data?.items.length === 0 && <EmptyState title="Sem notificações." description="Aparecem aqui quando um job termina, uma importação conclui ou um relatório fica pronto." />}
        </Card>
      )}
    </Shell>
  );
}
