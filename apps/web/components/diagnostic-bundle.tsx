"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation } from "@tanstack/react-query";
import { FileDown, ShieldAlert } from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type DiagnosticBundle = {
  generated_at: string;
  app_version: string;
  organization_id: string;
  configuration: Record<string, unknown>;
  health: Record<string, unknown>;
  ai_runtime: Record<string, unknown>;
  counts: Record<string, number>;
  disclosure: string;
};

function download(bundle: DiagnosticBundle) {
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `cyberaudit-diagnostic-bundle-${bundle.generated_at}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

/**
 * Privacy-safe diagnostic bundle generator (section 49). Deferred honestly
 * in Phase 10.4; implemented here for real, backed by the shared redaction
 * pipeline (`cyberaudit.redaction`) and an explicit settings allowlist --
 * see `apps/api/cyberaudit/diagnostics.py`. Never contains finding/evidence/
 * report content or any credential.
 */
export function DiagnosticBundlePanel() {
  const generate = useMutation({
    mutationFn: () => api<DiagnosticBundle>("/diagnostics/bundle"),
    onSuccess: download,
  });

  return (
    <Shell title="Diagnostic Bundle" eyebrow="Support & Troubleshooting">
      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <Card className="p-6">
          <div className="mb-5 flex items-center gap-3">
            <ShieldAlert className="text-primary" />
            <div>
              <h2 className="font-semibold">Gerar bundle de diagnóstico</h2>
              <p className="text-sm text-muted">
                Recolhe metadados operacionais (saúde dos componentes, contagens, configuração
                não-sensível) para partilhar com suporte, sem incluir findings, evidências,
                relatórios ou credenciais.
              </p>
            </div>
          </div>
          <Button disabled={generate.isPending} onClick={() => generate.mutate()}>
            <FileDown size={16} className="mr-2 inline" />
            {generate.isPending ? "A gerar…" : "Gerar e descarregar"}
          </Button>
          {generate.isError && (
            <p className="mt-4 text-sm text-red-300">{(generate.error as Error).message}</p>
          )}
          {generate.data && (
            <div className="mt-6 space-y-3 rounded-lg border border-border bg-surface p-4">
              <div className="flex flex-wrap gap-2">
                <Badge tone="neutral">v{generate.data.app_version}</Badge>
                <Badge tone="neutral">{generate.data.ai_runtime.backend as string}</Badge>
                <Badge tone={generate.data.ai_runtime.healthy ? "success" : "warning"}>
                  IA {generate.data.ai_runtime.healthy ? "saudável" : "indisponível"}
                </Badge>
              </div>
              <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-3">
                {Object.entries(generate.data.counts).map(([label, value]) => (
                  <div key={label} className="rounded border border-border p-2">
                    <dt className="text-xs text-muted">{label}</dt>
                    <dd className="font-semibold">{value}</dd>
                  </div>
                ))}
              </dl>
              <p className="text-xs text-muted">{generate.data.disclosure}</p>
            </div>
          )}
        </Card>
        <Card className="p-5">
          <h2 className="mb-3 font-semibold">O que nunca é incluído</h2>
          <ul className="space-y-2 text-sm text-muted">
            <li>• Conteúdo de findings, evidências ou relatórios</li>
            <li>• Credenciais, tokens, chaves ou connection strings</li>
            <li>• Qualquer linha individual de dados de outro tenant</li>
            <li>• Endereços IP, hostnames ou identificadores de clientes</li>
          </ul>
        </Card>
      </div>
    </Shell>
  );
}
