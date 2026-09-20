"use client";

import { Badge, Button, Card, SeverityBadge } from "@cyberaudit/ui";
import { useMutation } from "@tanstack/react-query";
import { ShieldCheck, UploadCloud } from "lucide-react";
import { FormEvent, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type ValidationResult = {
  accepted: boolean;
  bundle_id: string | null;
  bundle_type: string | null;
  reasons: string[];
  checked_at: string;
};

function readAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve((reader.result as string).split(",")[1] ?? "");
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

/**
 * Offline/online update manager (sections 42-43). This only ever calls
 * /api/v1/updates/validate -- it never stages, extracts or applies a
 * bundle. Nothing is ever marked successful before that validation passes,
 * and there is no path here that bypasses Ed25519 signature verification.
 */
export function UpdateManager() {
  const [manifestFile, setManifestFile] = useState<File | null>(null);
  const [signatureFile, setSignatureFile] = useState<File | null>(null);

  const validate = useMutation({
    mutationFn: async () => {
      if (!manifestFile || !signatureFile) throw new Error("Selecione o manifesto e a assinatura.");
      const manifest_json = await readAsText(manifestFile);
      const signature_base64 = await readAsBase64(signatureFile);
      return api<ValidationResult>("/updates/validate", {
        method: "POST",
        body: JSON.stringify({ manifest_json, signature_base64, files: [] }),
      });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    validate.mutate();
  }

  return (
    <Shell title="Gestor de Atualizações" eyebrow="Local Distribution">
      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <Card className="p-6">
          <div className="mb-5 flex items-center gap-3">
            <UploadCloud className="text-primary" />
            <div>
              <h2 className="font-semibold">Importar bundle offline (.caup)</h2>
              <p className="text-sm text-muted">
                Um bundle nunca é confiado só por ter sido carregado; a assinatura Ed25519 tem de
                verificar contra uma chave configurada pelo administrador.
              </p>
            </div>
          </div>
          <form onSubmit={submit} className="space-y-4">
            <label className="block">
              <span className="mb-1 block text-sm font-semibold">Manifesto (JSON)</span>
              <input
                className="field"
                type="file"
                accept="application/json"
                onChange={(event) => setManifestFile(event.target.files?.[0] ?? null)}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-sm font-semibold">Assinatura Ed25519</span>
              <input
                className="field"
                type="file"
                onChange={(event) => setSignatureFile(event.target.files?.[0] ?? null)}
              />
            </label>
            <Button disabled={!manifestFile || !signatureFile || validate.isPending}>
              {validate.isPending ? "A validar…" : "Validar bundle"}
            </Button>
          </form>
          {validate.isError && (
            <p className="mt-4 text-sm text-red-300">{(validate.error as Error).message}</p>
          )}
          {validate.data && (
            <div className="mt-6 rounded-lg border border-border bg-surface p-4">
              <div className="mb-2 flex items-center gap-2">
                <SeverityBadge state={validate.data.accepted ? "healthy" : "failed"} />
                {validate.data.bundle_type && <Badge tone="neutral">{validate.data.bundle_type}</Badge>}
              </div>
              {validate.data.bundle_id && (
                <p className="text-sm text-muted">Bundle: {validate.data.bundle_id}</p>
              )}
              {validate.data.reasons.length > 0 && (
                <ul className="mt-2 space-y-1 text-sm text-red-300">
                  {validate.data.reasons.map((reason, index) => (
                    <li key={index}>• {reason}</li>
                  ))}
                </ul>
              )}
              {validate.data.accepted && (
                <p className="mt-2 text-sm text-primary">
                  Bundle válido. A aplicação (staging, migração, health check) continua a ser
                  trabalho de instalação futuro — esta validação não altera a instalação.
                </p>
              )}
            </div>
          )}
        </Card>
        <Card className="p-5">
          <div className="mb-3 flex items-center gap-2">
            <ShieldCheck size={18} className="text-primary" />
            <h2 className="font-semibold">Fluxo seguro de atualização</h2>
          </div>
          <ol className="space-y-2 text-sm text-muted">
            <li>1. Verificar assinatura Ed25519</li>
            <li>2. Verificar compatibilidade de versão</li>
            <li>3. Verificar checksums de cada ficheiro</li>
            <li>4. Backup (instalação futura)</li>
            <li>5. Aplicar + migrar (instalação futura)</li>
            <li>6. Health check → commit ou rollback (instalação futura)</li>
          </ol>
        </Card>
      </div>
    </Shell>
  );
}
