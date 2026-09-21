"use client";

import { Badge, Button, Card, EmptyState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cpu, HardDrive } from "lucide-react";
import { FormEvent, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type ModelManifest = {
  id: string;
  model_id: string;
  family: string;
  version: string;
  quantization: string;
  size_gb: number;
  context_window: number;
  capabilities: string[];
  ram_required_mb: number;
  install_status: string;
  trust_status: string;
};

type HardwareProfile = {
  os_name: string;
  cpu_cores: number;
  ram_total_mb: number;
  ram_available_mb: number;
  gpu_vendor: string | null;
  gpu_model: string | null;
  profile: string;
};

/**
 * Administrator-facing local model management (section 33). Never executes
 * code bundled with a model artifact -- every action here is a metadata
 * change (install_status) through the existing, security-reviewed
 * ai_runtime_api endpoints; there is no "run this file" action.
 */
export function ModelManagement() {
  const queryClient = useQueryClient();
  const models = useQuery({
    queryKey: ["model-management-models"],
    queryFn: () => api<{ items: ModelManifest[] }>("/ai-runtime/models"),
  });
  const hardware = useQuery({
    queryKey: ["model-management-hardware"],
    queryFn: () => api<HardwareProfile>("/ai-runtime/hardware"),
  });

  const setInstallStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api(`/ai-runtime/models/${id}/install-status`, {
        method: "POST",
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["model-management-models"] }),
  });

  const register = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api("/ai-runtime/models", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["model-management-models"] }),
  });

  return (
    <Shell title="Gestão de Modelos Locais" eyebrow="Cyber AI · Local Runtime">
      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <Card className="overflow-hidden">
          <div className="border-b border-border p-4">
            <h2 className="font-semibold">Modelos registados</h2>
            <p className="text-sm text-muted">
              Instalar, verificar e ativar modelos nunca executa código do artefacto; apenas altera
              o estado registado.
            </p>
          </div>
          {models.isLoading && <LoadingState />}
          {models.data?.items.length === 0 && (
            <EmptyState
              title="Nenhum modelo registado."
              description="Sem modelo instalado, o Cyber AI responde de forma 100% determinística."
            />
          )}
          <ul className="divide-y divide-border">
            {models.data?.items.map((model) => (
              <li key={model.id} className="flex flex-wrap items-center gap-3 p-4">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{model.model_id}</p>
                  <p className="text-xs text-muted">
                    {model.family} · {model.quantization} · {model.size_gb} GB · contexto{" "}
                    {model.context_window.toLocaleString("pt-PT")} tokens · {model.ram_required_mb} MB RAM
                  </p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {model.capabilities.map((capability) => (
                      <Badge key={capability} tone="neutral">
                        {capability}
                      </Badge>
                    ))}
                  </div>
                </div>
                <SeverityBadge state={model.trust_status} />
                <SeverityBadge state={model.install_status} />
                {model.install_status !== "installed" && model.trust_status !== "revoked" && (
                  <Button
                    className="button-secondary"
                    onClick={() => setInstallStatus.mutate({ id: model.id, status: "installed" })}
                    disabled={setInstallStatus.isPending}
                  >
                    Ativar
                  </Button>
                )}
                {model.install_status === "installed" && (
                  <Button
                    className="button-secondary"
                    onClick={() => setInstallStatus.mutate({ id: model.id, status: "not_installed" })}
                    disabled={setInstallStatus.isPending}
                  >
                    Desativar
                  </Button>
                )}
              </li>
            ))}
          </ul>
          <div className="border-t border-border p-4">
            <RegisterForm onSubmit={(payload) => register.mutate(payload)} pending={register.isPending} />
          </div>
        </Card>
        <div className="space-y-4">
          <Card className="p-5">
            <div className="mb-3 flex items-center gap-2">
              <Cpu size={18} className="text-primary" />
              <h2 className="font-semibold">Perfil de hardware</h2>
            </div>
            {hardware.data ? (
              <ul className="space-y-1 text-sm text-muted">
                <li>
                  Perfil recomendado: <span className="text-foreground">{hardware.data.profile}</span>
                </li>
                <li>SO: {hardware.data.os_name}</li>
                <li>Núcleos CPU: {hardware.data.cpu_cores}</li>
                <li>
                  RAM disponível: {Math.round(hardware.data.ram_available_mb / 1024)} GB /{" "}
                  {Math.round(hardware.data.ram_total_mb / 1024)} GB
                </li>
                <li>GPU: {hardware.data.gpu_model ?? hardware.data.gpu_vendor ?? "não detetada"}</li>
              </ul>
            ) : (
              <LoadingState />
            )}
          </Card>
          <Card className="p-5">
            <div className="mb-3 flex items-center gap-2">
              <HardDrive size={18} className="text-primary" />
              <h2 className="font-semibold">Garantias de segurança</h2>
            </div>
            <ul className="space-y-2 text-sm text-muted">
              <li>• Nenhum código de modelo é executado a partir desta página.</li>
              <li>• Um modelo revogado nunca pode ser reativado aqui.</li>
              <li>• O CapabilityRouter só seleciona modelos com estado &ldquo;installed&rdquo;.</li>
            </ul>
          </Card>
        </div>
      </div>
    </Shell>
  );
}

function RegisterForm({
  onSubmit,
  pending,
}: {
  onSubmit: (payload: Record<string, unknown>) => void;
  pending: boolean;
}) {
  const [modelId, setModelId] = useState("");
  const [family, setFamily] = useState("qwen");

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!modelId.trim()) return;
    onSubmit({
      model_id: modelId.trim(),
      family,
      version: "1.0",
      quantization: "q4_K_M",
      size_gb: 4,
      context_window: 8192,
      capabilities: ["knowledge_query"],
      ram_required_mb: 4096,
      vram_required_mb: 0,
      cpu_compatible: true,
      gpu_compatible: false,
      license: "unspecified",
      source: "manual",
      sha256: null,
    });
    setModelId("");
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
      <label className="flex-1">
        <span className="mb-1 block text-xs text-muted">Model ID</span>
        <input
          className="field"
          value={modelId}
          onChange={(event) => setModelId(event.target.value)}
          placeholder="qwen2.5:7b-instruct-q4"
        />
      </label>
      <label>
        <span className="mb-1 block text-xs text-muted">Família</span>
        <select className="field" value={family} onChange={(event) => setFamily(event.target.value)}>
          <option value="qwen">Qwen</option>
          <option value="gemma">Gemma</option>
          <option value="nemotron">Nemotron</option>
          <option value="other">Outro</option>
        </select>
      </label>
      <Button disabled={pending || !modelId.trim()}>Registar modelo</Button>
    </form>
  );
}
