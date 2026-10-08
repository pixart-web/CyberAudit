"use client";

import { Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Circle } from "lucide-react";
import Link from "next/link";
import { api } from "@/lib/api";

type Count = { total?: number; items?: unknown[] };
const total = (c?: Count) => c?.total ?? c?.items?.length ?? 0;

const STEPS: { key: string; label: string; href: string; path: string; hint: string }[] = [
  { key: "users", label: "Convidar a equipa", href: "/users", path: "/users?page_size=2", hint: "Crie utilizadores com o perfil adequado (mais do que o administrador)." },
  { key: "clients", label: "Criar o primeiro cliente", href: "/clients", path: "/clients?page_size=1", hint: "Cada auditoria pertence a um cliente." },
  { key: "engagements", label: "Criar uma auditoria", href: "/engagements/new", path: "/engagements?page_size=1", hint: "Defina datas, responsável e nível de risco." },
  { key: "scopes", label: "Definir âmbito autorizado", href: "/scopes", path: "/scopes?page_size=1", hint: "Sem âmbito e autorização válidos, nenhuma avaliação é executada." },
  { key: "assets", label: "Registar ou importar ativos", href: "/assets", path: "/assets?page_size=1", hint: "Crie ativos manualmente ou importe resultados em /imports." },
  { key: "findings", label: "Obter findings", href: "/imports", path: "/findings?page_size=1", hint: "Execute uma avaliação suportada ou importe resultados (CSV, SARIF, JSON)." },
];

/** Shown until the first end-to-end path exists. Every tick is derived from real record counts. */
export function OnboardingChecklist() {
  const results = STEPS.map((step) => ({
    step,
    // eslint-disable-next-line react-hooks/rules-of-hooks -- fixed-length static list
    query: useQuery({ queryKey: ["onboarding", step.key], queryFn: () => api<Count>(step.path), retry: false }),
  }));
  const loaded = results.every((r) => !r.query.isLoading);
  const done = results.map((r) => total(r.query.data) >= (r.step.key === "users" ? 2 : 1));
  if (!loaded || done.every(Boolean)) return null;
  return (
    <Card className="mb-5 p-5" aria-label="Primeiros passos">
      <h2 className="text-sm font-semibold">Primeiros passos ({done.filter(Boolean).length}/{STEPS.length})</h2>
      <ol className="mt-3 grid gap-2 md:grid-cols-2">
        {results.map(({ step }, index) => (
          <li key={step.key} className="flex items-start gap-2 text-sm">
            {done[index] ? <CheckCircle2 size={16} className="mt-0.5 text-primary" aria-label="Concluído" /> : <Circle size={16} className="mt-0.5 text-muted" aria-label="Pendente" />}
            <span>
              <Link href={step.href} className={done[index] ? "text-muted line-through" : "text-cyan hover:underline"}>{step.label}</Link>
              {!done[index] && <small className="block text-muted">{step.hint}</small>}
            </span>
          </li>
        ))}
      </ol>
    </Card>
  );
}
