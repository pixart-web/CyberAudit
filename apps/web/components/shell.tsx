"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity, Bell, Boxes, BrainCircuit, BriefcaseBusiness, Building2, ChevronDown, CircleUserRound,
  Cloud, Code2, Cpu, FileCheck2, FileDown, FileSearch, Fingerprint, FlaskConical, Gauge, GitBranch, Globe2, HeartPulse,
  KeyRound, Layers3, Menu, Network, PackageSearch, Radar, RefreshCw, RotateCcw, Search, Settings,
  Scale, ShieldAlert, ShieldCheck, Smartphone, TimerReset, Users, Webhook,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { CommandItem, CommandPalette } from "@/components/command-palette";
import { GlobalSearch } from "@/components/global-search";
import { api } from "@/lib/api";

const groups = [
  { label: "Operações", items: [["Command Center", "/command-center", Gauge], ["Dashboard", "/dashboard", Activity], ["Notificações", "/notifications", Bell]] },
  { label: "SOC & Detection", items: [["SOC Command Center", "/soc", Gauge], ["Eventos", "/security-events", Activity], ["Deteções", "/detections", Radar], ["Incidentes", "/incidents", ShieldAlert], ["Casos", "/cases", FileSearch], ["Threat Intelligence", "/threat-intelligence", Globe2], ["Threat Hunting", "/hunts", Search], ["Playbooks", "/playbooks", FileCheck2]] },
  { label: "Asset Intelligence", items: [["Inventário de Ativos", "/assets", Boxes], ["Cyber Asset Graph", "/asset-graph", GitBranch], ["Ambientes", "/environments", Layers3], ["Zonas de Rede", "/network-zones", Network], ["Redes", "/networks", Globe2], ["Serviços", "/services", Radar], ["Alterações", "/asset-changes", TimerReset]] },
  { label: "Exposure Intelligence", items: [["Exposição", "/exposure", ShieldAlert], ["Vulnerabilidades", "/vulnerabilities", ShieldAlert], ["Correlações", "/vulnerability-matches", GitBranch], ["Threat Feeds", "/vulnerability-feeds", PackageSearch], ["Attack Paths", "/attack-paths", Network], ["Risco", "/risk", Gauge], ["Simulador", "/risk-simulator", Activity], ["Cobertura", "/coverage", FileCheck2]] },
  { label: "Application Security", items: [["AppSec Command Center", "/appsec", Gauge], ["Aplicações", "/applications", Webhook], ["APIs", "/apis", Activity], ["Repositórios", "/repositories", Code2], ["Releases", "/releases", PackageSearch], ["SBOMs", "/sboms", Boxes], ["Componentes", "/components", Layers3], ["Segredos", "/secrets", KeyRound], ["Security Gates", "/security-gates", FileCheck2], ["Exceções", "/appsec-exceptions", ShieldAlert], ["Remediação AppSec", "/appsec-remediations", RotateCcw], ["Supply Chain Graph", "/supply-chain", GitBranch]] },
  { label: "Governance, Risk & Compliance", items: [["GRC Command Center", "/grc", Scale], ["Políticas", "/grc/policies", FileCheck2], ["Controlos", "/grc/controls", ShieldAlert], ["Risk Register", "/grc/risks", Gauge], ["Compliance", "/grc/compliance", FileSearch]] },
  { label: "Intelligence", items: [["Knowledge Graph", "/knowledge-graph", GitBranch], ["AI Security Assistant", "/ai-assistant", BrainCircuit], ["Cyber AI Workspace", "/cyber-agents", BrainCircuit], ["Gestão de Modelos", "/model-management", Cpu], ["Atualizações", "/update-manager", RefreshCw]] },
  { label: "Enterprise Domains", items: [["Identity Security", "/identity", KeyRound], ["Active Directory", "/identity/active-directory", Network], ["Microsoft Entra ID", "/identity/entra", Fingerprint], ["Microsoft 365", "/identity/microsoft-365", Cloud], ["Google Workspace", "/identity/google-workspace", Globe2], ["Cloud Security", "/cloud-security", Cloud], ["Kubernetes", "/kubernetes", Boxes], ["Endpoint Security", "/endpoint-security", ShieldAlert], ["Mobile Security", "/mobile-security", Smartphone], ["Zero Trust", "/zero-trust", ShieldCheck], ["Cyber Digital Twin", "/cyber-digital-twin", GitBranch], ["Conectores", "/enterprise-connectors", Webhook]] },
  { label: "Gestão", items: [["Organizações", "/organizations", Building2], ["Clientes", "/clients", BriefcaseBusiness], ["Auditorias", "/engagements", FileSearch], ["Autorizações", "/authorizations", FileCheck2], ["Âmbito", "/scopes", ShieldAlert]] },
  { label: "Avaliações", items: [["Catálogo", "/assessment-catalog", PackageSearch], ["Jobs", "/jobs", Activity], ["Perfis de Avaliação", "/scan-profiles", Settings], ["Adaptadores", "/adapters", Webhook], ["Aprovações", "/approvals", FileCheck2], ["Importar Resultados", "/imports", FileCheck2], ["Redes", "/assessments/networks", Network], ["Aplicações Web", "/assessments/web", Webhook], ["APIs", "/assessments/apis", Activity], ["Dispositivos Móveis", "/assessments/mobile", Smartphone], ["Cloud", "/assessments/cloud", Cloud], ["Identidades", "/assessments/identities", KeyRound], ["Código Fonte", "/assessments/source", Code2], ["Dependências", "/assessments/dependencies", PackageSearch]] },
  { label: "Resultados", items: [["Findings", "/findings", ShieldAlert], ["Evidências", "/evidence", FileCheck2], ["Retestes", "/retests", RotateCcw], ["Observações de Ativos", "/asset-observations", Boxes], ["Sugestões de Ativos", "/asset-suggestions", Bell], ["Incidentes", "/incidents", Bell], ["Relatórios", "/reports", FileSearch]] },
  { label: "Laboratório", items: [["Laboratório", "/laboratory", FlaskConical], ["Cenários", "/laboratory/scenarios", Boxes], ["Ferramentas", "/laboratory/tools", Settings]] },
  { label: "Automação", items: [["Agendamentos", "/assessment-schedules", TimerReset], ["Discovery Policies", "/discovery-policies", Radar]] },
  { label: "Sistema", items: [["Utilizadores", "/users", Users], ["Registos de Auditoria", "/audit-logs", Activity], ["Health Center", "/system-health", HeartPulse], ["Diagnostic Bundle", "/diagnostics", FileDown], ["Definições", "/settings", Settings]] },
] as const;

type RuntimeHealth = { healthy: boolean; sovereign_default: boolean };

function SystemHealthIndicator() {
  const { data } = useQuery({
    queryKey: ["shell-ai-runtime-health"],
    queryFn: () => api<RuntimeHealth>("/ai-runtime/health"),
    retry: false,
  });
  const label = !data
    ? "A verificar…"
    : data.sovereign_default
      ? "IA determinística"
      : data.healthy
        ? "IA local saudável"
        : "IA local indisponível";
  const tone = !data ? "neutral" : data.sovereign_default || data.healthy ? "info" : "warning";
  return (
    <Link
      href="/system-health"
      className={`badge badge-${tone} hidden xl:inline-flex`}
      title="Estado do runtime de IA local e da instalação"
    >
      <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-current" />
      {label}
    </Link>
  );
}

export function Shell({ children, title, eyebrow = "CyberAudit Demo" }: { children: React.ReactNode; title: string; eyebrow?: string }) {
  const pathname = usePathname();
  const commandItems: CommandItem[] = groups.flatMap((group) =>
    group.items.map(([label, href, Icon]) => ({ label, href, group: group.label, icon: Icon })),
  );
  return <div className="min-h-screen bg-background">
    <aside className="desktop-sidebar fixed inset-y-0 left-0 z-30 w-[252px] overflow-y-auto border-r border-border bg-surface/95 px-3 py-4">
      <Image src="/logo.svg" width={220} height={48} alt="CyberAudit" className="mb-6 h-10 w-auto px-2" priority />
      {groups.map((group) => <nav key={group.label} className="mb-5" aria-label={group.label}>
        <p className="mb-1 px-3 text-[10px] font-bold uppercase tracking-[.16em] text-muted/70">{group.label}</p>
        {group.items.map(([label, href, Icon]) => {
          const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(href));
          return <Link key={href} href={href} className={`mb-0.5 flex items-center gap-2.5 rounded-lg border px-3 py-2 text-[13px] transition ${active ? "border-primary/20 bg-primary/10 text-primary shadow-[inset_2px_0_0_#31F27C]" : "border-transparent text-muted hover:bg-white/[.03] hover:text-foreground"}`}>
            <Icon size={15} aria-hidden />{label}
          </Link>;
        })}
      </nav>)}
    </aside>
    <main className="app-main min-h-screen ml-[252px]">
      <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border bg-background/90 px-5 backdrop-blur-xl">
        <button className="lg:hidden text-muted" aria-label="Abrir menu"><Menu /></button>
        <button className="hidden min-w-36 items-center justify-between gap-2 rounded-lg border border-border bg-card px-3 py-2 text-sm lg:flex"><span>ACME-2026-01</span><ChevronDown size={14}/></button>
        <GlobalSearch />
        <CommandPalette items={commandItems} />
        <SystemHealthIndicator />
        <span className="badge badge-success"><span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-primary"/>Modo Cliente</span>
        <button className="relative rounded-lg border border-border p-2 text-muted" aria-label="Notificações"><Bell size={18}/><span className="absolute right-1 top-1 h-1.5 w-1.5 rounded-full bg-critical"/></button>
        <button className="flex items-center gap-2 rounded-lg border border-border px-2 py-1.5 text-left"><CircleUserRound size={22} className="text-primary"/><span className="hidden text-xs sm:block"><b className="block">Administrador</b><span className="text-muted">Administrator</span></span></button>
      </header>
      <div className="p-4 md:p-6 xl:p-8">
        <p className="mb-1 text-xs text-muted">{eyebrow} <span className="mx-1">/</span> {title}</p>
        <div className="mb-6 flex items-center justify-between"><h1 className="text-2xl font-semibold tracking-tight">{title}</h1></div>
        {children}
      </div>
    </main>
  </div>;
}
