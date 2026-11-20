"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Bell,
  Boxes,
  BrainCircuit,
  BriefcaseBusiness,
  Building2,
  ChevronDown,
  CircleUserRound,
  Cloud,
  Code2,
  Cpu,
  FileCheck2,
  FileDown,
  FileSearch,
  Fingerprint,
  FlaskConical,
  Gauge,
  GitBranch,
  Globe2,
  HeartPulse,
  KeyRound,
  Layers3,
  Menu,
  Network,
  PackageSearch,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  TimerReset,
  Users,
  Webhook,
  X,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { CommandItem, CommandPalette } from "@/components/command-palette";
import { GlobalSearch } from "@/components/global-search";
import { api } from "@/lib/api";

const groups = [
  {
    label: "Operações",
    items: [
      ["Command Center", "/command-center", Gauge],
      ["Dashboard", "/dashboard", Activity],
      ["Notificações", "/notifications", Bell],
    ],
  },
  {
    label: "SOC & Detection",
    items: [
      ["SOC Command Center", "/soc", Gauge],
      ["Eventos", "/security-events", Activity],
      ["Deteções", "/detections", Radar],
      ["Incidentes", "/incidents", ShieldAlert],
      ["Casos", "/cases", FileSearch],
      ["Threat Intelligence", "/threat-intelligence", Globe2],
      ["Threat Hunting", "/hunts", Search],
      ["Playbooks", "/playbooks", FileCheck2],
    ],
  },
  {
    label: "Asset Intelligence",
    items: [
      ["Inventário de Ativos", "/assets", Boxes],
      ["Cyber Asset Graph", "/asset-graph", GitBranch],
      ["Ambientes", "/environments", Layers3],
      ["Zonas de Rede", "/network-zones", Network],
      ["Redes", "/networks", Globe2],
      ["Serviços", "/services", Radar],
      ["Alterações", "/asset-changes", TimerReset],
    ],
  },
  {
    label: "Exposure Intelligence",
    items: [
      ["Exposição", "/exposure", ShieldAlert],
      ["Vulnerabilidades", "/vulnerabilities", ShieldAlert],
      ["Correlações", "/vulnerability-matches", GitBranch],
      ["Threat Feeds", "/vulnerability-feeds", PackageSearch],
      ["Attack Paths", "/attack-paths", Network],
      ["Risco", "/risk", Gauge],
      ["Simulador", "/risk-simulator", Activity],
      ["Cobertura", "/coverage", FileCheck2],
    ],
  },
  {
    label: "Application Security",
    items: [
      ["AppSec Command Center", "/appsec", Gauge],
      ["Aplicações", "/applications", Webhook],
      ["APIs", "/apis", Activity],
      ["Repositórios", "/repositories", Code2],
      ["Releases", "/releases", PackageSearch],
      ["SBOMs", "/sboms", Boxes],
      ["Componentes", "/components", Layers3],
      ["Segredos", "/secrets", KeyRound],
      ["Security Gates", "/security-gates", FileCheck2],
      ["Exceções", "/appsec-exceptions", ShieldAlert],
      ["Remediação AppSec", "/appsec-remediations", RotateCcw],
      ["Supply Chain Graph", "/supply-chain", GitBranch],
    ],
  },
  {
    label: "Governance, Risk & Compliance",
    items: [
      ["GRC Command Center", "/grc", ShieldCheck],
      ["Políticas", "/grc/policies", FileCheck2],
      ["Controlos", "/grc/controls", ShieldAlert],
      ["Risk Register", "/grc/risks", Gauge],
      ["Compliance", "/grc/compliance", FileSearch],
    ],
  },
  {
    label: "Intelligence",
    items: [
      ["Knowledge Graph", "/knowledge-graph", GitBranch],
      ["AI Security Assistant", "/ai-assistant", BrainCircuit],
      ["Cyber AI Workspace", "/cyber-agents", BrainCircuit],
      ["Gestão de Modelos", "/model-management", Cpu],
      ["Atualizações", "/update-manager", RefreshCw],
    ],
  },
  {
    label: "Enterprise Domains",
    items: [
      ["Identity Security", "/identity", KeyRound],
      ["Active Directory", "/identity/active-directory", Network],
      ["Microsoft Entra ID", "/identity/entra", Fingerprint],
      ["Microsoft 365", "/identity/microsoft-365", Cloud],
      ["Google Workspace", "/identity/google-workspace", Globe2],
      ["Cloud Security", "/cloud-security", Cloud],
      ["Kubernetes", "/kubernetes", Boxes],
      ["Endpoint Security", "/endpoint-security", ShieldAlert],
      ["Mobile Security", "/mobile-security", Smartphone],
      ["Zero Trust", "/zero-trust", ShieldCheck],
      ["Cyber Digital Twin", "/cyber-digital-twin", GitBranch],
      ["Conectores", "/enterprise-connectors", Webhook],
    ],
  },
  {
    label: "Gestão",
    items: [
      ["Organizações", "/organizations", Building2],
      ["Clientes", "/clients", BriefcaseBusiness],
      ["Auditorias", "/engagements", FileSearch],
      ["Autorizações", "/authorizations", FileCheck2],
      ["Âmbito", "/scopes", ShieldAlert],
    ],
  },
  {
    label: "Avaliações",
    items: [
      ["Catálogo", "/assessment-catalog", PackageSearch],
      ["Jobs", "/jobs", Activity],
      ["Perfis de Avaliação", "/scan-profiles", Settings],
      ["Adaptadores", "/adapters", Webhook],
      ["Aprovações", "/approvals", FileCheck2],
      ["Importar Resultados", "/imports", FileCheck2],
      ["Redes", "/assessments/networks", Network],
      ["Aplicações Web", "/assessments/web", Webhook],
      ["APIs", "/assessments/apis", Activity],
      ["Dispositivos Móveis", "/assessments/mobile", Smartphone],
      ["Cloud", "/assessments/cloud", Cloud],
      ["Identidades", "/assessments/identities", KeyRound],
      ["Código Fonte", "/assessments/source", Code2],
      ["Dependências", "/assessments/dependencies", PackageSearch],
    ],
  },
  {
    label: "Resultados",
    items: [
      ["Findings", "/findings", ShieldAlert],
      ["Evidências", "/evidence", FileCheck2],
      ["Retestes", "/retests", RotateCcw],
      ["Observações de Ativos", "/asset-observations", Boxes],
      ["Sugestões de Ativos", "/asset-suggestions", Bell],
      ["Incidentes", "/incidents", Bell],
      ["Relatórios", "/reports", FileSearch],
    ],
  },
  {
    label: "Laboratório",
    items: [
      ["Laboratório", "/laboratory", FlaskConical],
      ["Cenários", "/laboratory/scenarios", Boxes],
      ["Ferramentas", "/laboratory/tools", Settings],
    ],
  },
  {
    label: "Automação",
    items: [
      ["Agendamentos", "/assessment-schedules", TimerReset],
      ["Discovery Policies", "/discovery-policies", Radar],
    ],
  },
  {
    label: "Sistema",
    items: [
      ["Utilizadores", "/users", Users],
      ["Registos de Auditoria", "/audit-logs", Activity],
      ["Licença", "/license", Activity],
      ["Health Center", "/system-health", HeartPulse],
      ["Diagnostic Bundle", "/diagnostics", FileDown],
      ["Definições", "/settings", Settings],
    ],
  },
] as const;

type RuntimeHealth = { components?: Record<string, string> };
type Me = { name: string; email: string; roles: string[] };
type OrganizationPage = { items: { name: string }[] };
type EngagementPage = {
  items: { id: string; code: string; name: string; status: string }[];
};

function RuntimeStatus() {
  const health = useQuery({
    queryKey: ["shell-runtime-health"],
    queryFn: () => api<RuntimeHealth>("/system-health"),
    retry: false,
    refetchInterval: 30_000,
  });
  const values = health.data?.components
    ? Object.values(health.data.components).map((value) =>
        String(value).toLowerCase(),
      )
    : [];
  const degraded = values.some((value) =>
    ["failed", "offline", "error", "unhealthy"].includes(value),
  );
  const hasTelemetry = values.length > 0;
  const label = health.isLoading
    ? "Runtime a verificar"
    : health.error
      ? "Runtime indisponível"
      : !hasTelemetry
        ? "Runtime sem telemetria"
        : degraded
          ? "Runtime degradado"
          : "Runtime local saudável";
  return (
    <Link
      href="/system-health"
      className={`runtime-state ${health.error || degraded || !hasTelemetry ? "runtime-state-warning" : ""}`}
      title="Estado dos serviços locais"
    >
      <span aria-hidden className="runtime-state-mark" />
      <span className="hidden xl:inline">{label}</span>
      <span className="sr-only xl:hidden">{label}</span>
    </Link>
  );
}

export function Shell({
  children,
  title,
  eyebrow,
}: {
  children: React.ReactNode;
  title: string;
  eyebrow?: string;
}) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [openGroups, setOpenGroups] = useState<Set<string>>(
    () => new Set(["Operações"]),
  );
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => api<Me>("/auth/me"),
    staleTime: 60_000,
    retry: false,
  });
  const organization = useQuery({
    queryKey: ["current-organization"],
    queryFn: () => api<OrganizationPage>("/organizations?page_size=1"),
    staleTime: 300_000,
    retry: false,
  });
  const engagement = useQuery({
    queryKey: ["active-engagement-context"],
    queryFn: () =>
      api<EngagementPage>("/engagements?status=active&page_size=1"),
    staleTime: 60_000,
    retry: false,
  });
  const notifications = useQuery({
    queryKey: ["unread-notifications"],
    queryFn: () => api<{ items: unknown[] }>("/notifications?unread_only=true"),
    refetchInterval: 60_000,
    retry: false,
  });

  useEffect(() => {
    setMobileOpen(false);
    const activeGroup = groups.find((group) =>
      group.items.some(
        ([, href]) =>
          pathname === href ||
          (href !== "/dashboard" && pathname.startsWith(href)),
      ),
    );
    if (activeGroup)
      setOpenGroups((current) => new Set(current).add(activeGroup.label));
  }, [pathname]);

  const unread = notifications.data?.items?.length ?? 0;
  const organizationName =
    organization.data?.items?.[0]?.name ?? "Organização indisponível";
  const activeEngagement = engagement.data?.items?.[0];
  const commandItems: CommandItem[] = useMemo(
    () =>
      groups.flatMap((group) =>
        group.items.map(([label, href, Icon]) => ({
          label,
          href,
          group: group.label,
          icon: Icon,
        })),
      ),
    [],
  );
  const railWidth = collapsed ? 72 : 232;

  return (
    <div className="min-h-[100dvh] bg-background">
      {mobileOpen && (
        <button
          className="fixed inset-0 z-30 bg-[#020507]/70 lg:hidden"
          aria-label="Fechar navegação"
          onClick={() => setMobileOpen(false)}
        />
      )}
      <aside
        className="desktop-sidebar fixed inset-y-0 left-0 z-40 flex overflow-hidden border-r border-border bg-[#0b1218] transition-[width,transform] duration-200"
        data-open={mobileOpen}
        style={{ width: railWidth }}
      >
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex h-[58px] shrink-0 items-center border-b border-border px-3">
            {collapsed ? (
              <ShieldCheck
                className="mx-auto text-primary"
                size={24}
                aria-label="CyberAudit OS"
              />
            ) : (
              <Image
                src="/logo.svg"
                width={190}
                height={42}
                alt="CyberAudit"
                className="h-8 w-auto"
                priority
              />
            )}
            <button
              className="icon-button ml-auto hidden border-0 bg-transparent lg:inline-flex"
              aria-label={
                collapsed ? "Expandir navegação" : "Recolher navegação"
              }
              onClick={() => setCollapsed((value) => !value)}
            >
              {collapsed ? (
                <PanelLeftOpen size={16} />
              ) : (
                <PanelLeftClose size={16} />
              )}
            </button>
            <button
              className="icon-button ml-auto border-0 bg-transparent lg:hidden"
              aria-label="Fechar navegação"
              onClick={() => setMobileOpen(false)}
            >
              <X size={16} />
            </button>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-2 py-2">
            {groups.map((group) => {
              const groupActive = group.items.some(
                ([, href]) =>
                  pathname === href ||
                  (href !== "/dashboard" && pathname.startsWith(href)),
              );
              const GroupIcon = group.items[0][2];
              if (collapsed) {
                const [, href] = group.items[0];
                return (
                  <Link
                    key={group.label}
                    href={href}
                    title={group.label}
                    aria-label={group.label}
                    className={`nav-rail-button ${groupActive ? "nav-rail-button-active" : ""}`}
                  >
                    <GroupIcon size={18} aria-hidden />
                  </Link>
                );
              }
              return (
                <details
                  key={group.label}
                  className="nav-group"
                  open={openGroups.has(group.label)}
                  onToggle={(event) => {
                    const open = event.currentTarget.open;
                    setOpenGroups((current) => {
                      const next = new Set(current);
                      if (open) next.add(group.label);
                      else next.delete(group.label);
                      return next;
                    });
                  }}
                >
                  <summary className="nav-group-summary">
                    <GroupIcon size={15} aria-hidden />
                    <span className="min-w-0 flex-1 truncate">
                      {group.label}
                    </span>
                    <ChevronDown
                      size={13}
                      className="nav-group-chevron"
                      aria-hidden
                    />
                  </summary>
                  <nav aria-label={group.label} className="pb-1 pl-2">
                    {group.items.map(([label, href, Icon]) => {
                      const active =
                        pathname === href ||
                        (href !== "/dashboard" && pathname.startsWith(href));
                      return (
                        <Link
                          key={href}
                          href={href}
                          className={`nav-item ${active ? "nav-item-active" : ""}`}
                          aria-current={active ? "page" : undefined}
                        >
                          <Icon size={14} aria-hidden />
                          <span className="truncate">{label}</span>
                        </Link>
                      );
                    })}
                  </nav>
                </details>
              );
            })}
          </div>

          <div className="shrink-0 border-t border-border p-2">
            <Link
              href="/account"
              className={`flex items-center gap-2 rounded-md px-2 py-2 hover:bg-white/[.04] ${collapsed ? "justify-center" : ""}`}
              aria-label="A minha conta"
            >
              <CircleUserRound size={20} className="shrink-0 text-primary" />
              {!collapsed && (
                <span className="min-w-0 text-xs">
                  <b className="block truncate font-medium">
                    {me.data?.name ?? "Utilizador autenticado"}
                  </b>
                  <span className="block truncate text-muted">
                    {me.data?.roles?.[0] ?? me.data?.email ?? ""}
                  </span>
                </span>
              )}
            </Link>
          </div>
        </div>
      </aside>

      <main
        className="app-main min-h-[100dvh] transition-[margin] duration-200"
        style={{ marginLeft: railWidth }}
      >
        <header className="desktop-topbar sticky top-0 z-20 flex h-[58px] items-center gap-2 border-b border-border bg-background/95 px-4 backdrop-blur-md">
          <button
            className="icon-button lg:hidden"
            aria-label="Abrir navegação"
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen(true)}
          >
            <Menu size={17} />
          </button>
          <div className="hidden min-w-0 items-center gap-2 lg:flex">
            <span className="context-label">Organização</span>
            <span
              className="max-w-44 truncate text-xs font-medium"
              title={organizationName}
            >
              {organizationName}
            </span>
            <span className="h-5 w-px bg-border" aria-hidden />
            <span className="context-label">Auditoria</span>
            {activeEngagement ? (
              <Link
                href={`/engagements/${activeEngagement.id}`}
                className="max-w-52 truncate font-mono text-[11px] text-primary"
                title={activeEngagement.name}
              >
                {activeEngagement.code} / {activeEngagement.name}
              </Link>
            ) : (
              <Link href="/engagements" className="text-[11px] text-muted">
                Sem auditoria ativa
              </Link>
            )}
          </div>
          <div className="mx-auto flex min-w-0 max-w-2xl flex-1 items-center gap-2 lg:ml-4">
            <GlobalSearch />
            <CommandPalette items={commandItems} />
          </div>
          <RuntimeStatus />
          <Link
            href="/notifications"
            className="icon-button relative"
            aria-label={
              unread ? `Notificações (${unread} por ler)` : "Notificações"
            }
          >
            <Bell size={16} />
            {unread > 0 && (
              <span className="absolute -right-1 -top-1 grid min-w-4 place-items-center rounded-full bg-critical px-1 text-[9px] font-bold text-[#160706]">
                {unread > 9 ? "9+" : unread}
              </span>
            )}
          </Link>
        </header>

        <div className="workspace-content px-4 py-4 md:px-5 xl:px-6">
          <div className="mb-4 flex min-h-12 flex-wrap items-end justify-between gap-3 border-b border-border pb-3">
            <div className="min-w-0">
              <p className="blacksite-kicker mb-1 truncate">
                {eyebrow ?? organizationName} / {title}
              </p>
              <h1 className="truncate text-[1.35rem] font-semibold leading-tight tracking-[-.02em]">
                {title}
              </h1>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10px] text-muted">
              <span>{pathname}</span>
            </div>
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
