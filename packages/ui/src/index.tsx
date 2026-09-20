import * as React from "react";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleAlert,
  HelpCircle,
  Info,
  Loader2,
  ShieldAlert,
  ShieldQuestion,
  WifiOff,
} from "lucide-react";

export function Card({ className = "", ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`rounded-xl border border-border bg-card shadow-panel ${className}`} {...props} />;
}

export function Badge({
  tone = "neutral",
  className = "",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: "success" | "warning" | "danger" | "info" | "neutral" }) {
  return <span className={`badge badge-${tone} ${className}`} {...props} />;
}

export function Button({ className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={`button ${className}`} {...props} />;
}

// ---------------------------------------------------------------------------
// Security visual language (Phase 10.4, section 16): a single semantic scale
// used everywhere severity/status is shown, so "critical" always looks and
// reads the same whether it comes from a finding, a risk or a health check.
// Never relies on color alone -- every state also carries an icon and a text
// label, so it survives grayscale/color-blind viewing and screen readers.
// ---------------------------------------------------------------------------

export type SecurityState =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational"
  | "healthy"
  | "warning"
  | "failed"
  | "unknown"
  | "offline";

const SECURITY_STATE_META: Record<
  SecurityState,
  { label: string; tone: "success" | "warning" | "danger" | "info" | "neutral"; icon: React.ElementType }
> = {
  critical: { label: "Crítico", tone: "danger", icon: ShieldAlert },
  high: { label: "Elevado", tone: "danger", icon: AlertTriangle },
  medium: { label: "Médio", tone: "warning", icon: CircleAlert },
  low: { label: "Baixo", tone: "info", icon: Info },
  informational: { label: "Informativo", tone: "neutral", icon: Info },
  healthy: { label: "Saudável", tone: "success", icon: CheckCircle2 },
  warning: { label: "Aviso", tone: "warning", icon: AlertTriangle },
  failed: { label: "Falhou", tone: "danger", icon: Ban },
  unknown: { label: "Desconhecido", tone: "neutral", icon: ShieldQuestion },
  offline: { label: "Offline", tone: "neutral", icon: WifiOff },
};

/** Maps common backend strings (severity/status fields) onto SecurityState. */
export function toSecurityState(value: unknown): SecurityState {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized in SECURITY_STATE_META) return normalized as SecurityState;
  if (["active", "open", "valid", "covered", "success", "passed", "installed"].includes(normalized)) {
    return "healthy";
  }
  if (["pending", "pending_authorization", "draft", "downloading"].includes(normalized)) {
    return "warning";
  }
  if (["blocked", "denied", "error", "corrupt", "revoked"].includes(normalized)) {
    return "failed";
  }
  return "unknown";
}

export function SeverityBadge({
  state,
  className = "",
}: {
  state: SecurityState | string;
  className?: string;
}) {
  const resolved = (state in SECURITY_STATE_META ? state : toSecurityState(state)) as SecurityState;
  const meta = SECURITY_STATE_META[resolved];
  const Icon = meta.icon;
  return (
    <Badge tone={meta.tone} className={`gap-1 ${className}`}>
      <Icon size={12} aria-hidden />
      {meta.label}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// State primitives: every ResourcePage/Workspace should use these instead of
// re-implementing loading/empty/error markup inline.
// ---------------------------------------------------------------------------

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="grid place-items-center gap-2 p-12 text-center" role="status">
      <p className="font-semibold text-foreground">{title}</p>
      {description && <p className="max-w-md text-sm text-muted">{description}</p>}
      {action}
    </div>
  );
}

export function ErrorState({
  title = "Não foi possível carregar os dados.",
  description,
}: {
  title?: string;
  description?: string;
}) {
  return (
    <div className="grid place-items-center gap-2 p-12 text-center" role="alert">
      <ShieldAlert className="text-critical" aria-hidden />
      <p className="font-semibold text-foreground">{title}</p>
      {description && <p className="max-w-md text-sm text-muted">{description}</p>}
    </div>
  );
}

export function LoadingState({ label = "A carregar…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted" role="status">
      <Loader2 className="animate-spin" size={16} aria-hidden />
      {label}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tabs: an accessible (roving tabindex, arrow-key navigation, aria-selected)
// tab strip. Used by every Workspace so tab behavior is identical everywhere.
// ---------------------------------------------------------------------------

export function Tabs({
  items,
  active,
  onChange,
}: {
  items: { id: string; label: string; icon?: React.ElementType }[];
  active: string;
  onChange: (id: string) => void;
}) {
  const refs = React.useRef<Record<string, HTMLButtonElement | null>>({});

  function focusAndSelect(id: string) {
    onChange(id);
    refs.current[id]?.focus();
  }

  function onKeyDown(event: React.KeyboardEvent, index: number) {
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      event.preventDefault();
      const delta = event.key === "ArrowRight" ? 1 : -1;
      const next = items[(index + delta + items.length) % items.length];
      focusAndSelect(next.id);
    }
  }

  return (
    <div role="tablist" aria-label="Secções" className="flex gap-1 overflow-x-auto border-b border-border px-4 pt-3">
      {items.map((item, index) => {
        const selected = item.id === active;
        const Icon = item.icon;
        return (
          <button
            key={item.id}
            ref={(node) => {
              refs.current[item.id] = node;
            }}
            role="tab"
            id={`tab-${item.id}`}
            aria-selected={selected}
            aria-controls={`tabpanel-${item.id}`}
            tabIndex={selected ? 0 : -1}
            onKeyDown={(event) => onKeyDown(event, index)}
            onClick={() => onChange(item.id)}
            className={`flex items-center gap-1.5 whitespace-nowrap border-b-2 px-4 py-3 text-sm transition ${
              selected ? "border-primary text-primary" : "border-transparent text-muted hover:text-foreground"
            }`}
          >
            {Icon && <Icon size={14} aria-hidden />}
            {item.label}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  id,
  active,
  children,
}: {
  id: string;
  active: string;
  children: React.ReactNode;
}) {
  if (id !== active) return null;
  return (
    <div role="tabpanel" id={`tabpanel-${id}`} aria-labelledby={`tab-${id}`} tabIndex={0}>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Drawer: a lightweight, accessible side panel (used by the contextual Cyber
// AI panel and future detail drawers). Traps Escape-to-close and restores
// focus to the trigger.
// ---------------------------------------------------------------------------

export function Drawer({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  const triggerRef = React.useRef<Element | null>(null);

  React.useEffect(() => {
    if (!open) return;
    triggerRef.current = document.activeElement;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      if (triggerRef.current instanceof HTMLElement) triggerRef.current.focus();
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="presentation">
      <button
        aria-label="Fechar painel"
        className="absolute inset-0 bg-black/50"
        onClick={onClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="relative flex h-full w-full max-w-md flex-col border-l border-border bg-surface p-5 shadow-panel"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-semibold">{title}</h2>
          <button className="icon-button" aria-label="Fechar" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </aside>
    </div>
  );
}

export { HelpCircle as UnknownIcon };
