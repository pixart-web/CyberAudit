"use client";

import { ShieldAlert, FileSearch, Briefcase } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

type SearchResult = { id: string; label: string; href: string; group: string };

const SOURCES: {
  group: string;
  endpoint: string;
  icon: typeof ShieldAlert;
  labelKey: string;
  href: (id: string) => string;
}[] = [
  { group: "Findings", endpoint: "/findings", icon: ShieldAlert, labelKey: "title", href: (id) => `/findings/${id}` },
  { group: "Incidentes", endpoint: "/incidents", icon: FileSearch, labelKey: "title", href: (id) => `/incidents/${id}` },
  { group: "Auditorias", endpoint: "/engagements", icon: Briefcase, labelKey: "name", href: (id) => `/engagements/${id}` },
];

/**
 * Unified search across authorized objects (section 13). Every query goes
 * through the same endpoints, and therefore the same RBAC/tenant scoping,
 * that their dedicated list pages use -- this component never bypasses
 * domain authorization. A domain the caller lacks permission for simply
 * fails that one request and is dropped from the results.
 */
export function GlobalSearch() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const term = query.trim();
    if (term.length < 2) {
      setResults([]);
      return;
    }
    const timeout = setTimeout(async () => {
      const settled = await Promise.allSettled(
        SOURCES.map(async (source) => {
          const data = await api<{ items: Record<string, unknown>[] }>(
            `${source.endpoint}?q=${encodeURIComponent(term)}`,
          );
          return data.items.slice(0, 5).map((item) => ({
            id: String(item.id),
            label: String(item[source.labelKey] ?? item.id),
            href: source.href(String(item.id)),
            group: source.group,
          }));
        }),
      );
      setResults(
        settled.flatMap((entry) => (entry.status === "fulfilled" ? entry.value : [])),
      );
    }, 250);
    return () => clearTimeout(timeout);
  }, [query]);

  useEffect(() => {
    function onClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const grouped = results.reduce<Record<string, SearchResult[]>>((acc, item) => {
    (acc[item.group] ??= []).push(item);
    return acc;
  }, {});

  return (
    <div ref={containerRef} className="relative hidden min-w-40 max-w-xl flex-1 md:block">
      <label className="relative block">
        <span className="sr-only">Pesquisar em CyberAudit</span>
        <svg
          className="pointer-events-none absolute left-3 top-2.5 text-muted"
          width={17}
          height={17}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          aria-hidden
        >
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        <input
          className="field py-2 pl-10"
          placeholder="Pesquisar findings, incidentes, auditorias…"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          role="combobox"
          aria-expanded={open && results.length > 0}
          aria-controls="global-search-results"
        />
      </label>
      {open && query.trim().length >= 2 && (
        <div
          id="global-search-results"
          role="listbox"
          className="absolute z-30 mt-2 max-h-96 w-full overflow-y-auto rounded-lg border border-border bg-surface p-2 shadow-panel"
        >
          {results.length === 0 && (
            <p className="p-3 text-sm text-muted">Sem resultados autorizados para &ldquo;{query}&rdquo;.</p>
          )}
          {Object.entries(grouped).map(([group, items]) => (
            <div key={group} className="mb-2">
              <p className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-muted/70">{group}</p>
              {items.map((item) => {
                const Icon = SOURCES.find((source) => source.group === group)?.icon ?? ShieldAlert;
                return (
                  <Link
                    key={`${group}-${item.id}`}
                    href={item.href}
                    role="option"
                    aria-selected={false}
                    onClick={() => setOpen(false)}
                    className="flex items-center gap-2 rounded-md px-2 py-2 text-sm hover:bg-white/[.04]"
                  >
                    <Icon size={14} className="text-muted" aria-hidden />
                    {item.label}
                  </Link>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
