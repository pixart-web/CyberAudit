"use client";

import { Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export type CommandItem = { label: string; href: string; group: string; icon?: React.ElementType };

/**
 * Keyboard-accessible command palette (section 14): pure application
 * navigation over the existing, authorized route set. Never exposes a
 * shell/terminal-style arbitrary command; every entry is a fixed href the
 * user is already allowed to reach through the sidebar.
 */
export function CommandPalette({ items }: { items: CommandItem[] }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = query.trim()
    ? items.filter((item) => item.label.toLowerCase().includes(query.trim().toLowerCase()))
    : items.slice(0, 8);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      } else if (event.key === "Escape" && open) {
        setOpen(false);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  function navigate(href: string) {
    setOpen(false);
    window.location.assign(href);
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) => Math.min(index + 1, filtered.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => Math.max(index - 1, 0));
    } else if (event.key === "Enter" && filtered[activeIndex]) {
      navigate(filtered[activeIndex].href);
    }
  }

  return (
    <>
      <button
        className="icon-button hidden lg:inline-flex"
        aria-label="Abrir paleta de comandos (Cmd+K)"
        title="Cmd/Ctrl+K"
        onClick={() => setOpen(true)}
      >
        <Search size={16} />
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-[15vh]" role="presentation">
          <button aria-label="Fechar paleta de comandos" className="absolute inset-0" onClick={() => setOpen(false)} />
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Paleta de comandos"
            className="relative w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-panel"
          >
            <input
              ref={inputRef}
              className="field w-full rounded-none border-0 border-b border-border py-3"
              placeholder="Navegar para… (Findings, Engagements, Cyber AI…)"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setActiveIndex(0);
              }}
              onKeyDown={onKeyDown}
              role="combobox"
              aria-expanded={open}
              aria-controls="command-palette-results"
              aria-activedescendant={filtered[activeIndex] ? `cmd-${activeIndex}` : undefined}
            />
            <ul id="command-palette-results" role="listbox" className="max-h-96 overflow-y-auto p-2">
              {filtered.length === 0 && <li className="p-3 text-sm text-muted">Sem correspondências.</li>}
              {filtered.map((item, index) => {
                const Icon = item.icon;
                return (
                  <li key={item.href} id={`cmd-${index}`} role="option" aria-selected={index === activeIndex}>
                    <button
                      onClick={() => navigate(item.href)}
                      onMouseEnter={() => setActiveIndex(index)}
                      className={`flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm ${
                        index === activeIndex ? "bg-primary/10 text-primary" : "hover:bg-white/[.04]"
                      }`}
                    >
                      {Icon && <Icon size={14} aria-hidden />}
                      <span className="flex-1">{item.label}</span>
                      <span className="text-[10px] uppercase tracking-wide text-muted/60">{item.group}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}
