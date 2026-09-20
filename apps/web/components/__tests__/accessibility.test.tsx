/**
 * Phase 10.4.1 measured accessibility pass (section 78): real automated
 * tooling (axe-core), not a claim of compliance without evidence. This
 * runs axe's rule engine against jsdom-rendered output for the shared
 * design-system primitives and one representative Workspace, and reports
 * actual violations rather than asserting a hand-picked subset of rules.
 *
 * Known, documented limitation: jsdom does not implement layout (no
 * getBoundingClientRect/computed visibility), so axe's small set of
 * layout-dependent rules (e.g. color-contrast, which needs rendered
 * pixels) cannot run here and are excluded explicitly below. This is
 * disclosed, not silently worked around -- a real color-contrast audit
 * needs a real browser and is out of reach of this jsdom-based suite.
 */
import axe from "axe-core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  Badge,
  ConfirmationDialog,
  EmptyState,
  ErrorState,
  MetricCard,
  SeverityBadge,
  Tabs,
  TabPanel,
} from "@cyberaudit/ui";
import { IncidentWorkspace } from "../incident-workspace";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/incidents/inc-1" }));
vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path.startsWith("/incidents/")) {
      return {
        incident: {
          id: "inc-1",
          reference: "INC-1",
          title: "Atividade suspeita",
          description: "Descrição",
          severity: "high",
          status: "investigating",
          category: "security_event",
          business_impact: "",
          risk_score: 8,
          detected_at: "2026-09-20T00:00:00Z",
        },
        timeline: [],
      };
    }
    return { items: [] };
  },
}));

const AXE_OPTIONS: axe.RunOptions = {
  // Rules that need real rendered layout/pixels, unavailable in jsdom.
  rules: {
    "color-contrast": { enabled: false },
    "focus-order-semantics": { enabled: false },
  },
};

async function auditedViolations(container: HTMLElement) {
  const results = await axe.run(container, AXE_OPTIONS);
  return results.violations;
}

describe("axe-core automated accessibility audit (jsdom, layout rules excluded)", () => {
  test("design-system state primitives have no automated a11y violations", async () => {
    const { container } = render(
      <div>
        <Badge tone="danger">Crítico</Badge>
        <SeverityBadge state="critical" />
        <EmptyState title="Ainda não existem registos." description="Sem dados para mostrar." />
        <ErrorState title="Não foi possível carregar os dados." />
        <MetricCard label="Findings abertos" value={3} tone="high" />
      </div>,
    );
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });

  test("Tabs/TabPanel expose correct roles with no automated a11y violations", async () => {
    const { container } = render(
      <div>
        <Tabs
          items={[
            { id: "overview", label: "Visão Geral" },
            { id: "scope", label: "Âmbito" },
          ]}
          active="overview"
          onChange={() => {}}
        />
        <TabPanel id="overview" active="overview">
          Conteúdo
        </TabPanel>
      </div>,
    );
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });

  test("ConfirmationDialog (role=alertdialog) has no automated a11y violations", async () => {
    const { container } = render(
      <ConfirmationDialog
        open={true}
        title="Cancelar este incidente?"
        description="Esta ação é terminal."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });

  test("IncidentWorkspace (a full Workspace page) has no automated a11y violations", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <IncidentWorkspace id="inc-1" />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });
});
