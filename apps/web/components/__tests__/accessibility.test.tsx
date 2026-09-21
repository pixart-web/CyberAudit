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
import { IdentityWorkspace } from "../identity-workspace";
import { ControlWorkspace } from "../control-workspace";
import { EngagementWorkspace } from "../engagement-workspace";
import { SocCommandCenter } from "../enterprise-command-center";
import SecurityEventDetail from "@/app/security-events/[id]/page";
import DetectionAlertDetail from "@/app/detections/[id]/page";
import CaseDetail from "@/app/cases/[id]/page";
import HuntDetail from "@/app/hunts/[id]/page";
import RiskRegisterDetail from "@/app/grc/risks/[id]/page";
import ZeroTrustAssessmentDetail from "@/app/zero-trust/assessments/[id]/page";
import CloudAccountDetail from "@/app/cloud-security/accounts/[id]/page";
import KubernetesWorkloadDetail from "@/app/kubernetes/workloads/[id]/page";
import IocDetail from "@/app/threat-intelligence/[id]/page";
import KnowledgeNodeDetail from "@/app/knowledge-graph/[id]/page";
import CommandCenterPage from "@/app/command-center/page";
import AssetGraphPage from "@/app/asset-graph/page";
import KnowledgeGraphPage from "@/app/knowledge-graph/page";
import ReportsPage from "@/app/reports/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({
  usePathname: () => "/incidents/inc-1",
  useParams: () => ({ id: "obj-1" }),
}));

const socFixtures: Record<string, unknown> = {
  "/security-events/obj-1": {
    event: {
      id: "obj-1",
      source: "edr",
      event_type: "login_failed",
      severity: "high",
      occurred_at: "2026-09-20T00:00:00Z",
      actor_ref: "user@example.invalid",
      asset_id: "asset-1",
      source_ip: "10.0.0.1",
      destination_ip: null,
      summary: "Repeated failed login",
      normalized: { attempts: 5 },
      labels: ["brute-force"],
      content_hash: "a".repeat(64),
      trusted: false,
    },
    alerts: [{ id: "alert-1", title: "Brute force detected", severity: "high", status: "open" }],
  },
  "/detections/alerts/obj-1": {
    alert: {
      id: "obj-1",
      title: "Brute force detected",
      severity: "high",
      status: "open",
      confidence: 0.8,
      fingerprint: "fp-1",
      incident_id: "incident-1",
      event_id: "event-1",
      reasons: ["5 failed logins in 60s"],
      mitre_techniques: ["T1110"],
      occurrence_count: 5,
      first_seen_at: "2026-09-20T00:00:00Z",
      last_seen_at: "2026-09-20T00:05:00Z",
    },
    rule: { id: "rule-1", name: "Brute force rule", description: "Detects repeated failures", severity: "high" },
    event: { id: "event-1", summary: "Repeated failed login", source: "edr" },
  },
  "/cases/obj-1": {
    case: {
      id: "obj-1",
      reference: "CASE-1",
      title: "Suspicious authentication activity",
      status: "open",
      lead_investigator_id: "analyst-1",
      members: ["analyst-1"],
      hypothesis: "Credential stuffing attempt",
      conclusions: "",
      legal_hold: true,
      incident_id: "incident-1",
    },
    incident: { id: "incident-1", reference: "INC-1", title: "Anomalous auth activity", status: "investigating" },
  },
  "/hunts/obj-1": {
    id: "obj-1",
    name: "Brute force hunt",
    hypothesis: "Repeated login failures may indicate brute force",
    query: { event_type: "login_failed" },
    status: "draft",
    time_from: "2026-09-19T00:00:00Z",
    time_until: "2026-09-20T00:00:00Z",
    result_count: 0,
    findings: [],
  },
  "/identity/users/obj-1": {
    id: "obj-1",
    username: "jdoe",
    display_name: "Jane Doe",
    email: "jdoe@example.invalid",
    identity_type: "user",
    enabled: true,
    privileged: true,
    guest: false,
    service_account: false,
    owner: null,
    department: "Engineering",
    job_title: "SRE",
    mfa_state: "false",
    risk_state: "high",
    risk_score: 60,
    last_login_at: "2026-09-19T00:00:00Z",
    last_activity_at: "2025-01-01T00:00:00Z",
  },
  "/identity/users/obj-1/risk": {
    score: 90,
    reasons: ["privileged_identity", "mfa_not_enforced"],
    calculation_version: "identity-risk-1.0.0",
  },
  "/grc/risks/obj-1": {
    risk: {
      id: "obj-1",
      reference: "RISK-000001",
      title: "Unpatched public-facing service",
      description: "A public service is missing critical patches.",
      risk_type: "cyber",
      category: "vulnerability_management",
      status: "open",
      asset_id: null,
      third_party: null,
      likelihood: 4,
      impact: 4,
      inherent_score: 16,
      control_effectiveness: 0.25,
      residual_score: 12,
      appetite: 5,
      treatment_strategy: "mitigate",
    },
    treatments: [],
  },
  "/zero-trust/assessments/obj-1": {
    id: "obj-1",
    subject_type: "asset",
    subject_id: null,
    score: 62,
    status: "weak",
    confidence: 0.7,
    recommendations: [],
    unknown_factors: [],
    algorithm_version: "zero-trust-1.0.0",
    evaluated_at: "2026-09-20T00:00:00Z",
    dimensions: [],
  },
  "/cloud/accounts/obj-1": {
    account: {
      id: "obj-1",
      provider: "aws",
      account_type: "standard",
      external_id: "123456789012-demo",
      name: "AWS environment",
      environment: "laboratory",
      owner: null,
      criticality: "high",
      status: "active",
      risk_score: 85,
    },
    resources: [],
  },
  "/kubernetes/workloads/obj-1": {
    workload: {
      id: "obj-1",
      object_type: "workload",
      namespace: "demo",
      name: "Privileged workload",
      privileged: true,
      public_exposure: false,
      risk_score: 92,
      configuration_hash: "b".repeat(64),
    },
    cluster: null,
  },
  "/iocs/obj-1": {
    indicator: {
      id: "obj-1",
      indicator_type: "ip",
      display_value: "198.51.100.7",
      confidence: 0.9,
      severity: "high",
      status: "active",
      valid_from: "2026-09-01T00:00:00Z",
      valid_until: null,
      labels: [],
      references: [],
    },
    feed: null,
  },
  "/knowledge-nodes/obj-1": {
    node: {
      id: "obj-1",
      node_type: "finding",
      source_id: "finding-1",
      label: "Missing security headers",
      facts: {},
      source_references: [],
      confidence: 0.95,
      indexed_at: "2026-09-20T00:00:00Z",
    },
    outgoing_edges: [],
    incoming_edges: [],
  },
  "/grc/controls/obj-1": {
    id: "obj-1",
    code: "CTL-1",
    title: "MFA everywhere",
    description: "test",
    domain: "identity",
    objective: "",
    status: "approved",
    maturity_level: 3,
    implementation_status: "partially_implemented",
    next_review_at: null,
  },
  "/engagements/obj-1": {
    id: "obj-1",
    code: "ENG-1",
    name: "Avaliação de segurança",
    mode: "client",
    status: "active",
    risk_level: "medium",
  },
  "/command-center": {
    security_posture: 60,
    exposure_score: 35,
    assets: 1,
    new_assets: 0,
    unmanaged_assets: 0,
    internet_exposed_assets: 0,
    open_services: 1,
    critical_findings: 0,
    known_exploited: 0,
    coverage: 90,
    running_jobs: 0,
    open_incidents: 0,
    active_engagements: 1,
    failing_controls: 0,
    high_risk_identities: 0,
    top_assets: [{ id: "asset-1", name: "Demo Asset", risk: 42 }],
  },
  "/asset-graph?max_nodes=100": {
    nodes: [
      { id: "asset-1", label: "Demo Asset", type: "host", criticality: "medium", exposure: "internal", risk_score: 42, confidence: 0.9 },
    ],
    edges: [],
    limit: 100,
    progressive: false,
  },
  "/knowledge-graph": {
    nodes: [{ id: "node-1", node_type: "incident", label: "Demo node", confidence: 0.9 }],
    edges: [],
  },
  "/findings?page_size=100": {
    items: [
      { id: "finding-1", title: "Demo finding", category: "network", technical_severity: "medium", affected_component: "demo", simulated: true, imported: false },
    ],
    total: 1,
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => {
    if (path in socFixtures) return socFixtures[path];
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

  test("IdentityWorkspace has no automated a11y violations", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <IdentityWorkspace id="obj-1" />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });

  test("ControlWorkspace has no automated a11y violations", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <ControlWorkspace id="obj-1" />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });

  test("EngagementWorkspace has no automated a11y violations", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <EngagementWorkspace id="obj-1" />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });

  test("SocCommandCenter (SOC dashboard) has no automated a11y violations", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <SocCommandCenter />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
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

  test.each([
    ["Security Event detail", SecurityEventDetail],
    ["Detection Alert detail", DetectionAlertDetail],
    ["Case detail", CaseDetail],
    ["Hunt detail", HuntDetail],
    ["Risk Register detail", RiskRegisterDetail],
    ["Zero Trust assessment detail", ZeroTrustAssessmentDetail],
    ["Cloud Account detail", CloudAccountDetail],
    ["Kubernetes Workload detail", KubernetesWorkloadDetail],
    ["IOC detail", IocDetail],
    ["Knowledge Node detail", KnowledgeNodeDetail],
    ["Command Center", CommandCenterPage],
    ["Cyber Asset Graph (incl. table-view fallback)", AssetGraphPage],
    ["Knowledge Graph (list)", KnowledgeGraphPage],
    ["Reports (executive summary)", ReportsPage],
  ])("SOC/Risk Workspace: %s has no automated a11y violations", async (_label, Page) => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <Page />
      </QueryClientProvider>,
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    const violations = await auditedViolations(container);
    expect(violations, JSON.stringify(violations, null, 2)).toHaveLength(0);
  });
});
