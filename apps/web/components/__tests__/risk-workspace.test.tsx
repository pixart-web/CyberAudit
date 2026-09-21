import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import RiskRegisterDetail from "@/app/grc/risks/[id]/page";
import ZeroTrustAssessmentDetail from "@/app/zero-trust/assessments/[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ useParams: () => ({ id: "obj-1" }), usePathname: () => "/grc/risks/obj-1" }));

const fixtures: Record<string, unknown> = {
  "/grc/risks/obj-1": {
    risk: {
      id: "obj-1",
      reference: "RISK-000001",
      title: "Unpatched public-facing service",
      description: "A public service is missing critical patches.",
      risk_type: "cyber",
      category: "vulnerability_management",
      status: "open",
      asset_id: "asset-1",
      third_party: null,
      likelihood: 4,
      impact: 4,
      inherent_score: 16,
      control_effectiveness: 0.25,
      residual_score: 12,
      appetite: 5,
      treatment_strategy: "mitigate",
    },
    treatments: [
      {
        id: "treatment-1",
        title: "Apply vendor patch",
        description: "Schedule maintenance window",
        status: "in_progress",
        target_residual_score: 4,
        progress: 40,
      },
    ],
  },
  "/zero-trust/assessments/obj-1": {
    id: "obj-1",
    subject_type: "asset",
    subject_id: "asset-1",
    score: 62,
    status: "weak",
    confidence: 0.7,
    recommendations: ["Enforce conditional access for this asset"],
    unknown_factors: ["device_compliance_unknown"],
    algorithm_version: "zero-trust-1.0.0",
    evaluated_at: "2026-09-20T00:00:00Z",
    dimensions: [
      {
        id: "dim-1",
        dimension: "identity",
        score: 40,
        status: "weak",
        weight: 1,
        confidence: 0.6,
        unknown_factors: [],
      },
    ],
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Risk Register detail shows deterministic inherent/residual scores and treatment progress", async () => {
  wrapper(<RiskRegisterDetail />);
  expect(await screen.findByText("Unpatched public-facing service")).toBeInTheDocument();
  expect(screen.getByText("Acima do apetite")).toBeInTheDocument();
  expect(screen.getByText("Apply vendor patch")).toBeInTheDocument();
  expect(screen.getByText(/Progresso: 40%/)).toBeInTheDocument();
});

test("Zero Trust assessment detail shows per-dimension scores, never a single opaque number", async () => {
  wrapper(<ZeroTrustAssessmentDetail />);
  expect(await screen.findByText("identity")).toBeInTheDocument();
  expect(screen.getByText("Enforce conditional access for this asset")).toBeInTheDocument();
  expect(screen.getByText(/device_compliance_unknown/)).toBeInTheDocument();
});
