import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import CloudAccountDetail from "@/app/cloud-security/accounts/[id]/page";
import CloudResourceDetail from "@/app/cloud-security/resources/[id]/page";
import KubernetesWorkloadDetail from "@/app/kubernetes/workloads/[id]/page";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ useParams: () => ({ id: "obj-1" }), usePathname: () => "/cloud-security" }));

const fixtures: Record<string, unknown> = {
  "/cloud/accounts/obj-1": {
    account: {
      id: "obj-1",
      provider: "aws",
      account_type: "standard",
      external_id: "123456789012-demo",
      name: "[DEMO] AWS environment",
      environment: "laboratory",
      owner: null,
      criticality: "high",
      status: "active",
      risk_score: 85,
    },
    resources: [
      { id: "resource-1", name: "[DEMO] Public demo bucket", resource_type: "bucket", public_exposure: true, risk_score: 90 },
    ],
  },
  "/cloud/resources/obj-1": {
    resource: {
      id: "obj-1",
      provider: "aws",
      resource_type: "bucket",
      name: "[DEMO] Public demo bucket",
      region: "demo-region-1",
      environment: "laboratory",
      criticality: "high",
      public_exposure: true,
      managed: true,
      owner: null,
      status: "active",
      risk_score: 90,
      configuration_hash: "a".repeat(64),
    },
    account: { id: "account-1", name: "[DEMO] AWS environment", provider: "aws" },
  },
  "/kubernetes/workloads/obj-1": {
    workload: {
      id: "obj-1",
      object_type: "workload",
      namespace: "demo",
      name: "[DEMO] Privileged workload",
      privileged: true,
      public_exposure: false,
      risk_score: 92,
      configuration_hash: "b".repeat(64),
    },
    cluster: { id: "cluster-1", name: "[DEMO] Enterprise laboratory cluster", provider: "demo", version: "1.31-demo" },
  },
};

vi.mock("@/lib/api", () => ({
  api: async (path: string) => fixtures[path] ?? { items: [] },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("Cloud Account detail lists its resources with a working link", async () => {
  wrapper(<CloudAccountDetail />);
  expect(await screen.findByText("[DEMO] AWS environment")).toBeInTheDocument();
  expect(screen.getByText(/Public demo bucket/, { exact: false })).toBeInTheDocument();
});

test("Cloud Resource detail links back to its account", async () => {
  wrapper(<CloudResourceDetail />);
  expect(await screen.findByText("[DEMO] Public demo bucket")).toBeInTheDocument();
  expect(screen.getByText("Exposição pública")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /AWS environment/ })).toHaveAttribute(
    "href",
    "/cloud-security/accounts/account-1",
  );
});

test("Kubernetes Workload detail shows its parent cluster", async () => {
  wrapper(<KubernetesWorkloadDetail />);
  expect(await screen.findByText("[DEMO] Privileged workload")).toBeInTheDocument();
  expect(screen.getByText("Privilegiado")).toBeInTheDocument();
  expect(screen.getByText("[DEMO] Enterprise laboratory cluster")).toBeInTheDocument();
});
