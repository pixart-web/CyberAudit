import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { ModelManagement } from "../model-management";

afterEach(cleanup);
vi.mock("next/navigation", () => ({ usePathname: () => "/model-management" }));

const posted: unknown[] = [];

vi.mock("@/lib/api", () => ({
  api: async (path: string, init?: RequestInit) => {
    if (path === "/ai-runtime/models" && (!init || init.method === undefined)) {
      return {
        items: [
          {
            id: "m-1",
            model_id: "qwen2.5:7b",
            family: "qwen",
            version: "2.5",
            quantization: "q4_K_M",
            size_gb: 4.7,
            context_window: 32000,
            capabilities: ["knowledge_query"],
            ram_required_mb: 8192,
            install_status: "installed",
            trust_status: "verified",
          },
        ],
      };
    }
    if (path === "/ai-runtime/hardware") {
      return {
        os_name: "Linux",
        cpu_cores: 8,
        ram_total_mb: 16384,
        ram_available_mb: 8192,
        gpu_vendor: null,
        gpu_model: null,
        profile: "standard",
      };
    }
    if (path === "/ai-runtime/models" && init?.method === "POST") {
      posted.push(JSON.parse(String(init.body)));
      return { id: "m-2" };
    }
    return { items: [] };
  },
}));

function wrapper(component: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{component}</QueryClientProvider>);
}

test("model management never claims to execute model code -- only shows state changes", async () => {
  wrapper(<ModelManagement />);
  expect(await screen.findByText("qwen2.5:7b")).toBeInTheDocument();
  expect(screen.getByText(/Nenhum código de modelo é executado/)).toBeInTheDocument();
  expect(await screen.findByText("standard")).toBeInTheDocument();
});

test("registering a model posts the expected manifest shape", async () => {
  wrapper(<ModelManagement />);
  await screen.findByText("qwen2.5:7b");
  fireEvent.change(screen.getByPlaceholderText("qwen2.5:7b-instruct-q4"), {
    target: { value: "gemma2:9b" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Registar modelo" }));
  await waitFor(() => expect(posted.length).toBeGreaterThan(0));
  expect(posted[0]).toMatchObject({ model_id: "gemma2:9b", family: "qwen" });
});
