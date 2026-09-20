import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import CommandCenterPage from "@/app/command-center/page";

afterEach(cleanup);

vi.mock("next/navigation",()=>({usePathname:()=>"/command-center"}));
vi.mock("@/lib/api",()=>({api:async()=>({security_posture:71,exposure_score:34,assets:5,new_assets:1,unmanaged_assets:1,internet_exposed_assets:1,open_services:3,critical_findings:1,known_exploited:0,coverage:82,running_jobs:1,open_incidents:2,active_engagements:4,failing_controls:3,high_risk_identities:1,top_assets:[{id:"a1",name:"demo-edge",risk:82}]})}));

test("renders tenant command center metrics and top-risk asset",async()=>{
  render(<QueryClientProvider client={new QueryClient()}><CommandCenterPage/></QueryClientProvider>);
  expect(await screen.findByText("demo-edge")).toBeInTheDocument();
  expect(screen.getByText("71%")).toBeInTheDocument();
  expect(screen.getByText("Serviços abertos")).toBeInTheDocument();
});

test("cross-domain attention panel drills down into Incidents, Engagements, Controls and Identity", async () => {
  render(<QueryClientProvider client={new QueryClient()}><CommandCenterPage/></QueryClientProvider>);
  expect(await screen.findByText("Incidentes ativos")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Incidentes ativos/ })).toHaveAttribute("href", "/incidents");
  expect(screen.getByRole("link", { name: /Auditorias ativas/ })).toHaveAttribute("href", "/engagements");
  expect(screen.getByRole("link", { name: /Controlos não implementados/ })).toHaveAttribute("href", "/grc/controls");
  expect(screen.getByRole("link", { name: /Identidades de alto risco/ })).toHaveAttribute("href", "/identity/users");
});
