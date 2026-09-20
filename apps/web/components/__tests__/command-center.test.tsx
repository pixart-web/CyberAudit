import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import CommandCenterPage from "@/app/command-center/page";

vi.mock("next/navigation",()=>({usePathname:()=>"/command-center"}));
vi.mock("@/lib/api",()=>({api:async()=>({security_posture:71,exposure_score:34,assets:5,new_assets:1,unmanaged_assets:1,internet_exposed_assets:1,open_services:3,critical_findings:1,known_exploited:0,coverage:82,running_jobs:1,top_assets:[{id:"a1",name:"demo-edge",risk:82}]})}));

test("renders tenant command center metrics and top-risk asset",async()=>{
  render(<QueryClientProvider client={new QueryClient()}><CommandCenterPage/></QueryClientProvider>);
  expect(await screen.findByText("demo-edge")).toBeInTheDocument();
  expect(screen.getByText("71%")).toBeInTheDocument();
  expect(screen.getByText("Serviços abertos")).toBeInTheDocument();
});
