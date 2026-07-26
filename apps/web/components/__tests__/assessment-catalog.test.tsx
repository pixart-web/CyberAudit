import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import AssessmentCatalog from "@/app/assessment-catalog/page";

vi.mock("next/navigation",()=>({usePathname:()=>"/assessment-catalog"}));
vi.mock("@/lib/api",()=>({api:async()=>({items:[{id:"p1",name:"Headers HTTP",description:"HEAD e GET limitado.",category:"http_security_headers",adapter_code:"cyberaudit.http_security_headers",default_intensity:"low",timeout_seconds:20,target_types:["url"],network_access:true}]})}));

test("shows safe profile impact and excludes offensive actions",async()=>{
  render(<QueryClientProvider client={new QueryClient()}><AssessmentCatalog/></QueryClientProvider>);
  expect(await screen.findByText("Headers HTTP")).toBeInTheDocument();
  expect(screen.getByText(/Sem exploração, credenciais, brute force ou comandos livres/)).toBeInTheDocument();
  expect(screen.getByText(/rede limitada/)).toBeInTheDocument();
});
