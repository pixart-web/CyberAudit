import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import AssetDetailPage from "@/app/assets/[id]/page";

vi.mock("next/navigation",()=>({usePathname:()=>"/assets/a1",useParams:()=>({id:"a1"})}));
vi.mock("@/lib/api",()=>({api:async()=>({asset:{id:"a1",name:"demo-edge",asset_type:"server",primary_ip:"127.0.0.1",lifecycle_status:"active",managed:true,internet_exposed:false,risk_score:42,exposure_score:20,confidence:.9,source:"phase4_demo_seed",tags:[]},services:[{id:"s1",port:8080,transport_protocol:"tcp",service_name:"http",state:"open",confidence:.8}],findings:[]})}));

test("renders Asset 360 with observed services and confidence",async()=>{
  render(<QueryClientProvider client={new QueryClient()}><AssetDetailPage/></QueryClientProvider>);
  expect((await screen.findAllByText("demo-edge")).length).toBeGreaterThan(0);
  expect(screen.getByText("8080/tcp")).toBeInTheDocument();
  expect(screen.getByText(/confiança 90%/)).toBeInTheDocument();
  expect(screen.getByText("Nenhum finding associado.")).toBeInTheDocument();
});
