import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import AssetGraphPage from "@/app/asset-graph/page";

vi.mock("next/navigation",()=>({usePathname:()=>"/asset-graph"}));
vi.mock("@/lib/api",()=>({api:async()=>({nodes:[{id:"a1",label:"demo-edge",type:"host",risk_score:82,exposure:"internet",criticality:"critical",confidence:.9}],edges:[],truncated:false})}));

test("renders bounded graph and accessible zoom controls",async()=>{
  render(<QueryClientProvider client={new QueryClient()}><AssetGraphPage/></QueryClientProvider>);
  expect(await screen.findByText("demo-edge")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button",{name:"Aumentar zoom"}));
  expect(screen.getByText(/não representam exploração/i)).toBeInTheDocument();
});
