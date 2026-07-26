import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import EvidenceDetail from "@/app/evidence/[id]/page";

vi.mock("next/navigation",()=>({usePathname:()=>"/evidence/e-1",useParams:()=>({id:"e-1"})}));
vi.mock("@/lib/api",()=>({getToken:()=>"test",api:async()=>({id:"e-1",title:"Headers sanitizados",description:"Preview seguro",evidence_type:"http_headers",sensitivity:"internal",redacted:true,mime_type:"application/json",size_bytes:120,collected_by_adapter:"cyberaudit.http_security_headers",sanitized_content:"{\"set-cookie\":[\"session=[REDACTED]\"]}",evidence_metadata:{untrusted:true}})}));

test("renders evidence as inert preformatted text and marks redaction",async()=>{
  render(<QueryClientProvider client={new QueryClient()}><EvidenceDetail/></QueryClientProvider>);
  expect(await screen.findByText("Headers sanitizados")).toBeInTheDocument();
  expect(screen.getByText("Redigida")).toBeInTheDocument();
  expect(screen.getByText(/session=\[REDACTED\]/)).toBeInTheDocument();
  expect(screen.getByText(/HTML, JavaScript e SVG nunca são renderizados/)).toBeInTheDocument();
});
