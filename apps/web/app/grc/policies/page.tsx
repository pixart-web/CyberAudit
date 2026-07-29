import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Governance Policies" endpoint="/grc/policies" columns={[["title", "Política"], ["code", "Código"], ["version", "Versão"], ["status", "Estado"], ["review_at", "Revisão"], ["expires_at", "Expiração"]]} />;
}
