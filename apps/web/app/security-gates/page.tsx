import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Security Gates" endpoint="/security-gates" columns={[["name", "Política"], ["environment", "Ambiente"], ["minimum_appsec_score", "Score mínimo"], ["maximum_critical_findings", "Críticos"], ["require_sbom", "Exige SBOM"], ["enabled", "Ativa"]]} />;
}
