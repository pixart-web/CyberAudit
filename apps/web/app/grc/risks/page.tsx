import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Enterprise Risk Register" endpoint="/grc/risks" rowHref="/grc/risks" columns={[["reference", "Referência"], ["title", "Risco"], ["risk_type", "Tipo"], ["inherent_score", "Inerente"], ["residual_score", "Residual"], ["status", "Estado"]]} />;
}
