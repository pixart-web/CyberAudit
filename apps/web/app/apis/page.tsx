import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="APIs" endpoint="/apis" rowHref="/apis" columns={[["name", "API"], ["api_type", "Tipo"], ["visibility", "Visibilidade"], ["version", "Versão"], ["authentication_type", "Autenticação"], ["risk_score", "Risco"]]} />;
}
