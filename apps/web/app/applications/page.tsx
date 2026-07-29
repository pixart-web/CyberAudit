import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Aplicações" endpoint="/applications" rowHref={(item) => `/applications/${item.id}`} columns={[["name", "Aplicação"], ["application_type", "Tipo"], ["lifecycle_status", "Ciclo de vida"], ["business_criticality", "Criticidade"], ["appsec_score", "AppSec score"], ["internet_exposed", "Internet"]]} />;
}
