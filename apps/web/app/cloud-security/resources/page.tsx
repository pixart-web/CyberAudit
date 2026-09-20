import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Recursos Cloud" endpoint="/cloud/resources" columns={[
    ["name", "Recurso"], ["provider", "Provider"], ["resource_type", "Tipo"],
    ["region", "Região"], ["public_exposure", "Público"], ["risk_score", "Risco"],
  ]} />;
}
