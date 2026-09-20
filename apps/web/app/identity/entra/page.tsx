import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Microsoft Entra ID" endpoint="/identity/entra/applications" columns={[
    ["name", "Objeto"], ["object_type", "Tipo"], ["owner", "Responsável"],
    ["risk_score", "Risco"], ["last_seen_at", "Última observação"],
  ]} />;
}
