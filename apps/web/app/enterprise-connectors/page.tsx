import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Conectores Enterprise" endpoint="/enterprise-connectors" columns={[
    ["name", "Conector"], ["connector_type", "Domínio"], ["provider", "Provider"],
    ["status", "Estado"], ["health_status", "Saúde"], ["last_synced_at", "Última sync"],
  ]} />;
}
