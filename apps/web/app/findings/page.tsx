import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Findings" endpoint="/findings" columns={[
    ["title", "Finding"],
    ["category", "Categoria"],
    ["affected_component", "Componente"],
    ["technical_severity", "Severidade"],
    ["status", "Estado"],
    ["last_seen_at", "Última deteção"],
  ]} />;
}
