import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Microsoft 365" endpoint="/saas/microsoft365/posture" columns={[
    ["name", "Área"], ["object_type", "Tipo"], ["status", "Estado"],
    ["owner", "Responsável"], ["last_seen_at", "Última observação"],
  ]} />;
}
