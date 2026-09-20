import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Google Workspace" endpoint="/saas/google-workspace/posture" columns={[
    ["name", "Área"], ["object_type", "Tipo"], ["status", "Estado"],
    ["owner", "Responsável"], ["last_seen_at", "Última observação"],
  ]} />;
}
