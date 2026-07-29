import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Active Directory" endpoint="/identity/active-directory/domains" columns={[
    ["name", "Domínio"], ["object_type", "Tipo"], ["status", "Estado"],
    ["privileged", "Privilegiado"], ["last_seen_at", "Última observação"],
  ]} />;
}
