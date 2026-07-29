import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Playbooks" endpoint="/playbooks" columns={[["name", "Playbook"], ["code", "Código"], ["version", "Versão"], ["approval_required", "Aprovação"], ["automatic_execution", "Execução automática"], ["enabled", "Ativo"]]} />;
}
