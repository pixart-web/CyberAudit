import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Repositórios" endpoint="/repositories" rowHref="/repositories" columns={[["name", "Repositório"], ["provider", "Provider"], ["visibility", "Visibilidade"], ["default_branch", "Branch"], ["security_posture", "Postura"], ["integration_status", "Integração"]]} />;
}
