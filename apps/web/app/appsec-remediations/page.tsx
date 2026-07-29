import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Remediação AppSec" endpoint="/appsec-remediations" columns={[["owner_team", "Equipa"], ["status", "Estado"], ["priority", "Prioridade"], ["target_release", "Release alvo"], ["due_date", "Prazo"], ["ticket_reference", "Ticket"]]} />;
}
