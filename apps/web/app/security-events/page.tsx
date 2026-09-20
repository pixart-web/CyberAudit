import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Eventos de Segurança" endpoint="/security-events" columns={[["summary", "Evento"], ["event_type", "Tipo"], ["source", "Origem"], ["severity", "Severidade"], ["occurred_at", "Ocorrido"], ["trusted", "Confiável"]]} />;
}
