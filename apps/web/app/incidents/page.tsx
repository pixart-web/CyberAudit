import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Incidentes" endpoint="/incidents" rowHref="/incidents" columns={[["reference", "Referência"], ["title", "Incidente"], ["severity", "Severidade"], ["status", "Estado"], ["risk_score", "Risco"], ["detected_at", "Detetado"]]} />;
}
