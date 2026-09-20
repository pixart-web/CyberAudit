import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Deteções" endpoint="/detections/alerts" columns={[["title", "Deteção"], ["severity", "Severidade"], ["status", "Estado"], ["confidence", "Confiança"], ["occurrence_count", "Ocorrências"], ["last_seen_at", "Última observação"]]} />;
}
