import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Threat Hunting" endpoint="/hunts" rowHref="/hunts" columns={[["name", "Hunt"], ["hypothesis", "Hipótese"], ["status", "Estado"], ["result_count", "Resultados"], ["time_from", "Desde"], ["time_until", "Até"]]} />;
}
