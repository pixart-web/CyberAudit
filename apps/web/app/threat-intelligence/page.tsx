import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Threat Intelligence" endpoint="/iocs" rowHref="/threat-intelligence" columns={[["display_value", "Indicador"], ["indicator_type", "Tipo"], ["severity", "Severidade"], ["confidence", "Confiança"], ["status", "Estado"], ["valid_until", "Validade"]]} />;
}
