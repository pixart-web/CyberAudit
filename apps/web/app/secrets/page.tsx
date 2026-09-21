import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Observações de Segredos" endpoint="/secrets" columns={[["secret_type", "Tipo"], ["masked_prefix", "Máscara"], ["location", "Localização"], ["status", "Estado"], ["confidence", "Confiança"], ["created_at", "Detetado"]]} />;
}
