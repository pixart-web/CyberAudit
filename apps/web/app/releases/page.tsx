import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Releases" endpoint="/releases" rowHref="/releases" columns={[["version", "Versão"], ["artifact_identifier", "Artefacto"], ["status", "Estado"], ["signed", "Assinado"], ["provenance_verified", "Proveniência"], ["created_at", "Criado"]]} />;
}
