import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Autorizações"
      endpoint="/authorizations"
      columns={[["filename", "Documento"], ["status", "Estado"], ["signed_by", "Assinado por"], ["valid_from", "Válido de"], ["valid_until", "Válido até"]]}
    />
  );
}
