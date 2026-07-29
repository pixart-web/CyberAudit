import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Software Bill of Materials" endpoint="/sboms" rowHref={(item) => `/sboms/${item.id}`} columns={[["document_hash", "SHA-256"], ["format", "Formato"], ["specification_version", "Versão"], ["component_count", "Componentes"], ["dependency_count", "Dependências"], ["validated", "Validado"]]} />;
}
