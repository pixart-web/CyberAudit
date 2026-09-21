import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Componentes de Software" endpoint="/components" columns={[["name", "Componente"], ["version", "Versão"], ["component_type", "Tipo"], ["purl", "PURL"], ["direct_dependency", "Direta"], ["scope", "Scope"]]} />;
}
