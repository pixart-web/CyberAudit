import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Compliance Frameworks" endpoint="/grc/frameworks" columns={[["name", "Referencial"], ["code", "Código"], ["version", "Versão"], ["framework_type", "Tipo"], ["enabled", "Ativo"]]} />;
}
