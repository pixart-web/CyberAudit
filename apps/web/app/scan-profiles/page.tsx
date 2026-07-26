import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Perfis de Avaliação" endpoint="/scan-profiles" columns={[
    ["name", "Nome"],
    ["category", "Categoria"],
    ["adapter_code", "Adaptador"],
    ["default_intensity", "Intensidade"],
    ["timeout_seconds", "Timeout"],
    ["enabled", "Ativo"],
  ]} />;
}
