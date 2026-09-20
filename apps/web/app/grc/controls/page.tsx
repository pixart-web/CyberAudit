import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Controlos Unificados" endpoint="/grc/controls" columns={[["code", "Código"], ["title", "Controlo"], ["domain", "Domínio"], ["implementation_status", "Implementação"], ["maturity_level", "Maturidade"], ["next_review_at", "Próxima revisão"]]} />;
}
