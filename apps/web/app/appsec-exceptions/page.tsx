import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Exceções AppSec" endpoint="/appsec-exceptions" columns={[["exception_type", "Tipo"], ["status", "Estado"], ["reason", "Motivo"], ["expires_at", "Expira"], ["review_date", "Revisão"], ["created_at", "Pedido"]]} />;
}
