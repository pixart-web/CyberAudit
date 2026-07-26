import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Aprovações" endpoint="/approvals" columns={[
    ["approval_type", "Tipo"],
    ["job_id", "Job"],
    ["reason", "Motivo"],
    ["expires_at", "Expira em"],
    ["status", "Estado"],
    ["created_at", "Pedido em"],
  ]} />;
}
