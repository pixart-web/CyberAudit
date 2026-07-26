import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Jobs" endpoint="/jobs" createHref="/jobs/new" columns={[
    ["target_value", "Alvo"],
    ["adapter_code", "Adaptador"],
    ["intensity", "Intensidade"],
    ["progress", "Progresso"],
    ["status", "Estado"],
    ["created_at", "Criado em"],
  ]} />;
}
