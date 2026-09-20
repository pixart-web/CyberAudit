import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Organização"
      endpoint="/organizations"
      columns={[["name", "Nome"], ["slug", "Identificador"], ["status", "Estado"], ["created_at", "Criada em"]]}
    />
  );
}
