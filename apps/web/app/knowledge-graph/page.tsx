import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Knowledge Graph" endpoint="/knowledge-nodes" columns={[["label", "Nó"], ["node_type", "Tipo"], ["source_id", "Origem"], ["confidence", "Confiança"], ["indexed_at", "Indexado"]]} />;
}
