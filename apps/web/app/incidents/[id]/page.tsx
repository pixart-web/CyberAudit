import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Timeline do Incidente" endpoint="/incidents" columns={[["reference", "Referência"], ["title", "Incidente"], ["severity", "Severidade"], ["status", "Estado"]]} />;
}
