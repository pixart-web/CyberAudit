import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Case Management" endpoint="/cases" rowHref="/cases" columns={[["reference", "Referência"], ["title", "Caso"], ["status", "Estado"], ["lead_investigator_id", "Investigador"], ["legal_hold", "Legal hold"]]} />;
}
