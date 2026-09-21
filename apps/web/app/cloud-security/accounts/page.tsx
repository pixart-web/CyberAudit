import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Contas Cloud" endpoint="/cloud/accounts" rowHref="/cloud-security/accounts" columns={[
    ["name", "Conta"], ["provider", "Provider"], ["environment", "Ambiente"],
    ["owner", "Responsável"], ["status", "Estado"], ["risk_score", "Risco"],
  ]} />;
}
