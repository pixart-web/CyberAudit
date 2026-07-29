import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Endpoints" endpoint="/endpoints" rowHref="/endpoint-security/devices" columns={[
    ["hostname", "Endpoint"], ["platform", "Plataforma"], ["compliance_state", "Conformidade"],
    ["encryption_state", "Encriptação"], ["edr_state", "EDR"], ["risk_score", "Risco"],
  ]} />;
}
