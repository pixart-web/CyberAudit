import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Mobile Devices" endpoint="/mobile-devices" rowHref="/mobile-security/devices" columns={[
    ["name", "Dispositivo"], ["platform", "Plataforma"], ["compliance_state", "Conformidade"],
    ["encryption_state", "Encriptação"], ["integrity_state", "Integridade"], ["risk_score", "Risco"],
  ]} />;
}
