import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Identidades" endpoint="/identity/users" columns={[
    ["display_name", "Identidade"], ["identity_type", "Tipo"], ["mfa_state", "MFA"],
    ["privileged", "Privilegiada"], ["risk_score", "Risco"], ["last_seen_at", "Última observação"],
  ]} />;
}
