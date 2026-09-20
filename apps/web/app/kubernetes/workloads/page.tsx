import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Workloads Kubernetes" endpoint="/kubernetes/workloads" rowHref="/kubernetes/workloads" columns={[
    ["name", "Workload"], ["namespace", "Namespace"], ["object_type", "Tipo"],
    ["privileged", "Privilegiado"], ["public_exposure", "Público"], ["risk_score", "Risco"],
  ]} />;
}
