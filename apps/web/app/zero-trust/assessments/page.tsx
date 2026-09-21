import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return <ResourcePage title="Avaliações Zero Trust" endpoint="/zero-trust/assessments" rowHref="/zero-trust/assessments" columns={[
    ["subject_type", "Âmbito"], ["status", "Estado"], ["score", "Score"],
    ["confidence", "Confiança"], ["algorithm_version", "Algoritmo"], ["evaluated_at", "Avaliada em"],
  ]} />;
}
