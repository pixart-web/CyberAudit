"use client";

import { useParams } from "next/navigation";
import { Entity360, RelatedTable } from "@/components/appsec-detail";

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <Entity360 title="Repository 360" endpoint={`/repositories/${id}`} fields={[["name", "Repositório"], ["provider", "Provider"], ["repository_identifier", "Identificador"], ["repository_url", "URL declarada"], ["default_branch", "Branch"], ["visibility", "Visibilidade"], ["owner_team", "Equipa"], ["language_summary", "Linguagens"], ["security_posture", "Postura"], ["risk_score", "Risco"], ["integration_status", "Integração"]]}>
    <RelatedTable title="Observações de segredos (sem valor)" endpoint={`/repositories/${id}/secrets`} columns={[["secret_type", "Tipo"], ["masked_prefix", "Máscara"], ["location", "Localização"], ["status", "Estado"], ["confidence", "Confiança"]]} />
  </Entity360>;
}
