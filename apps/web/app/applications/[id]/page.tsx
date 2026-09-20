"use client";

import { useParams } from "next/navigation";
import { Entity360, RelatedTable } from "@/components/appsec-detail";

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <Entity360 title="Application 360" endpoint={`/applications/${id}`} fields={[["name", "Aplicação"], ["application_type", "Tipo"], ["architecture_type", "Arquitetura"], ["lifecycle_status", "Ciclo de vida"], ["business_criticality", "Criticidade"], ["data_classification", "Dados"], ["internet_exposed", "Exposta à Internet"], ["authentication_type", "Autenticação"], ["authorization_model", "Autorização"], ["appsec_score", "AppSec score"], ["risk_score", "Risco"], ["owners", "Responsáveis"]]}>
    <RelatedTable title="APIs associadas" endpoint={`/apis?application_id=${id}`} columns={[["name", "API"], ["api_type", "Tipo"], ["visibility", "Visibilidade"], ["risk_score", "Risco"]]} />
  </Entity360>;
}
