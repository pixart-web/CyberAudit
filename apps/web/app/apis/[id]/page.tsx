"use client";

import { useParams } from "next/navigation";
import { Entity360, RelatedTable } from "@/components/appsec-detail";

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <Entity360 title="API 360" endpoint={`/apis/${id}`} fields={[["name", "API"], ["api_type", "Tipo"], ["visibility", "Visibilidade"], ["base_url", "Base URL"], ["version", "Versão"], ["specification_type", "Especificação"], ["authentication_type", "Autenticação"], ["authorization_model", "Autorização"], ["data_classification", "Dados"], ["risk_score", "Risco"], ["confidence", "Confiança"], ["last_assessed_at", "Última avaliação"]]}>
    <RelatedTable title="Endpoints declarados" endpoint={`/apis/${id}/endpoints`} columns={[["method", "Método"], ["normalized_path", "Path"], ["authentication_required", "Autenticação"], ["sensitive", "Sensível"], ["deprecated", "Deprecated"]]} />
  </Entity360>;
}
