"use client";

import { useParams } from "next/navigation";
import { Entity360, RelatedTable } from "@/components/appsec-detail";

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <Entity360 title="SBOM 360" endpoint={`/sboms/${id}`} fields={[["format", "Formato"], ["specification_version", "Versão"], ["serial_number", "Serial"], ["document_hash", "SHA-256"], ["component_count", "Componentes"], ["dependency_count", "Dependências"], ["direct_dependency_count", "Diretas"], ["transitive_dependency_count", "Transitivas"], ["generated_by", "Gerado por"], ["validated", "Validado"], ["validation_errors", "Alertas"]]}>
    <RelatedTable title="Componentes" endpoint={`/sboms/${id}/components`} columns={[["name", "Componente"], ["version", "Versão"], ["purl", "PURL"], ["direct_dependency", "Direta"], ["licenses", "Licenças"]]} />
  </Entity360>;
}
