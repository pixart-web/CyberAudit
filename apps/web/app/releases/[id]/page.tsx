"use client";

import { useParams } from "next/navigation";
import { Entity360 } from "@/components/appsec-detail";

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <Entity360 title="Release 360" endpoint={`/releases/${id}`} fields={[["version", "Versão"], ["artifact_identifier", "Artefacto"], ["artifact_hash", "Hash"], ["commit_hash", "Commit"], ["branch", "Branch"], ["status", "Estado"], ["signed", "Assinado"], ["signature_verified", "Assinatura verificada"], ["provenance_available", "Proveniência"], ["provenance_verified", "Proveniência verificada"], ["sbom_id", "SBOM"], ["released_at", "Release"]]} />;
}
