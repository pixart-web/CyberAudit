import { ResourcePage } from "@/components/resource-page";
export default function AssetObservations(){return <ResourcePage title="Observações de Ativos" endpoint="/asset-observations" columns={[["observation_type","Tipo"],["confidence","Confiança"],["source_adapter","Adaptador"],["asset_id","Ativo"],["observed_at","Observada"]]}/>}
