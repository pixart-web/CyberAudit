import { ResourcePage } from "@/components/resource-page";
export default function AssetSuggestions(){return <ResourcePage title="Sugestões de Ativos" endpoint="/asset-suggestions" columns={[["suggestion_type","Tipo"],["reason","Motivo"],["status","Estado"],["asset_id","Ativo"],["created_at","Criada"]]}/>}
