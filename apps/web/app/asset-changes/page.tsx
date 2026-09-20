import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Alterações de Ativos" endpoint="/asset-changes" columns={[["change_type","Alteração"],["asset_id","Ativo"],["field_name","Campo"],["source","Fonte"],["confidence","Confiança"],["created_at","Data"]]}/>}
