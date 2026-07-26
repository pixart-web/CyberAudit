import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Ativos" endpoint="/assets" columns={[["name","Nome"],["asset_type","Tipo"],["identifier","Identificador"],["ip_address","IP"],["criticality","Criticidade"],["status","Estado"]]}/>}
