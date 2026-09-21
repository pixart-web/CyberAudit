import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Ambientes" endpoint="/environments" columns={[["name","Nome"],["environment_type","Tipo"],["criticality","Criticidade"],["exposure","Exposição"],["owner","Responsável"],["active","Ativo"]]}/>}
