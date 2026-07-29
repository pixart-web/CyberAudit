import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Zonas de Rede" endpoint="/network-zones" columns={[["name","Nome"],["zone_type","Tipo"],["trust_level","Confiança"],["exposure","Exposição"],["internet_access","Internet"],["criticality","Criticidade"]]}/>}
