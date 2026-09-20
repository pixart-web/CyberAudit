import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Redes Autorizadas" endpoint="/networks" columns={[["name","Nome"],["cidr","CIDR"],["ip_version","IP"],["scan_allowed","Discovery permitido"],["owner","Responsável"],["active","Ativa"]]}/>}
