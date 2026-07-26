import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Âmbito" endpoint="/scopes" columns={[["name","Nome"],["engagement_id","Auditoria"],["maximum_intensity","Intensidade"],["status","Estado"],["created_at","Criado em"]]}/>}
