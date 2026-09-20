import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Auditorias" endpoint="/engagements" createHref="/engagements/new" rowHref="/engagements" columns={[["code","Código"],["name","Nome"],["mode","Modo"],["risk_level","Risco"],["status","Estado"],["created_at","Criada em"]]}/>}
