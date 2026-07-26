import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Clientes" endpoint="/clients" columns={[["name","Nome"],["legal_name","Razão social"],["email","Email"],["status","Estado"],["created_at","Criado em"]]}/>}
