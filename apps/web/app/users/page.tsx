import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Utilizadores" endpoint="/users" columns={[["name","Nome"],["email","Email"],["status","Estado"]]}/>}
