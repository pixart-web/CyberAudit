import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Registos de Auditoria" endpoint="/audit-logs" columns={[["created_at","Data"],["action","Ação"],["resource_type","Recurso"],["result","Resultado"],["actor_id","Ator"]]}/>}
