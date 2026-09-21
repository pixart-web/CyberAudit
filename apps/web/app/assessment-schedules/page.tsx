import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Agendamentos" endpoint="/assessment-schedules" columns={[["engagement_id","Auditoria"],["scan_profile_id","Perfil"],["recurrence","Recorrência"],["timezone","Timezone"],["enabled","Ativo"],["next_run_at","Próxima execução"]]}/>}
