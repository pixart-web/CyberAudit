import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Notificações" endpoint="/notifications" columns={[["title","Título"],["notification_type","Tipo"],["severity","Severidade"],["message","Mensagem"],["created_at","Data"],["read_at","Lida"]]}/>}
