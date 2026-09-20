import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Serviços Observados" endpoint="/services" columns={[["service_name","Serviço"],["port","Porta"],["transport_protocol","Protocolo"],["state","Estado"],["product","Produto"],["confidence","Confiança"]]}/>}
