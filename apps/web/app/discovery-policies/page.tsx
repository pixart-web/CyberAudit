import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Discovery Policies" endpoint="/discovery-policies" columns={[["name","Política"],["maximum_hosts","Hosts máx."],["maximum_ports","Portas máx."],["packets_per_second","Taxa/s"],["allow_tcp_discovery","TCP"],["active","Ativa"]]}/>}
