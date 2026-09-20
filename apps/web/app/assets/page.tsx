"use client";

import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Inventário de Ativos" endpoint="/assets" rowHref="/assets" columns={[["name","Nome"],["asset_type","Tipo"],["primary_ip","IP principal"],["environment_id","Ambiente"],["internet_exposed","Internet"],["risk_score","Risco"],["status","Estado"]]}/>}
