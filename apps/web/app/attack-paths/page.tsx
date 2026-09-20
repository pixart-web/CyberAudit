import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Attack Paths" endpoint="/attack-paths" columns={[["name","Caminho candidato"],["entry_point","Entrada"],["target_asset_id","Destino"],["overall_risk","Risco"],["confidence","Confiança"],["status","Revisão"]]}/>}
