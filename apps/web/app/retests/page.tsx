import { ResourcePage } from "@/components/resource-page";
export default function Retests(){return <ResourcePage title="Retestes" endpoint="/retests" columns={[["status","Estado"],["result","Resultado"],["finding_id","Finding"],["retest_job_id","Job"],["created_at","Pedido"]]}/>}
