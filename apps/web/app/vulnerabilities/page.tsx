import { ResourcePage } from "@/components/resource-page";
export default function Page(){return <ResourcePage title="Vulnerability Intelligence" endpoint="/vulnerabilities" columns={[["external_id","ID"],["title","Vulnerabilidade"],["severity","Severidade"],["cvss_score","CVSS"],["known_exploited","KEV"],["published_at","Publicada"]]}/>}
