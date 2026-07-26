import { Card } from "@cyberaudit/ui";
import { Construction } from "lucide-react";
import { Shell } from "@/components/shell";

export default async function Development({params}:{params:Promise<{slug:string[]}>}){
  const {slug}=await params;
  const title=slug.map(s=>s.replaceAll("-"," ")).join(" / ");
  return <Shell title={title.charAt(0).toUpperCase()+title.slice(1)}><Card className="grid min-h-[55vh] place-items-center p-8 text-center"><div><span className="mx-auto mb-5 grid h-16 w-16 place-items-center rounded-2xl border border-primary/20 bg-primary/10"><Construction className="text-primary"/></span><h2 className="text-xl font-semibold">Em desenvolvimento</h2><p className="mx-auto mt-2 max-w-md text-sm text-muted">Este módulo está preparado na navegação e será disponibilizado numa próxima fase sem comprometer os controlos de segurança existentes.</p></div></Card></Shell>;
}
