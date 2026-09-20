"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Minus, Plus, RotateCcw } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Graph = { nodes:{id:string;label:string;type:string;risk_score:number;exposure:string;criticality:string;confidence:number}[]; edges:{id:string;source:string;target:string;type:string;confidence:number}[]; truncated?:boolean };
export default function AssetGraphPage(){
  const [zoom,setZoom]=useState(1);
  const {data,error}=useQuery({queryKey:["asset-graph"],queryFn:()=>api<Graph>("/asset-graph?max_nodes=100")});
  return <Shell title="Cyber Asset Graph" eyebrow="Asset Intelligence">
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-4"><Badge tone="info">PostgreSQL graph repository</Badge><span className="text-xs text-muted">{data?.nodes.length??0} nós · {data?.edges.length??0} relações</span><div className="ml-auto flex gap-2"><button className="icon-button" aria-label="Reduzir zoom" onClick={()=>setZoom(Math.max(.7,zoom-.1))}><Minus size={16}/></button><button className="icon-button" aria-label="Repor zoom" onClick={()=>setZoom(1)}><RotateCcw size={16}/></button><button className="icon-button" aria-label="Aumentar zoom" onClick={()=>setZoom(Math.min(1.4,zoom+.1))}><Plus size={16}/></button></div></div>
      {error?<p className="p-8 text-red-300">Não foi possível construir o grafo.</p>:<div className="graph-canvas min-h-[560px] overflow-auto p-8"><div className="mx-auto grid max-w-5xl grid-cols-2 gap-14 md:grid-cols-3 xl:grid-cols-4" style={{transform:`scale(${zoom})`,transformOrigin:"top center"}}>
        {data?.nodes.map((node,index)=><Link href={`/assets/${node.id}`} key={node.id} className={`graph-node relative rounded-xl border p-4 text-center ${node.exposure==="internet"?"border-critical/40":"border-border"} ${index%3===1?"md:translate-y-12":""}`}>
          <span className={`mx-auto mb-3 block h-3 w-3 rounded-full ${node.risk_score>=80?"bg-critical":node.risk_score>=60?"bg-high":"bg-primary"}`}/><b className="block truncate text-sm">{node.label}</b><small className="text-muted">{node.type} · risco {node.risk_score.toFixed(0)}</small>
        </Link>)}
      </div>{data&&data.edges.length>0&&<div className="mx-auto mt-24 grid max-w-5xl gap-2 md:grid-cols-2">{data.edges.map(edge=><div key={edge.id} className="flex items-center gap-2 rounded-lg border border-border/80 bg-card/90 px-3 py-2 text-xs"><span className="truncate">{data.nodes.find(node=>node.id===edge.source)?.label??edge.source}</span><span className="text-cyan">→ {edge.type} →</span><span className="truncate">{data.nodes.find(node=>node.id===edge.target)?.label??edge.target}</span><span className="ml-auto text-muted">{Math.round(edge.confidence*100)}%</span></div>)}</div>}</div>}
      <div className="border-t border-border p-4 text-xs text-muted">As ligações representam relações observadas ou inferidas; não representam exploração. {data?.truncated&&"Vista truncada pelos limites progressivos."}</div>
    </Card>
  </Shell>
}
