"use client";

import { useParams } from "next/navigation";
import { IncidentWorkspace } from "@/components/incident-workspace";

export default function Detail() {
  const { id } = useParams<{ id: string }>();
  return <IncidentWorkspace id={id} />;
}
