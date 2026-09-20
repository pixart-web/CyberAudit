"use client";

import { useParams } from "next/navigation";
import { EngagementWorkspace } from "@/components/engagement-workspace";

export default function Detail() {
  const { id } = useParams<{ id: string }>();
  return <EngagementWorkspace id={id} />;
}
