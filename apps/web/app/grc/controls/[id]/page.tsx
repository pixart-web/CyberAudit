"use client";

import { useParams } from "next/navigation";
import { ControlWorkspace } from "@/components/control-workspace";

export default function Detail() {
  const { id } = useParams<{ id: string }>();
  return <ControlWorkspace id={id} />;
}
