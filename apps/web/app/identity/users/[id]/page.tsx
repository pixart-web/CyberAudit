"use client";

import { useParams } from "next/navigation";
import { IdentityWorkspace } from "@/components/identity-workspace";

export default function Detail() {
  const { id } = useParams<{ id: string }>();
  return <IdentityWorkspace id={id} />;
}
