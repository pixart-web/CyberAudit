"use client";

import { ShieldCheck } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { api } from "@/lib/api";

type Tokens = { access_token: string; refresh_token: string };

function CallbackHandler() {
  const router = useRouter();
  const parameters = useSearchParams();
  const [error, setError] = useState("");

  useEffect(() => {
    const complete = async () => {
      const code = parameters.get("code");
      const state = parameters.get("state");
      const expectedState = sessionStorage.getItem("oidc_state");
      const verifier = sessionStorage.getItem("oidc_verifier");
      const organization = sessionStorage.getItem("oidc_organization");
      if (!code || !state || !expectedState || state !== expectedState || !verifier || !organization) {
        throw new Error("A transação SSO é inválida ou expirou.");
      }
      const tokens = await api<Tokens>("/auth/oidc/callback", {
        method: "POST",
        body: JSON.stringify({
          organization_slug: organization,
          code,
          state,
          code_verifier: verifier,
        }),
      });
      sessionStorage.setItem("access_token", tokens.access_token);
      sessionStorage.setItem("refresh_token", tokens.refresh_token);
      sessionStorage.removeItem("oidc_state");
      sessionStorage.removeItem("oidc_verifier");
      sessionStorage.removeItem("oidc_organization");
      router.replace("/dashboard");
    };
    complete().catch((cause: unknown) => {
      sessionStorage.removeItem("oidc_state");
      sessionStorage.removeItem("oidc_verifier");
      setError(cause instanceof Error ? cause.message : "Não foi possível concluir o SSO.");
    });
  }, [parameters, router]);

  return (
    <main className="grid min-h-screen place-items-center px-4">
      <section className="w-full max-w-md rounded-2xl border border-border bg-card p-8 text-center">
        <ShieldCheck size={36} className="mx-auto mb-4 text-primary" />
        <h1 className="text-xl font-semibold">Validação de identidade</h1>
        {error ? (
          <div role="alert" className="mt-4 rounded-lg border border-critical/30 p-3 text-red-300">
            {error}
          </div>
        ) : (
          <p className="mt-3 text-sm text-muted">A concluir a sessão segura…</p>
        )}
      </section>
    </main>
  );
}

export default function OidcCallbackPage() {
  return (
    <Suspense fallback={null}>
      <CallbackHandler />
    </Suspense>
  );
}
