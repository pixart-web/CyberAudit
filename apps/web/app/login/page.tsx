"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound, LockKeyhole, Mail, ShieldCheck } from "lucide-react";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { api } from "@/lib/api";
import { createPkce } from "@/lib/oidc";

const schema = z.object({
  email: z.string().email("Introduza um email válido."),
  password: z.string().min(8, "A password deve ter pelo menos 8 caracteres."),
});
type FormData = z.infer<typeof schema>;

type OidcStartResponse = {
  authorization_url: string;
  state: string;
  expires_in: number;
};

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [oidcLoading, setOidcLoading] = useState(false);
  const [organizationSlug, setOrganizationSlug] = useState("cyberaudit-demo");
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: {
      email: "admin@cyberaudit.local",
      password: "ChangeMe123!",
    },
  });

  const submit = async (values: FormData) => {
    setError("");
    try {
      const token = await api<{ access_token: string; refresh_token: string }>(
        "/auth/login",
        { method: "POST", body: JSON.stringify(values) },
      );
      sessionStorage.setItem("access_token", token.access_token);
      sessionStorage.setItem("refresh_token", token.refresh_token);
      router.push("/dashboard");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Falha na autenticação.");
    }
  };

  const startOidc = async () => {
    setError("");
    setOidcLoading(true);
    try {
      const normalizedOrganization = organizationSlug.trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/.test(normalizedOrganization)) {
        throw new Error("Introduza o identificador válido da organização.");
      }
      const pkce = await createPkce();
      const transaction = await api<OidcStartResponse>("/auth/oidc/start", {
        method: "POST",
        body: JSON.stringify({
          organization_slug: normalizedOrganization,
          code_challenge: pkce.challenge,
          verifier_hash: pkce.verifierHash,
        }),
      });
      sessionStorage.setItem("oidc_verifier", pkce.verifier);
      sessionStorage.setItem("oidc_state", transaction.state);
      sessionStorage.setItem("oidc_organization", normalizedOrganization);
      window.location.assign(transaction.authorization_url);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Falha ao iniciar SSO.");
      setOidcLoading(false);
    }
  };

  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden px-4">
      <div className="absolute left-1/2 top-1/2 h-[560px] w-[560px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary/[.035] blur-3xl" />
      <section className="relative w-full max-w-md rounded-2xl border border-border bg-card/95 p-8 shadow-2xl">
        <Image
          src="/logo.svg"
          width={220}
          height={48}
          alt="CyberAudit"
          className="mx-auto mb-8"
          priority
        />
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-semibold">Acesso seguro</h1>
          <p className="mt-2 text-sm text-muted">Gestão de auditorias autorizadas</p>
        </div>
        {error && (
          <div
            role="alert"
            className="mb-4 rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-red-300"
          >
            {error}
          </div>
        )}
        <label className="mb-4 block text-sm">
          <span className="mb-1.5 block text-muted">Organização</span>
          <input
            className="field"
            value={organizationSlug}
            onChange={(event) => setOrganizationSlug(event.target.value)}
            autoComplete="organization"
            spellCheck={false}
          />
        </label>
        <button
          type="button"
          className="button flex w-full items-center justify-center gap-2"
          onClick={startOidc}
          disabled={oidcLoading}
        >
          <KeyRound size={17} />
          {oidcLoading ? "A redirecionar…" : "Entrar com SSO"}
        </button>
        <div className="my-5 flex items-center gap-3 text-xs text-muted">
          <span className="h-px flex-1 bg-border" />
          <span>acesso local de desenvolvimento</span>
          <span className="h-px flex-1 bg-border" />
        </div>
        <form method="post" onSubmit={handleSubmit(submit)} className="space-y-4">
          <label className="block text-sm">
            <span className="mb-1.5 block text-muted">Email</span>
            <span className="relative block">
              <Mail size={17} className="absolute left-3 top-3 text-muted" />
              <input {...register("email")} className="field pl-10" autoComplete="email" />
            </span>
            {errors.email && <small className="text-critical">{errors.email.message}</small>}
          </label>
          <label className="block text-sm">
            <span className="mb-1.5 block text-muted">Password</span>
            <span className="relative block">
              <LockKeyhole size={17} className="absolute left-3 top-3 text-muted" />
              <input
                {...register("password")}
                className="field pl-10"
                type="password"
                autoComplete="current-password"
              />
            </span>
            {errors.password && (
              <small className="text-critical">{errors.password.message}</small>
            )}
          </label>
          <button type="submit" className="button-secondary w-full" disabled={isSubmitting}>
            {isSubmitting ? "A autenticar…" : "Entrar na plataforma"}
          </button>
        </form>
        <p className="mt-6 flex items-center justify-center gap-2 text-xs text-muted">
          <ShieldCheck size={14} className="text-primary" />
          Sessão protegida e registada em audit log
        </p>
      </section>
    </main>
  );
}
