import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";

export const metadata: Metadata = {
  title: { default: "CyberAudit", template: "%s · CyberAudit" },
  description: "Gestão segura de auditorias de cibersegurança autorizadas.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="pt-PT" className="dark"><body><Providers>{children}</Providers></body></html>;
}
