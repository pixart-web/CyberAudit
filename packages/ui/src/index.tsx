import * as React from "react";

export function Card({ className = "", ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`rounded-xl border border-border bg-card shadow-panel ${className}`} {...props} />;
}

export function Badge({
  tone = "neutral",
  className = "",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: "success" | "warning" | "danger" | "info" | "neutral" }) {
  return <span className={`badge badge-${tone} ${className}`} {...props} />;
}

export function Button({ className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={`button ${className}`} {...props} />;
}
