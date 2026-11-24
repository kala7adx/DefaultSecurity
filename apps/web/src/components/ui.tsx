import clsx from "clsx";
import type { ButtonHTMLAttributes, ReactNode } from "react";

import type { Severity } from "@/lib/types";

export function Button({
  variant = "primary",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  return (
    <button
      type="button"
      className={clsx(
        "rounded-md px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50",
        variant === "primary" && "bg-brand text-white hover:opacity-90",
        variant === "secondary" && "border border-slate-300 bg-white hover:bg-slate-100",
        variant === "danger" && "bg-red-700 text-white hover:bg-red-800",
        className,
      )}
      {...props}
    />
  );
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-800 text-white",
  high: "bg-red-100 text-red-800",
  medium: "bg-amber-100 text-amber-800",
  low: "bg-sky-100 text-sky-800",
  info: "bg-slate-100 text-slate-700",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        "rounded px-2 py-0.5 text-xs font-semibold uppercase",
        SEVERITY_STYLES[severity],
      )}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "connected" || status === "succeeded" || status === "resolved"
      ? "bg-emerald-100 text-emerald-800"
      : status === "access_lost" || status === "failed"
        ? "bg-red-100 text-red-800"
        : "bg-slate-100 text-slate-700";
  return <span className={clsx("rounded px-2 py-0.5 text-xs font-medium", tone)}>{status}</span>;
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      {title ? <h2 className="mb-3 text-sm font-semibold text-slate-600">{title}</h2> : null}
      {children}
    </section>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : "Something went wrong";
  const id = (error as { correlationId?: string | null }).correlationId;
  return (
    <p role="alert" className="text-sm text-red-700">
      {message}
      {id ? <span className="ml-1 text-slate-500">(ref {id})</span> : null}
    </p>
  );
}

export function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}
