"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type { ReactNode } from "react";

import { Button } from "@/components/ui";
import { api } from "@/lib/api";
import type { Me } from "@/lib/types";

const NAV = [
  ["/", "Overview"],
  ["/findings", "Findings"],
  ["/assets", "Assets"],
  ["/integrations", "Integrations"],
] as const;

export default function AppLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const queryClient = useQueryClient();
  // A 401 here redirects to /login?next=<this page> (see lib/api.ts): deep links survive.
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/auth/me") });

  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => undefined);
    queryClient.clear();
    router.replace("/login");
  }

  if (!me.data) {
    return <p className="p-8 text-sm text-slate-500">Loading…</p>;
  }
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-3">
          <span className="font-semibold text-brand">Skyline</span>
          <nav className="flex gap-4 text-sm">
            {NAV.map(([href, label]) => {
              const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={clsx(active ? "font-semibold text-slate-900" : "text-slate-500")}
                >
                  {label}
                </Link>
              );
            })}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm text-slate-600">
            <span>
              {me.data.email} · {me.data.tenant.name} · {me.data.role}
            </span>
            <Button variant="secondary" onClick={logout}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-6">{children}</main>
    </div>
  );
}
