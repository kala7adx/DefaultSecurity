"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { Card, ErrorNote, SeverityBadge } from "@/components/ui";
import { api } from "@/lib/api";
import type { Severity, Summary } from "@/lib/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function OverviewPage() {
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api<Summary>("/findings/summary"),
  });
  if (summary.error) return <ErrorNote error={summary.error} />;
  const data = summary.data;
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Overview</h1>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card title="Open findings">
          <p className="text-3xl font-semibold" data-testid="open-total">
            {data?.open_total ?? "…"}
          </p>
          <ul className="mt-3 space-y-1 text-sm">
            {SEVERITIES.map((severity) => (
              <li key={severity} className="flex items-center justify-between">
                <SeverityBadge severity={severity} />
                <span>{data?.open_by_severity[severity] ?? 0}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Muted and resolved">
          <p className="text-sm">Muted: {data?.muted ?? 0}</p>
          <p className="text-sm">Resolved: {data?.resolved ?? 0}</p>
        </Card>
        <Card title="Open findings by framework">
          <ul className="space-y-1 text-sm">
            {Object.entries(data?.by_framework ?? {}).map(([framework, count]) => (
              <li key={framework} className="flex justify-between">
                <Link href={`/findings?framework=${encodeURIComponent(framework)}`}>
                  {framework}
                </Link>
                <span>{count}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
      {data && data.open_total === 0 && data.resolved === 0 ? (
        <p className="text-sm text-slate-600">
          No findings yet. <Link href="/integrations">Connect an integration</Link> to run a scan.
        </p>
      ) : null}
    </div>
  );
}
