"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";

import { FindingDrawer } from "@/components/finding-drawer";
import { ErrorNote, SeverityBadge, StatusBadge, formatDate } from "@/components/ui";
import { api } from "@/lib/api";
import type { Finding, Page } from "@/lib/types";

const STATUSES = ["open", "muted", "resolved", "all"] as const;
const SEVERITIES = ["", "critical", "high", "medium", "low", "info"] as const;

/** The findings table. `openId` comes from the URL (/findings/<id>), so a deep link from
 * Slack, Teams or Jira opens the drawer directly after sign-in. */
export function FindingsView({ openId }: { openId: string | null }) {
  const router = useRouter();
  const params = useSearchParams();
  const status = params.get("status") ?? "open";
  const severity = params.get("severity") ?? "";
  const framework = params.get("framework") ?? "";

  const query = new URLSearchParams({ status, limit: "100" });
  if (severity) query.set("severity", severity);
  if (framework) query.set("framework", framework);
  const findings = useQuery({
    queryKey: ["findings", query.toString()],
    queryFn: () => api<Page<Finding>>(`/findings?${query.toString()}`),
  });

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    router.replace(`/findings?${next.toString()}`);
  }

  const search = params.toString() ? `?${params.toString()}` : "";
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-4">
        <h1 className="text-xl font-semibold">Findings</h1>
        <label className="text-sm">
          Status{" "}
          <select
            value={status}
            onChange={(e) => setFilter("status", e.target.value)}
            className="rounded border border-slate-300 px-2 py-1"
          >
            {STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          Severity{" "}
          <select
            value={severity}
            onChange={(e) => setFilter("severity", e.target.value)}
            className="rounded border border-slate-300 px-2 py-1"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s || "any"}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          Framework{" "}
          <select
            value={framework}
            onChange={(e) => setFilter("framework", e.target.value)}
            className="rounded border border-slate-300 px-2 py-1"
          >
            <option value="">any</option>
            <option value="cyber-essentials-3.3">Cyber Essentials</option>
            <option value="iso27001-2022">ISO 27001:2022</option>
          </select>
        </label>
        <span className="ml-auto text-sm text-slate-500">{findings.data?.total ?? 0} findings</span>
      </div>
      <ErrorNote error={findings.error} />
      <table className="w-full overflow-hidden rounded-lg border border-slate-200 bg-white text-sm">
        <thead className="bg-slate-100 text-left text-slate-600">
          <tr>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">Finding</th>
            <th className="px-3 py-2">Resource</th>
            <th className="px-3 py-2">Risk</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {findings.data?.items.map((finding) => (
            <tr
              key={finding.id}
              data-testid="finding-row"
              className="cursor-pointer border-t border-slate-100 hover:bg-slate-50"
              onClick={() => router.push(`/findings/${finding.id}${search}`)}
            >
              <td className="px-3 py-2">
                <SeverityBadge severity={finding.severity} />
              </td>
              <td className="px-3 py-2">{finding.title}</td>
              <td className="px-3 py-2">
                {finding.asset_name ?? "—"}
                <span className="block text-xs text-slate-500">{finding.resource_type}</span>
              </td>
              <td className="px-3 py-2">{finding.risk_score}</td>
              <td className="px-3 py-2">
                <StatusBadge status={finding.muted ? "muted" : finding.status} />
              </td>
              <td className="px-3 py-2">{formatDate(finding.last_seen_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <FindingDrawer id={openId} onClose={() => router.push(`/findings${search}`)} />
    </div>
  );
}
