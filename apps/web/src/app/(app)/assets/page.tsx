"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorNote, formatDate } from "@/components/ui";
import { api } from "@/lib/api";
import type { Asset, Page } from "@/lib/types";

export default function AssetsPage() {
  const [q, setQ] = useState("");
  const query = new URLSearchParams({ limit: "200" });
  if (q.trim()) query.set("q", q.trim());
  const assets = useQuery({
    queryKey: ["assets", query.toString()],
    queryFn: () => api<Page<Asset>>(`/assets?${query.toString()}`),
  });
  return (
    <div className="space-y-4">
      <div className="flex items-end gap-4">
        <h1 className="text-xl font-semibold">Assets</h1>
        <label className="text-sm">
          Name contains{" "}
          <input
            value={q}
            maxLength={100}
            onChange={(e) => setQ(e.target.value)}
            className="rounded border border-slate-300 px-2 py-1"
          />
        </label>
        <span className="ml-auto text-sm text-slate-500">{assets.data?.total ?? 0} assets</span>
      </div>
      <ErrorNote error={assets.error} />
      <table className="w-full rounded-lg border border-slate-200 bg-white text-sm">
        <thead className="bg-slate-100 text-left text-slate-600">
          <tr>
            <th className="px-3 py-2">Name</th>
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2">Account / region</th>
            <th className="px-3 py-2">Tags</th>
            <th className="px-3 py-2">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {assets.data?.items.map((asset) => (
            <tr key={asset.id} className="border-t border-slate-100">
              <td className="px-3 py-2">{asset.name ?? asset.native_id}</td>
              <td className="px-3 py-2">{asset.resource_type}</td>
              <td className="px-3 py-2">
                {asset.account_id ?? "—"} / {asset.region ?? "global"}
              </td>
              <td className="px-3 py-2 text-xs">
                {Object.entries(asset.tags)
                  .map(([key, value]) => `${key}=${value}`)
                  .join(", ")}
              </td>
              <td className="px-3 py-2">{formatDate(asset.last_seen_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
