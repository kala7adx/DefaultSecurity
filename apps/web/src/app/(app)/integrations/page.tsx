"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Button, Card, ErrorNote, StatusBadge, formatDate } from "@/components/ui";
import { api } from "@/lib/api";
import type { Integration, Page, ScanRun } from "@/lib/types";

/** The fake provider's simulated fixes (packages/connectors/.../fake/models.py). */
const ALL_FIXES = [
  "remove_public_ip",
  "close_admin_ports",
  "encrypt_bucket",
  "enable_mfa",
  "upgrade_os",
];

function useRefreshAll() {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries();
}

function IntegrationRow({ integration, scans }: { integration: Integration; scans: ScanRun[] }) {
  const refresh = useRefreshAll();
  const fixed = (integration.config.simulate_fixes ?? []).length > 0;
  const scan = useMutation({
    mutationFn: () => api("/scans", { method: "POST", body: { integration_id: integration.id } }),
    onSettled: refresh,
  });
  const toggleFixes = useMutation({
    mutationFn: () =>
      api(`/integrations/${integration.id}`, {
        method: "PATCH",
        body: { config: { ...integration.config, simulate_fixes: fixed ? [] : ALL_FIXES } },
      }),
    onSettled: refresh,
  });
  const latest = scans.find((s) => s.integration_id === integration.id);
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="font-semibold">{integration.name}</h2>
        <span className="text-xs text-slate-500">{integration.provider}</span>
        <StatusBadge status={integration.status} />
        {integration.status_detail ? (
          <span className="text-xs text-slate-500">{integration.status_detail}</span>
        ) : null}
        <div className="ml-auto flex gap-2">
          <Button
            variant="secondary"
            disabled={integration.status !== "connected" || scan.isPending}
            onClick={() => scan.mutate()}
          >
            Scan now
          </Button>
          {integration.provider === "fake" ? (
            <Button
              variant="secondary"
              disabled={toggleFixes.isPending}
              onClick={() => toggleFixes.mutate()}
            >
              {fixed ? "Undo simulated fixes" : "Simulate fixes"}
            </Button>
          ) : null}
        </div>
      </div>
      <p className="mt-2 text-sm text-slate-600">
        Last scan: {latest ? `${latest.status} (${formatDate(latest.finished_at)})` : "none"}
        {latest?.scope_errors.length
          ? ` · failed scopes: ${latest.scope_errors.map((e) => e.scope).join(", ")}`
          : ""}
      </p>
      <ErrorNote error={scan.error ?? toggleFixes.error} />
    </Card>
  );
}

export default function IntegrationsPage() {
  const refresh = useRefreshAll();
  const integrations = useQuery({
    queryKey: ["integrations"],
    queryFn: () => api<Page<Integration>>("/integrations"),
    // Poll while anything is being verified or scanned.
    refetchInterval: (query) =>
      query.state.data?.items.some((i) => i.status === "verifying") ? 2000 : 10_000,
  });
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<Page<ScanRun>>("/scans?limit=50"),
    refetchInterval: (query) =>
      query.state.data?.items.some((s) => s.status === "queued" || s.status === "running")
        ? 2000
        : 10_000,
  });
  const add = useMutation({
    mutationFn: () =>
      api("/integrations", {
        method: "POST",
        body: { provider: "fake", name: "Demo company", config: {} },
      }),
    onSettled: refresh,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center">
        <h1 className="text-xl font-semibold">Integrations</h1>
        <Button className="ml-auto" disabled={add.isPending} onClick={() => add.mutate()}>
          Add demo company
        </Button>
      </div>
      <ErrorNote error={integrations.error ?? add.error} />
      {integrations.data?.items.length === 0 ? (
        <p className="text-sm text-slate-600">
          No integrations yet. The demo company is a simulated cloud with a few misconfigurations;
          it makes no network calls.
        </p>
      ) : null}
      {integrations.data?.items.map((integration) => (
        <IntegrationRow
          key={integration.id}
          integration={integration}
          scans={scans.data?.items ?? []}
        />
      ))}
    </div>
  );
}
