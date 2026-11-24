"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Button, ErrorNote, SeverityBadge, StatusBadge, formatDate } from "@/components/ui";
import { api } from "@/lib/api";
import type { FindingDetail } from "@/lib/types";

function MuteForm({ finding }: { finding: FindingDetail }) {
  const queryClient = useQueryClient();
  const [justification, setJustification] = useState("");
  const mute = useMutation({
    mutationFn: () =>
      api("/exceptions", {
        method: "POST",
        body: {
          scope_type: "finding",
          finding_id: finding.id,
          justification,
          expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
        },
      }),
    onSuccess: () => queryClient.invalidateQueries(),
  });
  if (finding.active_exception) {
    return (
      <p className="text-sm text-slate-600">
        Muted until {formatDate(finding.active_exception.expires_at)}:{" "}
        {finding.active_exception.justification}
      </p>
    );
  }
  return (
    <div className="space-y-2">
      <label className="block text-sm">
        Mute for 30 days. Why is this acceptable?
        <textarea
          value={justification}
          onChange={(event) => setJustification(event.target.value)}
          maxLength={2000}
          className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
        />
      </label>
      <Button
        variant="secondary"
        disabled={justification.trim().length < 10 || mute.isPending}
        onClick={() => mute.mutate()}
      >
        Mute finding
      </Button>
      <ErrorNote error={mute.error} />
    </div>
  );
}

export function FindingDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api<FindingDetail>(`/findings/${encodeURIComponent(id ?? "")}`),
    enabled: id !== null,
  });
  const finding = detail.data;
  return (
    <Dialog.Root open={id !== null} onOpenChange={(open) => (open ? undefined : onClose())}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-slate-900/30" />
        <Dialog.Content className="fixed top-0 right-0 h-full w-full max-w-xl overflow-y-auto bg-white p-6 shadow-xl">
          <div className="mb-4 flex items-start gap-3">
            <Dialog.Title className="text-lg font-semibold">
              {finding?.title ?? "Finding"}
            </Dialog.Title>
            <Dialog.Close asChild>
              <Button variant="secondary" className="ml-auto">
                Close
              </Button>
            </Dialog.Close>
          </div>
          <Dialog.Description className="sr-only">Finding details</Dialog.Description>
          <ErrorNote error={detail.error} />
          {finding ? (
            <div className="space-y-5 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.muted ? "muted" : finding.status} />
                <span>Risk {finding.risk_score}</span>
                <span className="text-slate-500">
                  {finding.resource_type} · {finding.asset_name ?? finding.asset_id}
                </span>
              </div>
              {finding.check.description ? <p>{finding.check.description}</p> : null}
              <section>
                <h3 className="font-semibold">Evidence</h3>
                {/* Rendered as text: evidence mirrors attacker-controllable cloud data. */}
                <pre className="mt-1 overflow-x-auto rounded bg-slate-100 p-3 text-xs">
                  {JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </section>
              {finding.check.remediation ? (
                <section>
                  <h3 className="font-semibold">Remediation</h3>
                  <p className="mt-1">{finding.check.remediation.summary}</p>
                  <ol className="mt-1 list-decimal pl-5">
                    {finding.check.remediation.steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                </section>
              ) : null}
              <section>
                <h3 className="font-semibold">Compliance mappings</h3>
                <ul className="mt-1 space-y-1" data-testid="mappings">
                  {finding.controls.map((control) => (
                    <li key={`${control.framework_id}:${control.ref}`}>
                      <span className="font-medium">{control.framework_name}</span> {control.ref} —{" "}
                      {control.title}
                      {control.reviewed ? null : (
                        <span className="ml-1 text-xs text-slate-500">(mapping not reviewed)</span>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
              <section>
                <h3 className="font-semibold">History</h3>
                <ul className="mt-1 space-y-1 text-slate-600">
                  {finding.events.map((event) => (
                    <li key={`${event.scan_run_id}:${event.event}`}>
                      {formatDate(event.at)} — {event.event.replace("_", " ")}
                    </li>
                  ))}
                </ul>
              </section>
              <MuteForm finding={finding} />
            </div>
          ) : null}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
