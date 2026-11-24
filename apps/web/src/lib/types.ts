/** Response shapes of the Skyline API (apps/api/src/skyline_api/schemas.py). */

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Me {
  user_id: string;
  email: string;
  role: string;
  permissions: string[];
  must_change_password: boolean;
  tenant: { id: string; slug: string; name: string };
}

export interface Integration {
  id: string;
  provider: string;
  name: string;
  config: { simulate_fixes?: string[]; fail_scopes?: string[] } & Record<string, unknown>;
  status: "pending_registration" | "verifying" | "connected" | "access_lost" | "disabled";
  status_detail: string;
  scan_interval_hours: number;
  next_scan_at: string | null;
  last_scan_at: string | null;
  created_at: string;
}

export interface ScanRun {
  id: string;
  integration_id: string;
  trigger: string;
  status: "queued" | "running" | "succeeded" | "partial" | "failed";
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stats: Record<string, number>;
  scope_errors: { scope: string; reason: string }[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  check_id: string;
  title: string;
  severity: Severity;
  status: "open" | "resolved";
  muted: boolean;
  risk_score: string;
  asset_id: string;
  asset_name: string | null;
  resource_type: string;
  integration_id: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  reopened_count: number;
}

export interface ControlRef {
  framework_id: string;
  framework_name: string;
  ref: string;
  title: string;
  reviewed: boolean;
}

export interface FindingDetail extends Finding {
  evidence: Record<string, unknown>;
  check: {
    description?: string;
    rationale?: string;
    remediation?: { summary: string; steps: string[] };
    references?: { title: string; url: string }[];
  };
  controls: ControlRef[];
  events: { event: string; scan_run_id: string; at: string }[];
  active_exception: { id: string; justification: string; expires_at: string } | null;
}

export interface Summary {
  open_by_severity: Partial<Record<Severity, number>>;
  open_total: number;
  muted: number;
  resolved: number;
  by_framework: Record<string, number>;
}

export interface Asset {
  id: string;
  integration_id: string;
  provider: string;
  resource_type: string;
  native_id: string;
  name: string | null;
  account_id: string | null;
  region: string | null;
  tags: Record<string, string>;
  first_seen_at: string;
  last_seen_at: string;
  deleted_at: string | null;
}
