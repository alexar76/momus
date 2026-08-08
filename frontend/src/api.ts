/* ===========================================================================
 *  api.ts — typed fetch helpers for the MOMUS backend control surface.
 *
 *  Base URL: VITE_MOMUS_API if set, else in dev talk to the local backend on
 *  :9400, else same-origin ('') — in prod the TLS edge routes the API paths to
 *  the MOMUS backend and serves this SPA for everything else.
 *
 *  Every call here is read-only or triggers a SAFE self/allowlisted probe. None
 *  of them can move funds or authorize a payout — that is the separate Treasury
 *  service, which holds a key MOMUS structurally does not have.
 * ========================================================================= */

const DEV = import.meta.env.DEV;
export const API_BASE: string =
  (import.meta.env.VITE_MOMUS_API as string | undefined) || (DEV ? "http://localhost:9400" : "");

// ── contract types (mirror the backend, do not change the shapes) ────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ProviderInfo {
  provider: string;
  model: string;
  reachable?: boolean;
}

export interface Health {
  status: string;
  service: string;
  version: string;
  targets: string[];
  provider: ProviderInfo;
  crypto_enabled: boolean;
  prod: boolean;
  self_attack?: boolean;
  scanner_pubkey: string;
  holds_treasury_key: boolean;
  /** True when control routes (scan / selfaudit / retest / remediate) need an operator token —
   *  the production default. The panel disables its action buttons instead of provoking a 403. */
  control_gated?: boolean;
  corpus?: {
    backend?: string;
    total_findings?: number;
    recurring?: number;
    scans?: number;
    by_severity?: Record<string, number>;
    by_status?: Record<string, number>;
  };
  settlement?: {
    mode?: string;
    reason?: string;
    simulated?: boolean;
    moves_real_value?: boolean;
    chain?: string;
  };
}

export interface ProviderChoice {
  name: string;
  kind: string;
  default_model: string;
  default_base_url: string;
  needs_key: boolean;
  local: boolean;
  ecosystem?: boolean;
}

export interface Providers {
  selected: { provider: string; model: string };
  choices: ProviderChoice[];
}

export interface Evidence {
  status_code?: number;
  reproducer?: string;
  [k: string]: unknown;
}

export interface Finding {
  finding_id: string;
  target: string;
  target_kind: string;
  probe: string;
  category: string;
  severity: Severity | string;
  outcome: string;
  title: string;
  detail: string;
  evidence: Evidence;
  dedup_key: string;
  created_at: string;
  status: string;
  scanner_pubkey: string;
  signature: { algorithm?: string; value?: string };
}

export interface ScanRecord {
  target: string;
  probe: string;
  outcome: string;
  severity: Severity | string;
  title: string;
}

export interface ScanReport {
  scan_id: string;
  targets: string[];
  counts: { probes: number; findings: number; no_finding: number; inconclusive: number };
  provider: ProviderInfo | Record<string, unknown>;
  findings: Finding[];
  records: ScanRecord[];
}

export interface FindingsResponse {
  count: number;
  findings: Finding[];
  scanner_pubkey: string;
}

export interface IntelCard {
  title: string;
  url: string;
  source: string;
  mapped_categories: string[];
  identifiers: string[];
  published?: string;
  [k: string]: unknown;
}

export interface IntelArm {
  alpha: number;
  beta: number;
  mean: number;
}

export interface Intel {
  intel_enabled: boolean;
  provider: string;
  cards_total: number;
  recent_cards: IntelCard[];
  category_scores: Record<string, number>;
  arms: Record<string, IntelArm>;
  learned_pairs: number;
}

// ── fetch core ───────────────────────────────────────────────────────────────

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { accept: "application/json" },
    signal,
  });
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function postJSON<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body ?? {}),
    signal,
  });
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
  return (await res.json()) as T;
}

// ── public helpers ────────────────────────────────────────────────────────────

export const getHealth = (signal?: AbortSignal) => getJSON<Health>("/health", signal);
export const getProviders = (signal?: AbortSignal) => getJSON<Providers>("/providers", signal);
export const getFindings = (limit = 50, signal?: AbortSignal) =>
  getJSON<FindingsResponse>(`/findings?limit=${limit}`, signal);
export const getIntel = (signal?: AbortSignal) => getJSON<Intel>("/intel", signal);

export const postScan = (target = "self", probes?: string[], signal?: AbortSignal) =>
  postJSON<ScanReport>("/scan", probes ? { target, probes } : { target }, signal);

export const postSelfaudit = (signal?: AbortSignal) => postJSON<ScanReport>("/selfaudit", {}, signal);

// ── Treasury: READ-ONLY audit surface ────────────────────────────────────────
// The TLS edge exposes only /treasury/health and /treasury/ledger. The payout path
// (POST /authorize, /deposit, /explain) is NOT public — it stays on loopback, because the one
// service that can release money should not have an open endpoint. Reading these two lets a
// visitor verify the separation for themselves: the treasury pubkey is not the scanner pubkey.
export interface TreasuryHealth {
  status: string;
  service: string;
  version: string;
  treasury_pubkey: string;
  crypto_enabled: boolean;
  prod: boolean;
  external_verifiers: string[];
}

export interface TreasuryLedgerEntry {
  kind?: string;
  ts?: string;
  state?: string;
  severity?: string;
  amount_usd?: number;
  finding_id?: string;
  ruling?: string;
  settlement?: { mode?: string; simulated?: boolean; reason?: string };
}

export interface TreasuryLedger {
  count: number;
  entries: TreasuryLedgerEntry[];
  treasury_pubkey: string;
}

// Treasury lives behind a different prefix than the MOMUS API (see the nginx vhost). In dev it is
// reachable on :9411 directly.
const TREASURY_BASE: string =
  (import.meta.env.VITE_TREASURY_API as string | undefined) ||
  (DEV ? "http://localhost:9411" : "/treasury");

async function getTreasury<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${TREASURY_BASE}${path}`, { signal, headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export const getTreasuryHealth = (signal?: AbortSignal) =>
  getTreasury<TreasuryHealth>("/health", signal);
export const getTreasuryLedger = (signal?: AbortSignal) =>
  getTreasury<TreasuryLedger>("/ledger", signal);

// Severity → colour, per the MOMUS brand palette (shared with the CSS vars).
export const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ff2d55",
  high: "#ff6b3d",
  medium: "#ffcc33",
  low: "#4db8ff",
  info: "#7a8699",
};

export function severityColor(sev: string): string {
  return SEVERITY_COLOR[String(sev || "").toLowerCase()] || SEVERITY_COLOR.info;
}
