// Ingestion health — presentation helpers.
//
// Pure: no React, no theme, no i18n. Colour is returned as a palette *token
// path* rather than a value so the component resolves it through the theme —
// `check-fds-conformity.mjs` fails on a hardcoded colour in a migrated zone.

export type IngestionHealthStatus =
  | 'healthy'
  | 'idle'
  | 'degraded'
  | 'critical'
  | 'stopped'
  | 'unknown';

export interface IngestionCheck {
  kind: string;
  code: string;
  severity: string;
  params?: Record<string, string | number> | null;
  message: string;
  detail?: string | null;
}

export type IngestionConfigurationStatus = 'ok' | 'advisory' | 'blocking';

export interface IngestionHealth {
  status: IngestionHealthStatus;
  // Reported independently of `status` so a source that is both degraded and
  // misconfigured stays visible on either axis.
  configuration_status?: IngestionConfigurationStatus | null;
  summary: string;
  checks: ReadonlyArray<IngestionCheck>;
  since?: string | null;
  last_productive_at?: string | null;
  next_expected_at?: string | null;
}

export type HealthPaletteToken = 'error' | 'warn' | 'success' | 'neutral';

// Only statuses that need attention get a colour. `stopped`, `idle` and
// `unknown` stay neutral on purpose: colouring a deliberately stopped source
// red is how a status column stops being read at all.
export const HEALTH_PALETTE_TOKEN: Record<IngestionHealthStatus, HealthPaletteToken> = {
  healthy: 'success',
  idle: 'neutral',
  degraded: 'warn',
  critical: 'error',
  stopped: 'neutral',
  unknown: 'neutral',
};

// English source strings, used as i18n message ids per the repo convention.
export const HEALTH_STATUS_LABEL: Record<IngestionHealthStatus, string> = {
  healthy: 'Healthy',
  idle: 'Idle',
  degraded: 'Degraded',
  critical: 'Critical',
  stopped: 'Stopped',
  unknown: 'Unknown',
};

// The configuration marker is driven by the checks, never by `status` — that is
// the whole point of keeping the two axes apart.
export const hasConfigurationFinding = (health: IngestionHealth | null | undefined): boolean => {
  return !!health?.checks?.some((check) => check.kind === 'configuration');
};

export const CONFIGURATION_STATUS_LABEL: Record<IngestionConfigurationStatus, string> = {
  ok: 'Configuration OK',
  advisory: 'Misconfigured',
  blocking: 'Cannot run as configured',
};

export const CONFIGURATION_PALETTE_TOKEN: Record<IngestionConfigurationStatus, HealthPaletteToken> = {
  ok: 'neutral',
  advisory: 'warn',
  blocking: 'error',
};

// Only the configuration findings, for the surfaces that show that axis on its
// own — the detail-page alert slot and the row marker's tooltip.
export const buildConfigurationLines = (health: IngestionHealth | null | undefined): string[] => {
  if (!health) {
    return [];
  }
  return health.checks.filter((check) => check.kind === 'configuration').map((check) => check.message);
};

// A status worth surfacing in the counters above the table.
export const ATTENTION_STATUSES: IngestionHealthStatus[] = ['critical', 'degraded'];

export const isAttentionStatus = (status?: IngestionHealthStatus | null): boolean => {
  return !!status && ATTENTION_STATUSES.includes(status);
};

export interface HealthCounts {
  critical: number;
  degraded: number;
  stopped: number;
  unknown: number;
  misconfigured: number;
  total: number;
}

export const countHealthStatuses = (
  sources: ReadonlyArray<{ ingestion_health?: { status?: string | null; configuration_status?: string | null } | null }>,
): HealthCounts => {
  const counts: HealthCounts = { critical: 0, degraded: 0, stopped: 0, unknown: 0, misconfigured: 0, total: 0 };
  sources.forEach((source) => {
    const status = source.ingestion_health?.status;
    if (!status) {
      return;
    }
    counts.total += 1;
    if (status === 'critical' || status === 'degraded' || status === 'stopped' || status === 'unknown') {
      counts[status] += 1;
    }
    // Counted independently: a source can be both, and both figures matter.
    if (source.ingestion_health?.configuration_status
      && source.ingestion_health.configuration_status !== 'ok') {
      counts.misconfigured += 1;
    }
  });
  return counts;
};

// The tooltip shows the whole story: the headline, then every check, then how
// long the source has been in this state. Returned as lines so the component
// decides the markup.
export const buildHealthTooltipLines = (health: IngestionHealth | null | undefined): string[] => {
  if (!health) {
    return [];
  }
  const lines = [health.summary];
  health.checks.forEach((check) => {
    // The summary already carries the first check — do not repeat it.
    if (check.message !== health.checks[0]?.message || lines.length > 1) {
      lines.push(check.message);
    }
  });
  return Array.from(new Set(lines)).filter((line) => line && line.length > 0);
};
