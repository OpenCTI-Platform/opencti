import type { ChipSeverity } from '@filigran/design-system';

export const PULSE_BRIEFING_INTENT = 'cti.pulse_briefing';

export const PULSE_PREVALENCE_ORDER = ['rare', 'uncommon', 'common', 'widespread'] as const;
export type PulsePrevalenceValue = typeof PULSE_PREVALENCE_ORDER[number];

export const PULSE_PERIODS = ['last_7_days', 'last_30_days', 'last_90_days'] as const;
export type PulsePeriodValue = typeof PULSE_PERIODS[number];

export const PULSE_SCOPE_ENTITY_TYPES = ['Indicator', 'Attack-Pattern', 'Vulnerability', 'Intrusion-Set', 'Malware', 'Tool'];

// Keys are translated with t_i18n at render time.
export const PULSE_PREVALENCE_LABELS: Record<string, string> = {
  rare: 'Rare',
  uncommon: 'Uncommon',
  common: 'Common',
  widespread: 'Widespread',
};

// The more platforms observe an object, the stronger its chip.
export const PULSE_PREVALENCE_SEVERITIES: Record<string, ChipSeverity> = {
  rare: 'neutral',
  uncommon: 'info',
  common: 'medium',
  widespread: 'high',
};

export const PULSE_TREND_LABELS: Record<string, string> = {
  rising: 'Rising',
  stable: 'Stable',
  falling: 'Falling',
};

export const PULSE_TREND_SEVERITIES: Record<string, ChipSeverity> = {
  rising: 'high',
  stable: 'neutral',
  falling: 'low',
};

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

// The coarse platforms range XTM Hub publishes ("10-24", "250+", "<5"), in words: never the raw bucket on screen.
export const pulsePlatformsBucketLabel = (t_i18n: Translate, bucket: string | null | undefined): string | null => {
  if (!bucket) {
    return null;
  }
  const below = /^<(\d+)$/.exec(bucket);
  if (below) {
    return t_i18n('Fewer than {count} platforms', { values: { count: Number(below[1]) } });
  }
  const range = /^(\d+)-(\d+)$/.exec(bucket);
  if (range) {
    return t_i18n('{min} to {max} platforms', { values: { min: Number(range[1]), max: Number(range[2]) } });
  }
  const atLeast = /^(\d+)\+$/.exec(bucket);
  if (atLeast) {
    return t_i18n('{count} platforms or more', { values: { count: Number(atLeast[1]) } });
  }
  return null;
};

export const PULSE_PERIOD_LABELS: Record<PulsePeriodValue, string> = {
  last_7_days: '7 days',
  last_30_days: '30 days',
  last_90_days: '90 days',
};

const DAY_MS = 24 * 60 * 60 * 1000;

// XTM Hub publishes the last 7, 30 or 90 days only: a dashboard date range of up to a week maps to 7 days, up to a
// month (31 days) to 30 days, anything longer or open-ended to 90 days. Null without any date, the widget then keeps
// its own period selector.
export const pulsePeriodFromDateRange = (startDate?: string | null, endDate?: string | null): PulsePeriodValue | null => {
  if (!startDate) {
    return endDate ? 'last_90_days' : null;
  }
  const start = new Date(startDate).getTime();
  const end = endDate ? new Date(endDate).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return null;
  }
  const days = Math.round((end - start) / DAY_MS);
  if (days <= 7) return 'last_7_days';
  if (days <= 31) return 'last_30_days';
  return 'last_90_days';
};

export const PULSE_MODE_LABELS: Record<string, string> = {
  off: 'Off',
  preview: 'Preview, nothing sent',
  contribute_and_read: 'Contribute, full experience',
};

export const PULSE_CONTRIBUTION_STATUS_LABELS: Record<string, string> = {
  active: 'Active contributor',
  grace: 'Grace period',
  lapsed: 'Lapsed',
  none: 'No contribution yet',
};

export const PULSE_SECTOR_LABELS: Record<string, string> = {
  finance: 'Finance',
  government: 'Government',
  defense: 'Defense industry',
  healthcare: 'Healthcare',
  energy_utilities: 'Energy and utilities',
  telecommunications: 'Telecommunications',
  technology: 'Technology',
  manufacturing: 'Manufacturing',
  transportation: 'Transportation',
  retail_consumer: 'Retail and consumer',
  education_research: 'Education and research',
  non_profit: 'Non-profit',
  other: 'Other sector',
  undisclosed: 'Undisclosed',
};

export const PULSE_REGION_LABELS: Record<string, string> = {
  africa: 'Africa',
  asia_pacific: 'Asia-Pacific',
  europe: 'Europe',
  latin_america: 'Latin America',
  middle_east: 'Middle East',
  north_america: 'North America',
  global: 'Global',
  undisclosed: 'Undisclosed',
};

export const PULSE_EVENT_KIND_LABELS: Record<string, string> = {
  created: 'Creations',
  sighted: 'Sightings',
  detected: 'Detections',
  hunted: 'Hunts',
  referenced: 'References',
};

export const PULSE_UNAVAILABLE_MESSAGES: Record<string, string> = {
  not_enabled: 'Threat Pulse is not enabled on this platform.',
  not_registered: 'Register the platform on XTM Hub to use Threat Pulse.',
  contribution_required: 'This platform shows the Threat Pulse preview: contributing unlocks the full experience.',
  hub_unreachable: 'XTM Hub is unreachable, the last known network information is displayed.',
  rate_limited: 'The XTM Hub rate limit is reached, retry in a few minutes.',
  enterprise_edition_required: 'Sector benchmarks require the Enterprise Edition.',
  out_of_scope: 'This entity type is not in the Threat Pulse scope.',
  excluded: 'This object never leaves the platform: its markings or its restricted access exclude it from Threat Pulse.',
};

// The last error of the hourly Threat Pulse cycle: the code a step of the cycle leaves when it fails, then the codes of
// the XTM Hub client for the contribution.
export const PULSE_PUSH_ERROR_MESSAGES: Record<string, string> = {
  cleanup_failed: 'The removal of community data that is no longer current failed: the next hourly run tries again.',
  contribution_failed: 'The last contribution failed on this platform: the next hourly run tries again with the pending records.',
  network_refresh_failed: 'The refresh of the community data of your objects failed: the next hourly run tries again.',
  trending_notifications_failed: 'The notifications of objects trending in your sector failed: the next hourly run tries again.',
  preview_refresh_failed: 'The preview refresh failed: the next hourly run tries again.',
  hub_unreachable: 'XTM Hub could not be reached: the pending records are sent with the next hourly run.',
  rate_limited: 'XTM Hub limited the requests of this platform: the pending records are sent with the next hourly run.',
  contribution_required: 'XTM Hub requires a recent contribution: the next accepted one restores the full experience.',
  unauthenticated: 'XTM Hub did not recognize this platform: check its registration in Settings > Filigran Experience.',
  forbidden: 'XTM Hub did not recognize this platform: check its registration in Settings > Filigran Experience.',
  bad_request: 'XTM Hub refused a batch of records as invalid: the batch was dropped.',
  unexpected: 'XTM Hub could not record the last contribution: the pending records are sent with the next hourly run.',
};

// Position of a prevalence bucket on a 0-100 gauge, the middle of its segment.
export const prevalenceGaugeValue = (prevalence: string | null | undefined) => {
  const index = PULSE_PREVALENCE_ORDER.indexOf((prevalence ?? '') as PulsePrevalenceValue);
  return index < 0 ? 0 : Math.round(((index + 0.5) / PULSE_PREVALENCE_ORDER.length) * 100);
};

// SVG polyline points of a sparkline, the series scaled to the box with a small vertical margin.
export const buildSparklinePoints = (series: readonly number[], width: number, height: number, margin = 2) => {
  if (series.length === 0) {
    return '';
  }
  const max = Math.max(...series, 1);
  const step = series.length > 1 ? width / (series.length - 1) : 0;
  return series.map((value, index) => {
    const x = series.length > 1 ? index * step : width / 2;
    const y = height - margin - (value / max) * (height - 2 * margin);
    return `${Number(x.toFixed(2))},${Number(y.toFixed(2))}`;
  }).join(' ');
};

// A multiplier, "x2.4" or "x12" above ten.
export const formatPulseRatio = (ratio: number | null | undefined) => {
  if (ratio === null || ratio === undefined) {
    return '-';
  }
  return `x${ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)}`;
};

export const formatPulseGrowth = (growth: number) => formatPulseRatio(growth);

// At least twice the sector median is high, at most half of it is low.
export const pulseRatioSeverity = (ratio: number | null | undefined): ChipSeverity => {
  if (ratio === null || ratio === undefined) return 'neutral';
  if (ratio >= 2) return 'high';
  if (ratio <= 0.5) return 'low';
  return 'info';
};
