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

export const PULSE_PERIOD_LABELS: Record<PulsePeriodValue, string> = {
  last_7_days: '7 days',
  last_30_days: '30 days',
  last_90_days: '90 days',
};

export const PULSE_MODE_LABELS: Record<string, string> = {
  off: 'Off',
  contribute: 'Contribute only',
  contribute_and_read: 'Contribute and read',
};

export const PULSE_SECTOR_LABELS: Record<string, string> = {
  finance: 'Finance',
  government: 'Government',
  defense: 'Defense',
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
  contribution_required: 'Reading Threat Pulse requires contributing: the first contribution is sent within the hour.',
  hub_unreachable: 'XTM Hub is unreachable, the last known network information is displayed.',
  rate_limited: 'The XTM Hub rate limit is reached, retry in a few minutes.',
  enterprise_edition_required: 'Sector benchmarks require the Enterprise Edition.',
  out_of_scope: 'This entity type is not in the Threat Pulse scope.',
  excluded: 'This object never leaves the platform: its markings or its restricted access exclude it from Threat Pulse.',
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

export const formatPulseGrowth = (growth: number) => `x${growth >= 10 ? Math.round(growth) : growth.toFixed(1)}`;
