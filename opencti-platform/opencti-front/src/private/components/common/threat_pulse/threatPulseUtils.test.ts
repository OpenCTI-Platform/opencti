import { describe, expect, it } from 'vitest';
import {
  buildSparklinePoints,
  formatPulseGrowth,
  formatPulseRatio,
  PULSE_EVENT_KIND_LABELS,
  PULSE_CONTRIBUTION_STATUS_LABELS,
  PULSE_MODE_LABELS,
  PULSE_PREVALENCE_LABELS,
  PULSE_PREVALENCE_ORDER,
  PULSE_PREVALENCE_SEVERITIES,
  PULSE_REGION_LABELS,
  PULSE_SECTOR_LABELS,
  PULSE_TREND_LABELS,
  PULSE_TREND_SEVERITIES,
  PULSE_UNAVAILABLE_MESSAGES,
  prevalenceGaugeValue,
  pulsePlatformsBucketLabel,
  pulseRatioSeverity,
} from './threatPulseUtils';
import { buildPulseBriefingContext } from './ThreatPulseBriefing';

describe('Threat Pulse utils', () => {
  it('should put the platforms range XTM Hub publishes in words, never the raw range', () => {
    const translate = (message: string, options?: { values?: Record<string, string | number> }) => Object.entries(options?.values ?? {})
      .reduce((text, [name, value]) => text.replace(`{${name}}`, String(value)), message);
    expect(pulsePlatformsBucketLabel(translate, '<5')).toBe('Fewer than 5 platforms');
    expect(pulsePlatformsBucketLabel(translate, '10-24')).toBe('10 to 24 platforms');
    expect(pulsePlatformsBucketLabel(translate, '250+')).toBe('250 platforms or more');
    expect(pulsePlatformsBucketLabel(translate, null)).toBeNull();
    expect(pulsePlatformsBucketLabel(translate, 'unexpected')).toBeNull();
  });

  it('should label every value of the API enums', () => {
    expect(Object.keys(PULSE_PREVALENCE_LABELS)).toEqual([...PULSE_PREVALENCE_ORDER]);
    expect(Object.keys(PULSE_PREVALENCE_SEVERITIES)).toEqual([...PULSE_PREVALENCE_ORDER]);
    expect(Object.keys(PULSE_TREND_LABELS)).toEqual(['rising', 'stable', 'falling']);
    expect(Object.keys(PULSE_TREND_SEVERITIES)).toEqual(['rising', 'stable', 'falling']);
    expect(Object.keys(PULSE_MODE_LABELS)).toEqual(['off', 'preview', 'contribute_and_read']);
    expect(Object.keys(PULSE_CONTRIBUTION_STATUS_LABELS)).toEqual(['active', 'grace', 'lapsed', 'none']);
    expect(Object.keys(PULSE_EVENT_KIND_LABELS)).toEqual(['created', 'sighted', 'detected', 'hunted', 'referenced']);
    expect(Object.keys(PULSE_SECTOR_LABELS)).toContain('undisclosed');
    expect(Object.keys(PULSE_REGION_LABELS)).toContain('undisclosed');
    expect(Object.keys(PULSE_UNAVAILABLE_MESSAGES).sort()).toEqual([
      'contribution_required',
      'enterprise_edition_required',
      'excluded',
      'hub_unreachable',
      'not_enabled',
      'not_registered',
      'out_of_scope',
      'rate_limited',
    ]);
  });

  it('should place each prevalence bucket in the middle of its gauge segment', () => {
    expect(prevalenceGaugeValue('rare')).toBe(13);
    expect(prevalenceGaugeValue('widespread')).toBe(88);
    expect(prevalenceGaugeValue('unknown')).toBe(0);
    expect(prevalenceGaugeValue(null)).toBe(0);
  });

  it('should scale a sparkline to its box with a vertical margin', () => {
    expect(buildSparklinePoints([], 100, 20)).toBe('');
    expect(buildSparklinePoints([5], 100, 20)).toBe('50,2');
    expect(buildSparklinePoints([0, 5, 10], 100, 20)).toBe('0,18 50,10 100,2');
    // An all-zero series stays on the baseline instead of dividing by zero.
    expect(buildSparklinePoints([0, 0], 100, 20)).toBe('0,18 100,18');
  });

  it('should format multipliers and rate them against the sector median', () => {
    expect(formatPulseRatio(null)).toBe('-');
    expect(formatPulseRatio(2.44)).toBe('x2.4');
    expect(formatPulseRatio(12.6)).toBe('x13');
    expect(formatPulseGrowth(3)).toBe('x3.0');
    expect(pulseRatioSeverity(undefined)).toBe('neutral');
    expect(pulseRatioSeverity(3)).toBe('high');
    expect(pulseRatioSeverity(0.4)).toBe('low');
    expect(pulseRatioSeverity(1)).toBe('info');
  });

  it('should send the Sector Pulse Briefing agent its scope and nothing else', () => {
    const context = JSON.parse(buildPulseBriefingContext({ period: 'last_30_days', sectorBucket: 'finance', regionBucket: undefined }, 'https://opencti.example'));
    expect(context).toEqual({
      kind: 'pulse_briefing',
      period: 'last_30_days',
      sector_bucket: 'finance',
      region_bucket: null,
      platform_url: 'https://opencti.example',
    });
  });
});
