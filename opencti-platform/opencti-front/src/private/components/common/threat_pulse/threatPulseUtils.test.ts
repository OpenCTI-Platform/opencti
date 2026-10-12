import { describe, expect, it } from 'vitest';
import {
  formatPulseGrowth,
  formatPulseRatio,
  isPulseSectorDisclosed,
  PULSE_EVENT_KIND_LABELS,
  PULSE_CONTRIBUTION_STATUS_LABELS,
  PULSE_MODE_LABELS,
  PULSE_PREVALENCE_LABELS,
  PULSE_PREVALENCE_ORDER,
  PULSE_PREVALENCE_SEVERITIES,
  PULSE_REGION_LABELS,
  PULSE_SECTOR_LABELS,
  PULSE_TREND_LABELS,
  PULSE_TREND_SENTENCES,
  PULSE_TREND_SEVERITIES,
  PULSE_UNAVAILABLE_MESSAGES,
  prevalenceGaugeValue,
  pulseObservedHeadline,
  pulsePeriodFromDateRange,
  pulsePlatformsBucketLabel,
  pulseRatioSeverity,
  pulseSectorLabel,
  pulseTrendBarHeights,
  pulseUniquenessMeaning,
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

  it('should map a dashboard date range to the Threat Pulse period of its length', () => {
    expect(pulsePeriodFromDateRange(undefined, undefined)).toBeNull();
    expect(pulsePeriodFromDateRange(null, null)).toBeNull();
    expect(pulsePeriodFromDateRange('2026-10-04T00:00:00.000Z', '2026-10-05T00:00:00.000Z')).toBe('last_7_days');
    expect(pulsePeriodFromDateRange('2026-09-28T00:00:00.000Z', '2026-10-05T00:00:00.000Z')).toBe('last_7_days');
    expect(pulsePeriodFromDateRange('2026-08-31T00:00:00.000Z', '2026-10-01T00:00:00.000Z')).toBe('last_30_days');
    expect(pulsePeriodFromDateRange('2026-07-05T00:00:00.000Z', '2026-10-05T00:00:00.000Z')).toBe('last_90_days');
    expect(pulsePeriodFromDateRange('2025-10-05T00:00:00.000Z', '2026-10-05T00:00:00.000Z')).toBe('last_90_days');
    // An open start is the longest period; an open end runs to now.
    expect(pulsePeriodFromDateRange(null, '2026-10-05T00:00:00.000Z')).toBe('last_90_days');
    expect(pulsePeriodFromDateRange(new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(), null)).toBe('last_7_days');
    expect(pulsePeriodFromDateRange('not a date', '2026-10-05T00:00:00.000Z')).toBeNull();
  });

  it('should place each prevalence bucket in the middle of its gauge segment', () => {
    expect(prevalenceGaugeValue('rare')).toBe(13);
    expect(prevalenceGaugeValue('widespread')).toBe(88);
    expect(prevalenceGaugeValue('unknown')).toBe(0);
    expect(prevalenceGaugeValue(null)).toBe(0);
  });

  it('should scale the weekly trend bars to the busiest week', () => {
    expect(pulseTrendBarHeights([], 32)).toEqual([]);
    expect(pulseTrendBarHeights([0, 5, 10], 32)).toEqual([2, 16, 32]);
    // A week without platforms stays on the baseline, a quiet week stays visible, an all-zero series never divides by zero.
    expect(pulseTrendBarHeights([1, 100], 32)).toEqual([4, 32]);
    expect(pulseTrendBarHeights([0, 0], 32)).toEqual([2, 2]);
  });

  it('should say how many platforms observed a published object, and what its uniqueness means', () => {
    const translate = (message: string, options?: { values?: Record<string, string | number> }) => Object.entries(options?.values ?? {})
      .reduce((text, [name, value]) => text.replace(`{${name}}`, String(value)), message);
    expect(pulseObservedHeadline(translate, '<5')).toBe('Observed on fewer than 5 platforms');
    expect(pulseObservedHeadline(translate, '10-24')).toBe('Observed on 10 to 24 platforms');
    expect(pulseObservedHeadline(translate, '250+')).toBe('Observed on 250 platforms or more');
    expect(pulseObservedHeadline(translate, null)).toBe('Observed across the community');
    expect(Object.keys(PULSE_TREND_SENTENCES)).toEqual(['rising', 'stable', 'falling']);
    expect(pulseUniquenessMeaning(100)).toMatch(/^Below the anonymity threshold/);
    expect(pulseUniquenessMeaning(75)).toMatch(/^Held by few platforms/);
    expect(pulseUniquenessMeaning(50)).toBe('Held by part of the community.');
    expect(pulseUniquenessMeaning(25)).toBe('Held by a large part of the community.');
    expect(pulseUniquenessMeaning(0)).toMatch(/^Held across the community/);
    expect(pulseSectorLabel(translate, 'energy_utilities')).toBe('Energy and utilities');
    expect(pulseSectorLabel(translate, null)).toBe('Undisclosed');
    expect(isPulseSectorDisclosed('finance')).toBe(true);
    expect(isPulseSectorDisclosed('undisclosed')).toBe(false);
    expect(isPulseSectorDisclosed(null)).toBe(false);
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
