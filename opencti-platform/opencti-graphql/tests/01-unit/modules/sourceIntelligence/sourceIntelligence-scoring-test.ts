import { describe, expect, it } from 'vitest';
import {
  computeCostPerActionable,
  computeFreshnessHours,
  computeImpactScore,
  computeLeadTimeHours,
  computeValueScore,
  isExpired,
  isNegativeRevocation,
  median,
  normalizeCostToDays,
  ratio,
  ReservoirSample,
  scorecardDocumentId,
  toSnapshotDate,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-scoring';
import { DEFAULT_SOURCE_INTELLIGENCE_SETTINGS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';

const HOUR = 3600 * 1000;

describe('Source intelligence scoring', () => {
  it('should compute bounded ratios', () => {
    expect(ratio(1, 4)).toEqual(0.25);
    expect(ratio(5, 4)).toEqual(1);
    expect(ratio(1, 0)).toBeNull();
    expect(ratio(1, 3)).toEqual(0.3333);
  });

  it('should compute medians', () => {
    expect(median([])).toBeNull();
    expect(median([3, 1, 2])).toEqual(2);
    expect(median([4, 1, 3, 2])).toEqual(2.5);
  });

  it('should sample deterministically with a bounded reservoir', () => {
    const first = new ReservoirSample(100, 7);
    const second = new ReservoirSample(100, 7);
    for (let i = 0; i < 10000; i += 1) {
      first.add(i);
      second.add(i);
    }
    expect(first.size).toEqual(10000);
    expect(first.median()).toEqual(second.median());
    // A uniform sample of 0..9999 has its median close to the middle
    expect(first.median()).toBeGreaterThan(3000);
    expect(first.median()).toBeLessThan(7000);
  });

  it('should compute the lead time against the earliest other source', () => {
    const t = Date.UTC(2026, 9, 1);
    expect(computeLeadTimeHours(t, [t + 5 * HOUR, t + 10 * HOUR])).toEqual(5);
    expect(computeLeadTimeHours(t, [t - 2 * HOUR])).toEqual(-2);
    expect(computeLeadTimeHours(t, [])).toBeNull();
    expect(computeLeadTimeHours(Number.NaN, [t])).toBeNull();
  });

  it('should normalize costs to the scorecard period', () => {
    expect(normalizeCostToDays({ amount: 3652.5, currency: 'EUR', period: 'year' }, 30)).toEqual(300);
    expect(normalizeCostToDays({ amount: 100, currency: 'EUR', period: 'month' }, 365.25 / 12)).toEqual(100);
    expect(normalizeCostToDays(null, 30)).toBeNull();
    expect(normalizeCostToDays({ amount: -1, currency: 'EUR', period: 'year' }, 30)).toBeNull();
    expect(computeCostPerActionable({ amount: 3652.5, currency: 'EUR', period: 'year' }, 30, 150)).toEqual(2);
    expect(computeCostPerActionable({ amount: 3652.5, currency: 'EUR', period: 'year' }, 30, 0)).toBeNull();
  });

  it('should weigh confirmed detections more than plain sightings in the impact score', () => {
    const base = { sightings_count: 0, security_platform_sightings_count: 0, hunt_true_positives_count: 0, incidents_count: 0 };
    expect(computeImpactScore(base)).toEqual(0);
    const plain = computeImpactScore({ ...base, sightings_count: 9 });
    const platform = computeImpactScore({ ...base, sightings_count: 9, security_platform_sightings_count: 9 });
    const hunts = computeImpactScore({ ...base, hunt_true_positives_count: 9 });
    expect(plain).toEqual(25);
    expect(platform).toBeGreaterThan(plain);
    expect(hunts).toBeGreaterThan(platform);
    expect(computeImpactScore({ ...base, sightings_count: 10 ** 9 })).toEqual(100);
  });

  it('should compute the freshness', () => {
    const now = Date.UTC(2026, 9, 3, 12);
    expect(computeFreshnessHours(now - 6 * HOUR, now)).toEqual(6);
    expect(computeFreshnessHours(now + HOUR, now)).toEqual(0);
    expect(computeFreshnessHours(null, now)).toBeNull();
  });

  it('should exclude unmeasurable components from the value score', () => {
    const weights = DEFAULT_SOURCE_INTELLIGENCE_SETTINGS.value_weights;
    const metrics = {
      unique_contribution: 1,
      first_reporter_share: null,
      shared_count: 0,
      accuracy: 1,
      relevance: null,
      impact_score: 100,
      noise: 0,
      volume_total: 10,
    };
    // Only uniqueness, accuracy, impact and noise are measurable, all perfect
    expect(computeValueScore(metrics, weights)).toEqual(100);
    expect(computeValueScore({ ...metrics, volume_total: 0 }, weights)).toEqual(0);
    const halfAccuracy = computeValueScore({ ...metrics, accuracy: 0.5 }, weights);
    expect(halfAccuracy).toBeLessThan(100);
    expect(halfAccuracy).toBeGreaterThan(80);
    expect(computeValueScore(metrics, { uniqueness: 0, lead_time: 0, accuracy: 0, relevance: 0, impact: 0, noise: 0 })).toEqual(0);
  });

  it('should only count revocations that are not the natural end of life of an indicator', () => {
    expect(isNegativeRevocation({ revoked: false })).toBe(false);
    expect(isNegativeRevocation({ revoked: true })).toBe(true);
    expect(isNegativeRevocation({ revoked: true, x_opencti_score: 10, decay_applied_rule: { decay_revoke_score: 20 } })).toBe(false);
    expect(isNegativeRevocation({ revoked: true, x_opencti_score: 80, decay_applied_rule: { decay_revoke_score: 20 } })).toBe(true);
  });

  it('should detect expired objects', () => {
    const now = Date.UTC(2026, 9, 3);
    expect(isExpired({ entity_type: 'Indicator', valid_until: '2026-01-01T00:00:00.000Z' }, now)).toBe(true);
    expect(isExpired({ entity_type: 'Indicator', valid_until: '2027-01-01T00:00:00.000Z' }, now)).toBe(false);
    expect(isExpired({ entity_type: 'Indicator', revoked: true, x_opencti_score: 5, decay_applied_rule: { decay_revoke_score: 20 } }, now)).toBe(true);
    expect(isExpired({ entity_type: 'Malware' }, now)).toBe(false);
  });

  it('should build stable scorecard identifiers', () => {
    expect(scorecardDocumentId('source-1', 'LAST_30_DAYS', '2026-10-03', true)).toEqual('source-1--LAST_30_DAYS--live');
    expect(scorecardDocumentId('source-1', 'LAST_30_DAYS', '2026-10-03', false)).toEqual('source-1--LAST_30_DAYS--2026-10-03');
    expect(toSnapshotDate(Date.UTC(2026, 9, 3, 23, 59))).toEqual('2026-10-03');
  });
});
