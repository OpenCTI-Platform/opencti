import type { SourceIntelligenceValueWeights } from './sourceIntelligence-settings';
import type { SourceCost, SourceScorecardMetrics } from './sourceIntelligence-types';

const HOUR_MS = 3600 * 1000;
const DAYS_PER_COST_PERIOD: Record<SourceCost['period'], number> = {
  month: 365.25 / 12,
  quarter: 365.25 / 4,
  year: 365.25,
};

export const round = (value: number, digits = 4): number => {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
};

export const ratio = (numerator: number, denominator: number): number | null => {
  if (denominator <= 0) {
    return null;
  }
  return round(Math.min(1, Math.max(0, numerator / denominator)));
};

export const median = (values: number[]): number | null => {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const value = sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
  return round(value, 2);
};

/**
 * Bounded sample used to compute medians over very large sources without keeping every value in memory.
 * Algorithm R reservoir sampling with a deterministic pseudo random generator so recomputations are stable.
 */
export class ReservoirSample {
  private readonly capacity: number;

  private readonly values: number[] = [];

  private seen = 0;

  private seed: number;

  constructor(capacity = 10000, seed = 42) {
    this.capacity = capacity;
    this.seed = seed;
  }

  private nextRandom(): number {
    // Mulberry32
    this.seed = (this.seed + 0x6D2B79F5) | 0;
    let t = this.seed;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  add(value: number) {
    this.seen += 1;
    if (this.values.length < this.capacity) {
      this.values.push(value);
      return;
    }
    const index = Math.floor(this.nextRandom() * this.seen);
    if (index < this.capacity) {
      this.values[index] = value;
    }
  }

  get size() {
    return this.seen;
  }

  median(): number | null {
    return median(this.values);
  }
}

/**
 * Advance of a source over the next source asserting the same object, in hours.
 * Positive when the source asserted the object before every other source, negative when it came later.
 */
export const computeLeadTimeHours = (sourceFirstAt: number, othersFirstAt: number[]): number | null => {
  const others = othersFirstAt.filter((t) => Number.isFinite(t));
  if (!Number.isFinite(sourceFirstAt) || others.length === 0) {
    return null;
  }
  return round((Math.min(...others) - sourceFirstAt) / HOUR_MS, 2);
};

/**
 * Cost of the source for a period of `days` days, from a manual cost declared per month, quarter or year.
 */
export const normalizeCostToDays = (cost: SourceCost | null | undefined, days: number): number | null => {
  if (!cost || !Number.isFinite(cost.amount) || cost.amount < 0) {
    return null;
  }
  const periodDays = DAYS_PER_COST_PERIOD[cost.period];
  if (!periodDays) {
    return null;
  }
  return round((cost.amount * days) / periodDays, 2);
};

export const computeCostPerActionable = (cost: SourceCost | null | undefined, days: number, actionableCount: number): number | null => {
  const normalized = normalizeCostToDays(cost, days);
  if (normalized === null || actionableCount <= 0) {
    return null;
  }
  return round(normalized / actionableCount, 4);
};

/**
 * Impact on a logarithmic 0-100 scale: incidents weigh more than security platform sightings, which weigh more than
 * any other sighting.
 */
export const computeImpactScore = (input: {
  sightings_count: number;
  security_platform_sightings_count: number;
  incidents_count: number;
}): number => {
  const otherSightings = Math.max(0, input.sightings_count - input.security_platform_sightings_count);
  const raw = otherSightings
    + 2 * input.security_platform_sightings_count
    + 3 * input.incidents_count;
  if (raw <= 0) {
    return 0;
  }
  return round(Math.min(100, 25 * Math.log10(1 + raw)), 2);
};

export const computeFreshnessHours = (lastAssertedAt: number | null, now: number): number | null => {
  if (lastAssertedAt === null || !Number.isFinite(lastAssertedAt)) {
    return null;
  }
  return round(Math.max(0, (now - lastAssertedAt) / HOUR_MS), 2);
};

/**
 * Operational value score (0-100): weighted average of the components that could be measured.
 * Components that are not measurable (no shared object for lead time, Community Edition for relevance...) are excluded
 * from both the numerator and the denominator instead of being counted as zero.
 */
export const computeValueScore = (
  metrics: Pick<SourceScorecardMetrics, 'unique_contribution' | 'first_reporter_share' | 'shared_count' | 'accuracy' | 'relevance' | 'impact_score' | 'noise' | 'volume_total'>,
  weights: SourceIntelligenceValueWeights,
): number => {
  if (metrics.volume_total <= 0) {
    return 0;
  }
  const components: Array<[number, number | null]> = [
    [weights.uniqueness, metrics.unique_contribution],
    [weights.lead_time, metrics.shared_count > 0 ? metrics.first_reporter_share : null],
    [weights.accuracy, metrics.accuracy],
    [weights.relevance, metrics.relevance],
    [weights.impact, metrics.impact_score / 100],
    [weights.noise, metrics.noise === null ? null : 1 - metrics.noise],
  ];
  let weighted = 0;
  let totalWeight = 0;
  components.forEach(([weight, value]) => {
    if (value !== null && Number.isFinite(value) && weight > 0) {
      weighted += weight * value;
      totalWeight += weight;
    }
  });
  if (totalWeight <= 0) {
    return 0;
  }
  return round((100 * weighted) / totalWeight, 2);
};

interface RevocableDocument {
  revoked?: boolean;
  x_opencti_score?: number | null;
  decay_applied_rule?: { decay_revoke_score?: number | null } | null;
}

/**
 * A revocation is a quality signal only when it is not the natural end of life of an indicator: an indicator revoked by
 * its decay rule (score at or below the revoke score) aged out, it was not wrong.
 */
export const isNegativeRevocation = (doc: RevocableDocument): boolean => {
  if (doc.revoked !== true) {
    return false;
  }
  const revokeScore = doc.decay_applied_rule?.decay_revoke_score;
  if (revokeScore !== undefined && revokeScore !== null && typeof doc.x_opencti_score === 'number') {
    return doc.x_opencti_score > revokeScore;
  }
  return true;
};

interface ExpirableDocument extends RevocableDocument {
  entity_type: string;
  valid_until?: string | null;
}

export const isExpired = (doc: ExpirableDocument, now: number): boolean => {
  if (doc.revoked === true && !isNegativeRevocation(doc)) {
    return true;
  }
  if (doc.valid_until) {
    const until = new Date(doc.valid_until).getTime();
    return Number.isFinite(until) && until < now;
  }
  return false;
};

export const scorecardDocumentId = (sourceId: string, period: string, snapshotDate: string, live: boolean) => {
  return `${sourceId}--${period}--${live ? 'live' : snapshotDate}`;
};

export const toSnapshotDate = (time: number): string => new Date(time).toISOString().substring(0, 10);
