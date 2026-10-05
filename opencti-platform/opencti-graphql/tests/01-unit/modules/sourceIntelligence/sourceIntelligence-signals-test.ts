import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  computeDocumentSignals,
  countedByLastScan,
  emptyPageLookups,
  periodCounting,
  type RunLookups,
  type ScanDocument,
  scanPageSize,
  type ScanTrace,
  signalSeenByLastScan,
  toAssertionActivity,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-compute';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';

const NOW = new Date('2026-10-01T00:00:00.000Z').getTime();

const run: RunLookups = {
  asOf: NOW,
  historical: false,
  falsePositiveLabelIds: new Set(['label-false-positive']),
  pirRelevance: false,
  huntTrueRunIds: [],
  availability: { provenance: 'assertions', pulse: false, huntRunType: null },
};

const indicator = (overrides: Partial<ScanDocument> = {}): ScanDocument => ({
  internal_id: 'indicator-1',
  entity_type: ENTITY_TYPE_INDICATOR,
  created: '2026-09-01T00:00:00.000Z',
  valid_until: '2027-01-01T00:00:00.000Z',
  ...overrides,
});

describe('Source intelligence document signals', () => {
  it('should keep an indicator without negative signal accurate', () => {
    const signals = computeDocumentSignals(indicator(), emptyPageLookups(), run, NOW);
    expect(signals.negative).toBe(false);
    expect(signals.decayExcluded).toBe(false);
  });

  it('should count an indicator excluded by a decay exclusion rule as negative', () => {
    const doc = indicator({ decay_exclusion_applied_rule: { decay_exclusion_id: 'exclusion-1' } });
    const signals = computeDocumentSignals(doc, emptyPageLookups(), run, NOW);
    expect(signals.decayExcluded).toBe(true);
    expect(signals.negative).toBe(true);
  });

  it('should count false positive labels and negative sightings as negative', () => {
    const labelled = computeDocumentSignals(indicator({ 'rel_object-label.internal_id': ['label-false-positive'] }), emptyPageLookups(), run, NOW);
    expect(labelled.falsePositive).toBe(true);
    expect(labelled.negative).toBe(true);
    const page = emptyPageLookups();
    page.negativeSightings.set('indicator-1', 1);
    const sighted = computeDocumentSignals(indicator(), page, run, NOW);
    expect(sighted.negativelySighted).toBe(true);
    expect(sighted.negative).toBe(true);
  });

  it('should never count in a past day a revocation, false positive label or decay exclusion it could not have seen', () => {
    // A backfilled day, ten days before the object was last updated
    const pastDay = new Date('2026-09-20T23:59:59.999Z').getTime();
    const backfill = { ...run, historical: true };
    const negatives: Partial<ScanDocument> = {
      revoked: true,
      'rel_object-label.internal_id': ['label-false-positive'],
      decay_exclusion_applied_rule: { decay_exclusion_id: 'exclusion-1' },
    };
    const updatedSince = indicator({ ...negatives, updated_at: '2026-09-30T00:00:00.000Z' });
    const signals = computeDocumentSignals(updatedSince, emptyPageLookups(), backfill, pastDay);
    expect(signals.negativeRevocation).toBe(false);
    expect(signals.falsePositive).toBe(false);
    expect(signals.decayExcluded).toBe(false);
    expect(signals.negative).toBe(false);
    // A negative sighting created before that day is dated: it still counts
    const page = emptyPageLookups();
    page.negativeSightings.set('indicator-1', 1);
    expect(computeDocumentSignals(updatedSince, page, backfill, pastDay).negative).toBe(true);
    // Not updated since that day: its current state is its state on that day
    const unchanged = computeDocumentSignals(indicator({ ...negatives, updated_at: '2026-09-10T00:00:00.000Z' }), emptyPageLookups(), backfill, pastDay);
    expect(unchanged.negativeRevocation).toBe(true);
    expect(unchanged.falsePositive).toBe(true);
    expect(unchanged.decayExcluded).toBe(true);
    // The live computation reads the current state, the stream applying the later changes
    expect(computeDocumentSignals(updatedSince, emptyPageLookups(), run, pastDay).negative).toBe(true);
  });

  it('should only expire an object in a past day by a decay revocation known on that day', () => {
    const pastDay = new Date('2026-09-20T23:59:59.999Z').getTime();
    const backfill = { ...run, historical: true };
    const decayRevoked: Partial<ScanDocument> = { revoked: true, x_opencti_score: 10, decay_applied_rule: { decay_revoke_score: 20 } };
    expect(computeDocumentSignals(indicator({ ...decayRevoked, updated_at: '2026-09-30T00:00:00.000Z' }), emptyPageLookups(), backfill, pastDay).expired).toBe(false);
    expect(computeDocumentSignals(indicator({ ...decayRevoked, updated_at: '2026-09-10T00:00:00.000Z' }), emptyPageLookups(), backfill, pastDay).expired).toBe(true);
    // The end of validity is a date: compared with that day whatever the later updates
    const ended = indicator({ valid_until: '2026-09-15T00:00:00.000Z', updated_at: '2026-09-30T00:00:00.000Z' });
    expect(computeDocumentSignals(ended, emptyPageLookups(), backfill, pastDay).expired).toBe(true);
  });

  it('should read the PIR relevance of an entity and of the entities a relationship connects from its page', () => {
    const page = emptyPageLookups();
    page.pirFlagged.add('indicator-1');
    page.pirFlagged.add('malware-1');
    const enterprise = { ...run, pirRelevance: true };
    expect(computeDocumentSignals(indicator(), page, enterprise, NOW).pirMatched).toBe(true);
    expect(computeDocumentSignals(indicator({ internal_id: 'indicator-2' }), page, enterprise, NOW).pirMatched).toBe(false);
    const relationship: ScanDocument = {
      internal_id: 'relationship-1',
      entity_type: 'indicates',
      connections: [{ internal_id: 'indicator-2', role: 'indicates_from' }, { internal_id: 'malware-1', role: 'indicates_to' }],
    };
    expect(computeDocumentSignals(relationship, page, enterprise, NOW).pirMatched).toBe(true);
    // Outside Enterprise Edition, PIR relevance is not measured
    expect(computeDocumentSignals(indicator(), page, run, NOW).pirMatched).toBe(false);
  });

  it('should only count in a past day a PIR score that last changed before it', () => {
    const pastDay = new Date('2026-09-20T23:59:59.999Z').getTime();
    const backfill = { ...run, historical: true, pirRelevance: true };
    const scored = (date: string | null) => indicator({ pir_information: [{ pir_id: 'pir-1', pir_score: 50, last_pir_score_date: date }] });
    expect(computeDocumentSignals(scored('2026-09-30T00:00:00.000Z'), emptyPageLookups(), backfill, pastDay).pirMatched).toBe(false);
    expect(computeDocumentSignals(scored(null), emptyPageLookups(), backfill, pastDay).pirMatched).toBe(false);
    expect(computeDocumentSignals(scored('2026-09-10T00:00:00.000Z'), emptyPageLookups(), backfill, pastDay).pirMatched).toBe(true);
    // A PIR link dated before that day still counts, and the live computation reads the current score
    const page = emptyPageLookups();
    page.pirFlagged.add('indicator-1');
    expect(computeDocumentSignals(scored('2026-09-30T00:00:00.000Z'), page, backfill, pastDay).pirMatched).toBe(true);
    expect(computeDocumentSignals(scored('2026-09-30T00:00:00.000Z'), emptyPageLookups(), { ...run, pirRelevance: true }, pastDay).pirMatched).toBe(true);
  });
});

describe('Source intelligence scan trace', () => {
  // Pages requested at 1100, 1200 and 1300, ending at internal ids 'b', 'm' and 't', by a computation started at 1000
  const trace: ScanTrace = { started_at: 1000, pages: [[1100, 'b'], [1200, 'm'], [1300, 't']] };

  it('should remove a deleted object only when the last scan counted it', () => {
    // Deleted after its page was read: counted
    expect(countedByLastScan(trace, 'c', 500, 1250)).toBe(true);
    // Deleted before its page was read, or beyond the scanned range: never counted
    expect(countedByLastScan(trace, 'c', 500, 1150)).toBe(false);
    expect(countedByLastScan(trace, 'z', 500, 1400)).toBe(false);
    // Created after the start, deleted before the computation, or no trace: the live accounting rules apply
    expect(countedByLastScan(trace, 'c', 1050, 1150)).toBe(true);
    expect(countedByLastScan(trace, 'c', 500, 900)).toBe(true);
    expect(countedByLastScan(null, 'c', 500, 1150)).toBe(true);
  });

  it('should skip a signal given during the scan only when the scan read it after the event', () => {
    // Page 'm' requested at 1200, its signals looked up at 1250
    const withSignals: ScanTrace = { started_at: 1000, pages: [[1100, 'b', 1150], [1200, 'm', 1250], [1300, 't', 1350]] };
    // A revocation is read with the object: before the page request it is already counted, after it is not
    expect(signalSeenByLastScan(withSignals, 'c', 500, 1190, 'object')).toBe(true);
    expect(signalSeenByLastScan(withSignals, 'c', 500, 1210, 'object')).toBe(false);
    // A sighting, PIR match or hunt verdict is read with the signals of the page
    expect(signalSeenByLastScan(withSignals, 'c', 500, 1210, 'signals')).toBe(true);
    expect(signalSeenByLastScan(withSignals, 'c', 500, 1260, 'signals')).toBe(false);
    // A trace without lookup times falls back to the page request time
    expect(signalSeenByLastScan(trace, 'c', 500, 1190, 'signals')).toBe(true);
    expect(signalSeenByLastScan(trace, 'c', 500, 1210, 'signals')).toBe(false);
    // Before the computation, on an object created after its start or beyond the scanned range, or without a trace:
    // the stream applies the signal
    expect(signalSeenByLastScan(withSignals, 'c', 500, 900, 'signals')).toBe(false);
    expect(signalSeenByLastScan(withSignals, 'c', 1050, 1100, 'signals')).toBe(false);
    expect(signalSeenByLastScan(withSignals, 'z', 500, 1100, 'signals')).toBe(false);
    expect(signalSeenByLastScan(null, 'c', 500, 1100, 'signals')).toBe(false);
  });
});

describe('Source intelligence assertion activity', () => {
  const DAY = 24 * 3600 * 1000;
  const january = Date.UTC(2026, 0, 10);
  const august = Date.UTC(2026, 7, 31);
  const october = Date.UTC(2026, 9, 1);

  it('should never count in a past snapshot an assertion made after it', () => {
    // First asserted in January, asserted again in October: an August snapshot only knows the January assertion
    const activity = toAssertionActivity({ sourceId: 'source-1', firstAt: january, lastAt: october }, january, october, august);
    expect(activity.end).toEqual(january);
    expect(periodCounting(activity, august - 30 * DAY, august)).toEqual({ inVolume: false, isNew: false, lastDay: false });
  });

  it('should keep the last assertion when it is known at the computation time', () => {
    const activity = toAssertionActivity({ sourceId: 'source-1', firstAt: january, lastAt: august - DAY }, january, august, august);
    expect(activity.end).toEqual(august - DAY);
    expect(periodCounting(activity, august - 30 * DAY, august).inVolume).toBe(true);
    // Undated assertions fall back to the object dates under the same rule
    const undated = toAssertionActivity({ sourceId: 'source-1', firstAt: null, lastAt: null }, january, october, august);
    expect(undated.start).toEqual(january);
    expect(undated.end).toEqual(january);
  });
});

describe('Source intelligence scan limit', () => {
  it('should request the objects left below the limit and one more that only tells whether the scan is truncated', () => {
    expect(scanPageSize(1000, 0)).toEqual({ remaining: 1000, size: 1001 });
    expect(scanPageSize(1, 0)).toEqual({ remaining: 1, size: 2 });
    expect(scanPageSize(1500, 1000)).toEqual({ remaining: 500, size: 501 });
  });

  it('should never request more than a page', () => {
    expect(scanPageSize(2000000, 0)).toEqual({ remaining: 2000000, size: 2000 });
    expect(scanPageSize(4000, 2000)).toEqual({ remaining: 2000, size: 2000 });
  });

  it('should only check for one more object once the limit is reached', () => {
    expect(scanPageSize(4000, 4000)).toEqual({ remaining: 0, size: 1 });
    expect(scanPageSize(4000, 4500)).toEqual({ remaining: 0, size: 1 });
  });
});
