import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  computeDocumentSignals,
  emptyPageLookups,
  periodCounting,
  type RunLookups,
  type ScanDocument,
  toAssertionActivity,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-compute';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';

const NOW = new Date('2026-10-01T00:00:00.000Z').getTime();

const run: RunLookups = {
  asOf: NOW,
  falsePositiveLabelIds: new Set(['label-false-positive']),
  pirFlaggedIds: null,
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
