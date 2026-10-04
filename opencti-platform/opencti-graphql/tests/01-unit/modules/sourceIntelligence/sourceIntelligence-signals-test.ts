import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { computeDocumentSignals, emptyPageLookups, type RunLookups, type ScanDocument } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-compute';
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
