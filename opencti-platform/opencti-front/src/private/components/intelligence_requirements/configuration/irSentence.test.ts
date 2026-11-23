import { describe, expect, it } from 'vitest';
import {
  countFilters,
  criterionToPhrases,
  criterionToStarts,
  impliedPhrases,
  IN_REQUIREMENT_START,
  phrasesToCriterion,
  relationPhraseOptions,
  startsToCriterion,
} from './irSentence';

describe('criteria as sentences', () => {
  it('offers a phrase per relationship type and direction', () => {
    const options = relationPhraseOptions();
    expect(options.find((o) => o.value === 'uses::outgoing')?.label).toBe('used by');
    expect(options.find((o) => o.value === 'uses::incoming')?.label).toBe('that use');
    expect(options.find((o) => o.value === 'beacons-to::outgoing')?.label).toBe('beacons-to (from)');
  });

  it('reads a criterion as phrases and writes it back unchanged', () => {
    const outgoing = { relationship_types: ['uses', 'targets'], direction: 'outgoing' as const };
    expect(criterionToPhrases(outgoing)).toEqual(['uses::outgoing', 'targets::outgoing']);
    expect(phrasesToCriterion(criterionToPhrases(outgoing))).toEqual(outgoing);
    const incoming = { relationship_types: ['attributed-to'], direction: 'incoming' as const };
    expect(phrasesToCriterion(criterionToPhrases(incoming))).toEqual(incoming);
    const both = { relationship_types: ['related-to'], direction: 'both' as const };
    expect(phrasesToCriterion(criterionToPhrases(both))).toEqual(both);
  });

  it('turns phrases of both directions into a "both" criterion and shows what it implies', () => {
    const picked = ['uses::outgoing', 'targets::incoming'];
    expect(phrasesToCriterion(picked)).toEqual({ relationship_types: ['uses', 'targets'], direction: 'both' });
    expect(impliedPhrases(picked)).toEqual(['uses::incoming', 'targets::outgoing']);
    expect(impliedPhrases(['uses::outgoing'])).toEqual([]);
  });

  it('maps the starting points to the subject groups and the second hop', () => {
    const criterion = { from_group_ids: ['g-dprk'], from_in_requirement: true };
    expect(criterionToStarts(criterion)).toEqual(['g-dprk', IN_REQUIREMENT_START]);
    expect(startsToCriterion(criterionToStarts(criterion))).toEqual(criterion);
    expect(startsToCriterion(['g-dprk'])).toEqual({ from_group_ids: ['g-dprk'], from_in_requirement: false });
  });

  it('counts the filters of a condition, nested groups included', () => {
    expect(countFilters(null)).toBe(0);
    expect(countFilters('')).toBe(0);
    expect(countFilters('not json')).toBe(0);
    const nested = { mode: 'and', filters: [{ key: ['confidence'] }], filterGroups: [{ mode: 'or', filters: [{ key: ['objectLabel'] }, { key: ['x_opencti_cisa_kev'] }], filterGroups: [] }] };
    expect(countFilters(JSON.stringify(nested))).toBe(3);
  });
});
