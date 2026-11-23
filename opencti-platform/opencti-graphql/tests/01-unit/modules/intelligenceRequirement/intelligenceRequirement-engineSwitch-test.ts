import { describe, expect, it } from 'vitest';
import { checkInPirParity, inPirRelationToMatch } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-pirLink';
import { canonicalPirFilters, samePirExplanations } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-projection';
import { legacyCriterionId } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-legacy';
import type { BasicStoreRelationPir } from '../../../../src/modules/pir/pir-types';

const france = '{"mode":"and","filters":[{"key":["toId"],"values":["france"]}],"filterGroups":[]}';
const healthcare = '{"mode":"and","filters":[{"key":["toId"],"values":["healthcare"]}],"filterGroups":[]}';
// Same criterion as france, written with another key order (the legacy manager re-serializes the parsed criterion)
const franceReordered = '{"filterGroups":[],"filters":[{"values":["france"],"key":["toId"]}],"mode":"and"}';

const pir = { pir_criteria: [{ filters: france, weight: 2 }, { filters: healthcare, weight: 1 }] };
const AT = '2026-11-22T06:00:00.000Z';

const relation = (pir_score: number, pir_explanation: BasicStoreRelationPir['pir_explanation']) => ({
  fromId: 'malware-1',
  fromType: 'Malware',
  pir_score,
  pir_explanation,
} as unknown as BasicStoreRelationPir);

describe('Pir engine switch: parity of the legacy flags', () => {
  it('should compare criterion filters whatever their key order', () => {
    expect(canonicalPirFilters(france)).toEqual(canonicalPirFilters(franceReordered));
    expect(canonicalPirFilters(france)).not.toEqual(canonicalPirFilters(healthcare));
    expect(canonicalPirFilters('not json')).toEqual('not json');
  });

  it('should compare legacy explanations whatever their order and the order of their dependencies', () => {
    const a = [
      { criterion: { filters: france, weight: 2 }, dependencies: [{ element_id: 'rel-1', author_id: 'author' }, { element_id: 'rel-3', author_id: null }] },
      { criterion: { filters: healthcare, weight: 1 }, dependencies: [{ element_id: 'rel-2', author_id: null }] },
    ];
    const b = [
      { criterion: { filters: healthcare, weight: 1 }, dependencies: [{ element_id: 'rel-2' }] },
      { criterion: { filters: franceReordered, weight: 2 }, dependencies: [{ element_id: 'rel-3', author_id: null }, { element_id: 'rel-1', author_id: 'author' }] },
    ];
    expect(samePirExplanations(a, b)).toBe(true);
    expect(samePirExplanations(a, [a[0]])).toBe(false);
    const otherAuthor = [{ ...a[0], dependencies: [{ element_id: 'rel-1', author_id: 'someone-else' }, a[0].dependencies[1]] }, a[1]];
    expect(samePirExplanations(a, otherAuthor)).toBe(false);
    const otherWeight = [{ ...a[0], criterion: { filters: france, weight: 3 } }, a[1]];
    expect(samePirExplanations(a, otherWeight)).toBe(false);
  });

  it('should turn a flag into the entity of the requirement with one proof per dependency', () => {
    const seed = inPirRelationToMatch(pir, relation(100, [
      { criterion: { filters: franceReordered, weight: 2 }, dependencies: [{ element_id: 'rel-1', author_id: 'author' }] },
      { criterion: { filters: healthcare, weight: 1 }, dependencies: [{ element_id: 'rel-2', author_id: null }] },
    ]), AT);
    expect(seed.match_criteria_ids.sort()).toEqual([legacyCriterionId(0), legacyCriterionId(1)].sort());
    expect(seed.match_score).toEqual(100);
    expect(JSON.parse(seed.match_explanations)).toEqual([
      { criterion_id: legacyCriterionId(0), kind: 'graph', at: AT, relationship_id: 'rel-1', author_id: 'author' },
      { criterion_id: legacyCriterionId(1), kind: 'graph', at: AT, relationship_id: 'rel-2', author_id: null },
    ]);
  });

  it('should pass the parity of flags written by the legacy engine (score and explanations unchanged)', () => {
    expect(checkInPirParity(pir, relation(67, [
      { criterion: { filters: franceReordered, weight: 2 }, dependencies: [{ element_id: 'rel-1', author_id: 'author' }] },
    ]), AT)).toBeNull();
    expect(checkInPirParity(pir, relation(33, [
      { criterion: { filters: healthcare, weight: 1 }, dependencies: [{ element_id: 'rel-2' }, { element_id: 'rel-4' }] },
    ]), AT)).toBeNull();
    expect(checkInPirParity(pir, relation(100, [
      { criterion: { filters: healthcare, weight: 1 }, dependencies: [{ element_id: 'rel-2', author_id: null }] },
      { criterion: { filters: france, weight: 2 }, dependencies: [{ element_id: 'rel-1', author_id: 'author' }] },
    ]), AT)).toBeNull();
  });

  it('should refuse the switch of a flag the requirement would write differently', () => {
    // a score the legacy formula does not give for these criteria (edited weights after the flag)
    expect(checkInPirParity(pir, relation(50, [
      { criterion: { filters: france, weight: 2 }, dependencies: [{ element_id: 'rel-1' }] },
    ]), AT)).toEqual({ entity_id: 'malware-1', stored_score: 50, projected_score: 67, same_explanations: true });
    // an explanation on a criterion the Pir no longer has
    const stale = checkInPirParity(pir, relation(67, [
      { criterion: { filters: france, weight: 2 }, dependencies: [{ element_id: 'rel-1' }] },
      { criterion: { filters: '{"mode":"and","filters":[],"filterGroups":[]}', weight: 5 }, dependencies: [{ element_id: 'rel-9' }] },
    ]), AT);
    expect(stale?.same_explanations).toBe(false);
  });
});
