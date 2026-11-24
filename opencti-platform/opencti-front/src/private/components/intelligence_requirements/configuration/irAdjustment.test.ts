import { describe, expect, it } from 'vitest';
import {
  adjustmentToRule,
  choose,
  directionResolver,
  emptyAdjustment,
  hopOptions,
  intermediateTypes,
  isAdjustmentComplete,
  ruleToAdjustment,
  secondHopOptions,
  withAdjustmentGroups,
  type IrAdjustment,
  type IrRelationMapping,
} from './irAdjustment';
import { emptyGroup } from './irConfigTypes';

const RELATIONS: Record<string, string[]> = {
  Malware_Sector: ['targets'],
  Malware_Region: ['targets'],
  'Intrusion-Set_Sector': ['targets'],
  'Intrusion-Set_Region': ['targets', 'originates-from'],
  'Intrusion-Set_Malware': ['uses'],
  'Malware_Attack-Pattern': ['uses'],
  'Intrusion-Set_Attack-Pattern': ['uses'],
  Malware_Malware: ['related-to'],
};
const mapping: IrRelationMapping = (from, to) => RELATIONS[`${from}_${to}`] ?? [];
const TYPES = ['Malware', 'Intrusion-Set', 'Sector', 'Region', 'Attack-Pattern'];
const europe = { value: 'europe', label: 'Europe', type: 'Region' };

const linked = (patch: Partial<IrAdjustment>): IrAdjustment => ({ ...emptyAdjustment('c1'), id: 'b1', points: 15, kind: 'linked', ...patch });

describe('hop options', () => {
  it('reads each relationship from the flagged entity side, both ways', () => {
    const values = hopOptions(['Malware'], TYPES, mapping).map((o) => o.value);
    expect(values).toEqual(expect.arrayContaining(['uses|outgoing', 'uses|incoming', 'targets|outgoing', 'related-to|outgoing']));
    expect(values).not.toContain('related-to|incoming'); // the same both ways: offered once
    expect(hopOptions(['Malware'], TYPES, mapping).find((o) => o.value === 'uses|incoming')?.endTypes).toEqual(['Intrusion-Set']);
  });
  it('offers only what every flagged type has when the adjustment applies to any of them', () => {
    const options = hopOptions(['Malware', 'Intrusion-Set'], TYPES, mapping);
    expect(options.find((o) => o.value === 'targets|outgoing')?.endTypes).toEqual(['Sector', 'Region']);
    expect(options.map((o) => o.value)).not.toContain('originates-from|outgoing'); // malware does not originate
  });
  it('follows the second relationship outward only, from types that have one', () => {
    expect(secondHopOptions('Intrusion-Set', TYPES, mapping).every((o) => o.dir === 'outgoing')).toBe(true);
    const usedBy = hopOptions(['Malware'], TYPES, mapping).find((o) => o.value === 'uses|incoming');
    expect(intermediateTypes(usedBy, TYPES, mapping)).toEqual(['Intrusion-Set']);
  });
});

describe('choices', () => {
  it('clears the choices after the one changed', () => {
    const full = linked({ hops: 'two', rel1: 'uses', dir1: 'incoming', bi1: true, inter: 'Intrusion-Set', rel2: 'targets', ends: [europe] });
    expect(choose(full, 'first', { rel1: 'targets', dir1: 'outgoing' })).toMatchObject({ rel1: 'targets', bi1: false, inter: null, rel2: null, ends: [] });
    expect(choose(full, 'appliesTo', { appliesTo: 'Malware' })).toMatchObject({ kind: null, hops: null, rel1: null, ends: [] });
  });
  it('is complete once the path ends on chosen entities', () => {
    expect(isAdjustmentComplete(linked({ hops: 'direct', rel1: 'targets', dir1: 'outgoing' }))).toBe(false);
    expect(isAdjustmentComplete(linked({ hops: 'direct', rel1: 'targets', dir1: 'outgoing', ends: [europe] }))).toBe(true);
    expect(isAdjustmentComplete(linked({ hops: 'two', rel1: 'uses', dir1: 'incoming', ends: [europe] }))).toBe(false);
  });
});

describe('saving as a rule', () => {
  it('saves a direct link as a link to a hidden group of the chosen entities', () => {
    const { rule, group } = adjustmentToRule(linked({ hops: 'direct', rel1: 'targets', dir1: 'outgoing', ends: [europe], appliesTo: 'Malware' }), 'n');
    expect(group).toMatchObject({ id: 'ga-b1', kind: 'list', role: 'context', entities: [europe] });
    expect(rule).toMatchObject({ id: 'b1', points: 15, applies_to_types: ['Malware'], applies_to_criterion_id: 'c1', link: { relationship_types: ['targets'], group_ids: ['ga-b1'] }, path_condition: null });
  });
  it('saves a path through an entity with its type in between and its direction', () => {
    const one = adjustmentToRule(linked({ hops: 'two', rel1: 'uses', dir1: 'incoming', inter: 'Intrusion-Set', rel2: 'targets', ends: [europe] }), 'n').rule;
    expect(one.path_condition).toMatchObject({ relationship_types: ['uses'], direction: 'incoming', intermediate_types: ['Intrusion-Set'], target_relationship_type: 'targets', targets: [europe] });
    const both = adjustmentToRule(linked({ hops: 'two', rel1: 'uses', dir1: 'incoming', bi1: true, inter: 'Intrusion-Set', rel2: 'targets', ends: [europe] }), 'n').rule;
    expect(both.path_condition?.direction).toBe('both');
  });
  it('saves a property as filters', () => {
    const { rule, group } = adjustmentToRule({ ...emptyAdjustment('c1'), kind: 'property', filters: '{"mode":"and"}' }, 'n');
    expect(rule.filters).toBe('{"mode":"and"}');
    expect(group).toBeNull();
  });
  it('reads a saved rule back for editing', () => {
    const a = linked({ hops: 'two', rel1: 'uses', dir1: 'incoming', inter: 'Intrusion-Set', rel2: 'targets', ends: [europe], appliesTo: 'Malware' });
    expect(ruleToAdjustment(adjustmentToRule(a, 'n').rule, [])).toMatchObject({ kind: 'linked', hops: 'two', rel1: 'uses', dir1: 'incoming', bi1: false, inter: 'Intrusion-Set', rel2: 'targets', ends: [europe], appliesTo: 'Malware', points: 15 });
    const direct = adjustmentToRule(linked({ hops: 'direct', rel1: 'targets', dir1: 'outgoing', ends: [europe] }), 'n');
    expect(ruleToAdjustment(direct.rule, [direct.group!])).toMatchObject({ hops: 'direct', rel1: 'targets', bi1: true, ends: [europe] });
  });
  it('drops the hidden group of an adjustment once its rule is gone', () => {
    const direct = adjustmentToRule(linked({ hops: 'direct', rel1: 'targets', dir1: 'outgoing', ends: [europe] }), 'n');
    const other = { ...emptyGroup(), id: 'g-entry' };
    expect(withAdjustmentGroups([other], [direct.rule], direct.group).map((g) => g.id)).toEqual(['g-entry', 'ga-b1']);
    expect(withAdjustmentGroups([other, direct.group!], [], null).map((g) => g.id)).toEqual(['g-entry']);
  });
});

describe('reading a direct link back', () => {
  it('takes the reading of the relationship that leads to the chosen entities', () => {
    const resolve = directionResolver(['Malware'], TYPES, mapping);
    expect(resolve('uses', ['Intrusion-Set'])).toBe('incoming'); // the malware "is used by" an intrusion set
    expect(resolve('uses', ['Attack-Pattern'])).toBe('outgoing'); // the malware "uses" an attack pattern
    const direct = adjustmentToRule(linked({ hops: 'direct', rel1: 'uses', dir1: 'incoming', ends: [{ value: 'apt', label: 'APT28', type: 'Intrusion-Set' }] }), 'n');
    expect(ruleToAdjustment(direct.rule, [direct.group!], resolve).dir1).toBe('incoming');
  });
});
