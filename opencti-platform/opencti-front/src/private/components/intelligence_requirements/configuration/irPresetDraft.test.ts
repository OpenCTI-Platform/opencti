import { describe, expect, it } from 'vitest';
import { draftToInput } from './irConfigTypes';
import { defaultItemName, defaultRuleName, emptyValue, presetItemsToDraft, presetQueryChips, validatePresetItems, type IrPresetItem, type IrPresetValue } from './irPresetDraft';

const t = (s: string) => s;
const fs = { value: 'id-fs', label: 'Financial services', type: 'Sector' };
const ap = (id: string) => ({ value: id, label: id, type: 'Attack-Pattern' });
const v = (patch: Partial<IrPresetValue>) => ({ ...emptyValue(), ...patch });
const typeRule = { id: 'r1', ruleKey: 'malware-type', value: v({ terms: ['trojan', 'remote-access-trojan', 'keylogger'] }) };
const targetsRule = { id: 'r2', ruleKey: 'targets', value: v({ entities: [fs] }) };
const usesRule = { id: 'r3', ruleKey: 'uses', value: v({ entities: [ap('T1185'), ap('T1056.003'), ap('T1557')] }) };
const general = { name: 'Banking malware', question: 'Which malware threatens our banking customers?', description: '', priority: 'high' as const };

describe('default names', () => {
  it('writes the name from the rule and its values', () => {
    expect(defaultRuleName('malware', targetsRule, t)).toBe('Malware targeting Financial services');
  });
  it('lists three values, then +N more', () => {
    const four = { ...usesRule, value: v({ entities: [...usesRule.value.entities, ap('T1059')] }) };
    expect(defaultRuleName('malware', four, t)).toBe('Malware using T1185, T1056.003, T1557 +1 more');
  });
  it('names a group after its first rule', () => {
    expect(defaultItemName('malware', { id: 'g', kind: 'group', name: '', rules: [targetsRule, usesRule] }, t)).toBe('Malware targeting Financial services');
  });
  it('places a {v} verb correctly', () => {
    expect(defaultRuleName('vulnerability', { id: 'x', ruleKey: 'cvss', value: v({ number: 9 }) }, t)).toBe('Vulnerabilities with CVSS 9 or higher');
  });
});

describe('presetItemsToDraft', () => {
  const items: IrPresetItem[] = [
    { id: 'i1', kind: 'rule', name: 'Banking malware types', rule: typeRule },
    { id: 'i2', kind: 'group', name: 'Malware targeting Financial services', rules: [targetsRule, usesRule] },
  ];
  const draft = presetItemsToDraft(general, 'malware', ['Malware'], items);
  it('makes one criterion per top-level item, named after it', () => {
    expect(draft.criteria.map((c) => [c.name, c.kind])).toEqual([['Banking malware types', 'attribute'], ['Malware targeting Financial services', 'graph']]);
  });
  it('reads the flagged malware as the source of targets', () => {
    const c = draft.criteria[1];
    expect([c.relationship_types, c.direction, c.target_types]).toEqual([['targets'], 'incoming', ['Malware']]);
    expect(draft.groups.find((g) => g.id === c.from_group_ids[0])?.entities).toEqual([fs]);
  });
  it('turns the second rule of a group into a link condition', () => {
    const [cond] = draft.criteria[1].conditions;
    expect(cond.link?.relationship_types).toEqual(['uses']);
    expect(cond.name).toBe('Malware using T1185, T1056.003, T1557');
  });
  it('filters the malware type on the entity', () => {
    expect(JSON.parse(draft.criteria[0].target_filters!).filters[0]).toMatchObject({ key: ['malware_types'], values: ['trojan', 'remote-access-trojan', 'keylogger'], operator: 'eq' });
  });
  it('produces an input the backend accepts', () => {
    const input = draftToInput(draft);
    expect(input.ir_scope_criteria).toHaveLength(2);
    const used = (id: string) => input.ir_scope_criteria.some((c) => c.from_group_ids.includes(id) || c.conditions.some((k) => k.link?.group_ids.includes(id)));
    expect(input.ir_subject_groups.every((g) => used(g.id))).toBe(true);
  });
  it('converts a one-rule group like a single rule', () => {
    const one = presetItemsToDraft(general, 'malware', ['Malware'], [{ id: 'g', kind: 'group', name: 'n', rules: [targetsRule] }]);
    expect(one.criteria[0].conditions).toEqual([]);
  });
  it('anchors on both a list and a filter group when entities and types are mixed', () => {
    const mixed = { ...targetsRule, value: v({ entities: [fs], types: ['Country'] }) };
    const d = presetItemsToDraft(general, 'malware', ['Malware'], [{ id: 'x', kind: 'rule', name: 'n', rule: mixed }]);
    expect(d.criteria[0].from_group_ids.map((id) => d.groups.find((g) => g.id === id)?.kind).sort()).toEqual(['filter', 'list']);
  });
});

describe('validatePresetItems', () => {
  it('needs at least one rule', () => {
    expect(validatePresetItems([])[0].message).toBe('Add at least one rule');
  });
  it('flags a rule with no value', () => {
    const empty = { id: 'i', kind: 'rule' as const, name: 'n', rule: { ...targetsRule, value: emptyValue() } };
    expect(validatePresetItems([empty])).toEqual([{ itemId: 'i', ruleId: 'r2', message: 'Add a value' }]);
  });
  it('accepts a rule with nothing to edit', () => {
    expect(validatePresetItems([{ id: 'i', kind: 'rule', name: 'n', rule: { id: 'k', ruleKey: 'indicated', value: emptyValue() } }])).toEqual([]);
  });
});

describe('presetQueryChips', () => {
  it('shows the targets query as in the mockup', () => {
    expect(presetQueryChips(targetsRule, ['Malware'], t)).toEqual([
      { key: 'Relationship type', values: 'targets', fromUser: false },
      { key: 'Source type', values: 'Malware', fromUser: false },
      { key: 'Target', values: 'Financial services', fromUser: true },
    ]);
  });
});
