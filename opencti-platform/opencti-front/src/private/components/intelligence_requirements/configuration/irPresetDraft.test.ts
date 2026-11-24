import { describe, expect, it } from 'vitest';
import { draftToInput } from './irConfigTypes';
import type { IrPirType } from './irPresetRules';
import {
  defaultItemName,
  defaultRuleName,
  emptyValue,
  isWeightRule,
  presetItemsToDraft,
  presetQueryChips,
  validatePresetItems,
  type IrPresetItem,
  type IrPresetValue,
} from './irPresetDraft';

const t = (s: string) => s;
const fs = { value: 'id-fs', label: 'Financial services', type: 'Sector' };
const ap = (id: string) => ({ value: id, label: id, type: 'Attack-Pattern' });
const v = (patch: Partial<IrPresetValue>) => ({ ...emptyValue(), ...patch });
const typeRule = { id: 'r1', ruleKey: 'malware-type', value: v({ terms: ['trojan', 'remote-access-trojan', 'keylogger'] }) };
const targetsRule = { id: 'r2', ruleKey: 'targets', value: v({ entities: [fs] }) };
const usesRule = { id: 'r3', ruleKey: 'uses', value: v({ entities: [ap('T1185'), ap('T1056.003'), ap('T1557')] }) };
const general = { name: 'Banking malware', question: 'Which malware threatens our banking customers?', description: '', priority: 'high' as const };

const advancedRule = { id: 'adv', ruleKey: 'advanced', value: v({ filters: JSON.stringify({ mode: 'and', filters: [{ key: ['confidence'], values: ['80'], operator: 'gte', mode: 'or' }], filterGroups: [] }) }) };

describe('advanced search criteria in a group', () => {
  it('names the group with them', () => {
    expect(defaultItemName('malware', { id: 'g', kind: 'group', name: '', rules: [targetsRule, advancedRule] }, t))
      .toBe('Malware targeting Financial services AND matching custom filters');
  });
  it('asks for filters when there are none', () => {
    const group = { id: 'g', kind: 'group' as const, name: 'n', rules: [targetsRule, { ...advancedRule, value: emptyValue() }] };
    expect(validatePresetItems([group])).toEqual([{ itemId: 'g', ruleId: 'adv', message: 'Add filters' }]);
  });
  it('makes them a filters condition of the criterion', () => {
    const draft = presetItemsToDraft(general, 'malware', ['Malware'], [{ id: 'g', kind: 'group', name: 'n', rules: [targetsRule, advancedRule] }]);
    expect(draft.criteria[0].conditions[0].filters).toBe(advancedRule.value.filters);
    expect(draft.criteria[0].conditions[0].link).toBeNull();
  });
  it('makes them the criterion when they come first', () => {
    const draft = presetItemsToDraft(general, 'malware', ['Malware'], [{ id: 'g', kind: 'group', name: 'n', rules: [advancedRule, targetsRule] }]);
    expect(draft.criteria[0]).toMatchObject({ kind: 'attribute', target_types: ['Malware'], target_filters: advancedRule.value.filters });
  });
  it('shows them in the query', () => {
    expect(presetQueryChips(advancedRule, ['Malware'], t)).toEqual([
      { key: 'Entity type', operator: '=', values: 'Malware', fromUser: false },
      { key: 'Advanced search criteria', operator: '=', values: '', fromUser: true, filterCount: 1 },
    ]);
  });
});

describe('default names', () => {
  it('writes the name from the rule and its values', () => {
    expect(defaultRuleName('malware', targetsRule, t)).toBe('Malware targeting Financial services');
  });
  it('lists three values, then +N more', () => {
    const four = { ...usesRule, value: v({ entities: [...usesRule.value.entities, ap('T1059')] }) };
    expect(defaultRuleName('malware', four, t)).toBe('Malware using T1185, T1056.003, T1557 +1 more');
  });
  it('names a group of one rule after it', () => {
    expect(defaultItemName('malware', { id: 'g', kind: 'group', name: '', rules: [targetsRule] }, t)).toBe('Malware targeting Financial services');
  });
  it('names a group of two rules after both', () => {
    expect(defaultItemName('malware', { id: 'g', kind: 'group', name: '', rules: [targetsRule, usesRule] }, t))
      .toBe('Malware targeting Financial services AND using T1185, T1056.003, T1557');
    expect(defaultItemName('malware', { id: 'g', kind: 'group', name: '', rules: [targetsRule, { id: 'o', ruleKey: 'one-of', value: v({ entities: [fs] }) }] }, t))
      .toBe('Malware targeting Financial services AND one of Financial services');
  });
  it('names a group of three rules or more after its first one and the count of the others', () => {
    expect(defaultItemName('malware', { id: 'g', kind: 'group', name: '', rules: [targetsRule, usesRule, typeRule] }, t))
      .toBe('Malware targeting Financial services AND 2 more rules');
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
      { key: 'Relationship type', operator: '=', values: 'targets', fromUser: false },
      { key: 'Source type', operator: '=', values: 'Malware', fromUser: false },
      { key: 'Target', operator: '=', values: 'Financial services', fromUser: true },
    ]);
  });
  it('shows a number rule with its operator', () => {
    expect(presetQueryChips({ id: 'x', ruleKey: 'cvss', value: v({ number: 9 }) }, ['Vulnerability'], t)).toEqual([
      { key: 'Entity type', operator: '=', values: 'Vulnerability', fromUser: false },
      { key: 'CVSS score', operator: '≥', values: '9', fromUser: true },
    ]);
  });
  it('shows the fixed filter of a rule with nothing to edit', () => {
    expect(presetQueryChips({ id: 'x', ruleKey: 'kev', value: emptyValue() }, ['Vulnerability'], t)).toEqual([
      { key: 'Entity type', operator: '=', values: 'Vulnerability', fromUser: false },
      { key: 'CISA KEV', operator: '=', values: 'true', fromUser: false },
    ]);
  });
  it('shows the container constraint of a data leak', () => {
    expect(presetQueryChips({ id: 'x', ruleKey: 'data-leak', value: emptyValue() }, ['Credential'], t)).toEqual([
      { key: 'Relationship type', operator: '=', values: 'object (contained in)', fromUser: false },
      { key: 'Source type', operator: '=', values: 'Case-Incident', fromUser: false },
      { key: 'Response types', operator: '=', values: 'data-leak', fromUser: false },
    ]);
  });
  it('shows the indicator as the source of new indicators', () => {
    expect(presetQueryChips({ id: 'x', ruleKey: 'indicated', value: emptyValue() }, ['Malware'], t)).toEqual([
      { key: 'Relationship type', operator: '=', values: 'indicates', fromUser: false },
      { key: 'Source type', operator: '=', values: 'Indicator', fromUser: false },
      { key: 'Target type', operator: '=', values: 'Malware', fromUser: false },
    ]);
  });
});

describe('container types in names', () => {
  it('names plain container types, without "any"', () => {
    const rule = { id: 'x', ruleKey: 'in-container', value: v({ types: ['Report', 'Grouping'] }) };
    expect(defaultRuleName('malware', rule, t)).toBe('Malware in Report, Grouping');
  });
  it('keeps "any" for the type choice of a linked rule', () => {
    const rule = { id: 'x', ruleKey: 'targets', value: v({ types: ['Country'] }) };
    expect(defaultRuleName('malware', rule, t)).toBe('Malware targeting any Country');
  });
});

describe('each rule kind as a criterion', () => {
  const one = (rule: { id: string; ruleKey: string; value: IrPresetValue }, pirType: IrPirType = 'malware', flags = ['Malware']) => presetItemsToDraft(
    general,
    pirType,
    flags,
    [{ id: 'i', kind: 'rule', name: 'n', rule }],
  );
  const filtersOf = (c: { target_filters: string | null }) => JSON.parse(c.target_filters!);
  const groupOf = (d: ReturnType<typeof one>, i = 0) => d.groups.find((g) => g.id === d.criteria[0].from_group_ids[i])!;

  it('oneOf: a list group as entry, and an attribute criterion on it', () => {
    const d = one({ id: 'x', ruleKey: 'one-of', value: v({ entities: [fs] }) });
    expect(d.criteria[0]).toMatchObject({ kind: 'attribute', target_types: ['Malware'], target_filters: null });
    expect(groupOf(d)).toMatchObject({ kind: 'list', role: 'entry', entities: [fs] });
    expect(d.groups).toHaveLength(1);
  });
  it('entityFilter: the operator and the id values of a label', () => {
    const label = { value: 'lbl-1', label: 'banking', type: 'Label' };
    const d = one({ id: 'x', ruleKey: 'has-label', value: v({ entities: [label] }) });
    expect(filtersOf(d.criteria[0]).filters[0]).toMatchObject({ key: ['objectLabel'], values: ['lbl-1'], operator: 'eq' });
    const n = one({ id: 'x', ruleKey: 'cvss', value: v({ number: 9 }) }, 'vulnerability', ['Vulnerability']);
    expect(filtersOf(n.criteria[0]).filters[0]).toMatchObject({ key: ['x_opencti_cvss_base_score'], values: ['9'], operator: 'gte' });
    expect(d.groups).toEqual([]);
  });
  it('motivation: primary or secondary motivations', () => {
    const d = one({ id: 'x', ruleKey: 'motivation', value: v({ terms: ['ideology'] }) }, 'adversary', ['Threat-Actor-Group']);
    const fg = filtersOf(d.criteria[0]);
    expect(fg.mode).toBe('or');
    expect(fg.filters.map((f: { key: string[] }) => f.key[0])).toEqual(['primary_motivation', 'secondary_motivations']);
  });
  it('fixedFilter: the catalogue filter as it is', () => {
    const d = one({ id: 'x', ruleKey: 'kev', value: emptyValue() }, 'vulnerability', ['Vulnerability']);
    expect(filtersOf(d.criteria[0]).filters[0]).toMatchObject({ key: 'x_opencti_cisa_kev', values: ['true'] });
  });
  it('linkedViaFilter: a filter group on the anchor type and key', () => {
    const d = one({ id: 'x', ruleKey: 'affects-product', value: v({ terms: ['nginx'] }) }, 'vulnerability', ['Vulnerability']);
    expect(d.criteria[0]).toMatchObject({ kind: 'graph', relationship_types: ['has'], direction: 'outgoing' });
    expect(groupOf(d)).toMatchObject({ kind: 'filter', role: 'entry' });
    expect(JSON.parse(groupOf(d).filters!).filters.map((f: { key: string[]; values: string[] }) => [f.key[0], f.values])).toEqual([['entity_type', ['Software']], ['x_opencti_product', ['nginx']]]);
  });
  it('container: a filter group on the container types, linked by object', () => {
    const d = one({ id: 'x', ruleKey: 'in-container', value: v({ types: ['Report'] }) });
    expect(d.criteria[0]).toMatchObject({ kind: 'graph', relationship_types: ['object'], direction: 'outgoing' });
    expect(JSON.parse(groupOf(d).filters!).filters[0]).toMatchObject({ key: ['entity_type'], values: ['Report'] });
  });
  it('containerFixed: the filters of the rule', () => {
    const d = one({ id: 'x', ruleKey: 'data-leak', value: emptyValue() }, 'credential', ['Credential']);
    expect(d.criteria[0]).toMatchObject({ relationship_types: ['object'], direction: 'outgoing' });
    expect(JSON.parse(groupOf(d).filters!).filters.map((f: { values: string[] }) => f.values)).toEqual([['Case-Incident'], ['data-leak']]);
  });
  it('indicated: indicators indicating the entity', () => {
    const d = one({ id: 'x', ruleKey: 'indicated', value: emptyValue() });
    expect(d.criteria[0]).toMatchObject({ relationship_types: ['indicates'], direction: 'outgoing' });
    expect(JSON.parse(groupOf(d).filters!).filters[0]).toMatchObject({ values: ['Indicator'] });
  });
  it('domains: three alternatives on mail, account and credential', () => {
    const d = one({ id: 'x', ruleKey: 'in-domains', value: v({ terms: ['acme.com'] }) }, 'credential', ['User-Account', 'Email-Addr', 'Credential']);
    const fg = filtersOf(d.criteria[0]);
    expect(fg.mode).toBe('or');
    expect(fg.filterGroups.map((g: { filters: { key: string[]; operator: string }[] }) => [g.filters[0].key[0], g.filters[1].key[0], g.filters[1].operator])).toEqual([
      ['entity_type', 'value', 'ends_with'],
      ['entity_type', 'account_login', 'ends_with'],
      ['entity_type', 'value', 'contains'],
    ]);
  });
  it('keywords: a keywords group as entry and a keywords criterion on it', () => {
    const d = one({ id: 'x', ruleKey: 'mentions', value: v({ terms: ['ransomware'] }) });
    expect(d.criteria[0].kind).toBe('keywords');
    expect(d.criteria[0].target_types).toEqual(['Malware']);
    expect(groupOf(d)).toMatchObject({ kind: 'keywords', role: 'entry', keywords: ['ransomware'] });
  });
  it('custom: an attribute criterion on the flagged types with the chosen filters', () => {
    const d = presetItemsToDraft(general, 'malware', ['Malware'], [{ id: 'c', kind: 'custom', name: 'Custom', filters: '{"mode":"and"}' }]);
    expect(d.criteria[0]).toMatchObject({ name: 'Custom', kind: 'attribute', target_types: ['Malware'], target_filters: '{"mode":"and"}' });
    expect(d.groups).toEqual([]);
  });
});

describe('each rule kind as a condition', () => {
  const inGroup = (rule: { id: string; ruleKey: string; value: IrPresetValue }) => presetItemsToDraft(
    general,
    'malware',
    ['Malware'],
    [{ id: 'g', kind: 'group', name: 'n', rules: [targetsRule, rule] }],
  );
  it('oneOf: an ids filter, and no subject group', () => {
    const d = inGroup({ id: 'x', ruleKey: 'one-of', value: v({ entities: [fs] }) });
    expect(JSON.parse(d.criteria[0].conditions[0].filters!).filters[0]).toMatchObject({ key: ['ids'], values: ['id-fs'], operator: 'eq', mode: 'or' });
    expect(d.groups).toHaveLength(1);
  });
  it('linked: a link and a context group', () => {
    const d = inGroup(usesRule);
    const { link } = d.criteria[0].conditions[0];
    expect(link?.group_ids).toHaveLength(1);
    expect(d.groups.find((g) => g.id === link!.group_ids[0])).toMatchObject({ kind: 'list', role: 'context' });
  });
  it('entityFilter: the same filters as the criterion', () => {
    const d = inGroup(typeRule);
    expect(JSON.parse(d.criteria[0].conditions[0].filters!).filters[0]).toMatchObject({ key: ['malware_types'], operator: 'eq' });
    expect(d.criteria[0].conditions[0].link).toBeNull();
  });
  it('keywords: refuses to be a condition', () => {
    expect(() => inGroup({ id: 'x', ruleKey: 'mentions', value: v({ terms: ['a'] }) })).toThrow('keywords');
  });
});

describe('container rules in a group', () => {
  const groupDraft = (pirType: IrPirType, flags: string[], rules: { id: string; ruleKey: string; value: IrPresetValue }[]) => presetItemsToDraft(
    general,
    pirType,
    flags,
    [{ id: 'g', kind: 'group', name: 'Group name', rules }],
  );
  it('makes the container rule the criterion and the targets rule its link condition', () => {
    const d = groupDraft('malware', ['Malware'], [targetsRule, { id: 'c', ruleKey: 'in-container', value: v({ types: ['Report'] }) }]);
    const [criterion] = d.criteria;
    expect(criterion).toMatchObject({ name: 'Group name', kind: 'graph', relationship_types: ['object'], direction: 'outgoing', target_types: ['Malware'] });
    expect(JSON.parse(d.groups.find((g) => g.id === criterion.from_group_ids[0])!.filters!).filters[0]).toMatchObject({ key: ['entity_type'], values: ['Report'] });
    expect(criterion.conditions).toHaveLength(1);
    expect(criterion.conditions[0].link?.relationship_types).toEqual(['targets']);
    expect(d.groups.find((g) => g.id === criterion.conditions[0].link!.group_ids[0])).toMatchObject({ kind: 'list', role: 'context', entities: [fs] });
  });
  it('makes a data leak the criterion and the email domains its filter condition', () => {
    const flags = ['User-Account', 'Email-Addr', 'Credential'];
    const d = groupDraft('credential', flags, [
      { id: 'd', ruleKey: 'in-domains', value: v({ terms: ['acme.com'] }) },
      { id: 'l', ruleKey: 'data-leak', value: emptyValue() },
    ]);
    const [criterion] = d.criteria;
    expect(criterion).toMatchObject({ kind: 'graph', relationship_types: ['object'], direction: 'outgoing', target_types: flags });
    expect(JSON.parse(d.groups.find((g) => g.id === criterion.from_group_ids[0])!.filters!).filters.map((f: { values: string[] }) => f.values)).toEqual([['Case-Incident'], ['data-leak']]);
    expect(criterion.conditions).toHaveLength(1);
    expect(criterion.conditions[0].link).toBeNull();
    expect(JSON.parse(criterion.conditions[0].filters!).filterGroups).toHaveLength(3);
  });
});

describe('subject groups of the whole draft', () => {
  it('references every group, as entry from a criterion and as context from a link', () => {
    const draft = presetItemsToDraft(general, 'malware', ['Malware'], [
      { id: 'a', kind: 'rule', name: 'a', rule: { id: 'r', ruleKey: 'one-of', value: v({ entities: [fs] }) } },
      { id: 'b', kind: 'rule', name: 'b', rule: { id: 'r', ruleKey: 'mentions', value: v({ terms: ['x'] }) } },
      { id: 'c', kind: 'group', name: 'c', rules: [targetsRule, usesRule, { id: 'o', ruleKey: 'one-of', value: v({ entities: [fs] }) }, { id: 'ind', ruleKey: 'indicated', value: emptyValue() }] },
    ]);
    const input = draftToInput(draft);
    const entry = new Set(input.ir_scope_criteria.flatMap((c) => c.from_group_ids));
    const context = new Set(input.ir_scope_criteria.flatMap((c) => c.conditions.flatMap((k) => k.link?.group_ids ?? [])));
    input.ir_subject_groups.forEach((g) => {
      expect(entry.has(g.id) || context.has(g.id)).toBe(true);
      expect(g.role).toBe(entry.has(g.id) ? 'entry' : 'context');
    });
    expect(context.size).toBe(2);
  });
});

describe('default scoring weights', () => {
  const ruleItem = (id: string, rule: { id: string; ruleKey: string; value: IrPresetValue }): IrPresetItem => ({ id, kind: 'rule', name: id, rule });
  const weights = (count: number) => {
    const items = [typeRule, targetsRule, usesRule].slice(0, count).map((rule, i) => ruleItem(`i${i}`, rule));
    return presetItemsToDraft(general, 'malware', ['Malware'], items);
  };

  it('gives each rule an equal share of 100, as a weight on its criterion', () => {
    const d = weights(2);
    expect(d.rules.map((r) => [r.applies_to_criterion_id, r.points])).toEqual(d.criteria.map((c) => [c.id, 50]));
    expect(d.rules.every((r) => isWeightRule(r) && !r.filters && !r.link && !r.path_condition && r.enabled)).toBe(true);
  });

  it('puts the rounding remainder on the last rule', () => {
    expect(weights(3).rules.map((r) => r.points)).toEqual([33, 33, 34]);
  });

  it('has no weight without a rule', () => {
    expect(presetItemsToDraft(general, 'malware', ['Malware'], []).rules).toEqual([]);
  });
});
