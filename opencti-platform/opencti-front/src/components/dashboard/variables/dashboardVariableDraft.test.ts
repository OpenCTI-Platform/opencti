import { describe, expect, it } from 'vitest';
import { DASHBOARD_VARIABLES_LIMITS, draftToVariable, emptyDraft, validateDraft, variableToDraft, type DashboardVariableDraft } from './dashboardVariableDraft';
import { DASHBOARD_VARIABLE_TYPES, type DashboardVariable, type DashboardVariableType } from '../dashboard-types';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';

const t_i18n = (s: string) => s;

const makeVariable = (type: DashboardVariableType, overrides: Record<string, unknown> = {}): DashboardVariable => {
  const base = { id: `id-${type}`, name: `Var ${type}`, restriction: { mode: 'none' }, defaultValue: 'x' };
  if (type === 'vocabulary') return { ...base, type, vocabularyCategory: 'report_types_ov', ...overrides } as DashboardVariable;
  if (type === 'killChainPhase') return { ...base, type, killChainName: 'mitre-attack', ...overrides } as DashboardVariable;
  if (type === 'entity') return { ...base, type, entityTypes: ['Malware', 'Tool'], ...overrides } as DashboardVariable;
  return { ...base, type, ...overrides } as DashboardVariable;
};

const validDraft = (overrides: Partial<DashboardVariableDraft> = {}): DashboardVariableDraft => ({
  ...emptyDraft,
  name: 'Sector',
  type: 'text',
  defaultValue: 'abc',
  ...overrides,
});

describe('dashboardVariableDraft round trip', () => {
  it.each(DASHBOARD_VARIABLE_TYPES)('restores a %s variable unchanged', (type) => {
    const variable = makeVariable(type);
    expect(draftToVariable(variableToDraft(variable), variable.id)).toEqual(variable);
  });

  it('restores a selection restriction unchanged', () => {
    const variable = makeVariable('label', { restriction: { mode: 'selection', values: ['a', 'b'] } });
    expect(draftToVariable(variableToDraft(variable), variable.id)).toEqual(variable);
  });

  it('restores a filters restriction unchanged', () => {
    const filters: FilterGroup = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    const variable = makeVariable('entity', { restriction: { mode: 'filters', filters } });
    expect(draftToVariable(variableToDraft(variable), variable.id)).toEqual(variable);
  });

  it('keeps a null default value as null', () => {
    const variable = makeVariable('boolean', { defaultValue: null });
    expect(draftToVariable(variableToDraft(variable), variable.id)).toEqual(variable);
  });

  it('builds a restriction-free variable from a new draft, with the given id and a trimmed name', () => {
    expect(draftToVariable(validDraft({ name: '  Sector  ' }), 'new-id')).toEqual({
      id: 'new-id',
      name: 'Sector',
      type: 'text',
      restriction: { mode: 'none' },
      defaultValue: 'abc',
    });
  });

  it('drops the fields that do not belong to the selected type', () => {
    const variable = draftToVariable(validDraft({ type: 'text', vocabularyCategory: 'x', killChainName: 'y', entityTypes: ['Malware'] }), 'i');
    expect(variable).not.toHaveProperty('vocabularyCategory');
    expect(variable).not.toHaveProperty('killChainName');
    expect(variable).not.toHaveProperty('entityTypes');
  });
});

describe('validateDraft', () => {
  it('accepts a valid draft', () => {
    expect(validateDraft(validDraft(), [], t_i18n)).toEqual({});
  });

  it('requires a name', () => {
    expect(validateDraft(validDraft({ name: '   ' }), [], t_i18n).name).toBe('Name is required');
  });

  it('refuses a name longer than the limit', () => {
    const name = 'a'.repeat(DASHBOARD_VARIABLES_LIMITS.nameLength + 1);
    expect(validateDraft(validDraft({ name }), [], t_i18n).name).toBe('Name is too long');
    expect(validateDraft(validDraft({ name: name.slice(1) }), [], t_i18n).name).toBeUndefined();
  });

  it('refuses a duplicated name regardless of case and surrounding spaces', () => {
    const existing = [makeVariable('text', { name: 'Sector' })];
    expect(validateDraft(validDraft({ name: ' sector ' }), existing, t_i18n).name)
      .toBe('A variable with this name already exists');
  });

  it('accepts the same name when editing the same variable', () => {
    const existing = [makeVariable('text', { id: 'v1', name: 'Sector' })];
    expect(validateDraft(validDraft({ id: 'v1', name: 'Sector' }), existing, t_i18n)).toEqual({});
  });

  it('requires a type', () => {
    expect(validateDraft(validDraft({ type: '' }), [], t_i18n).type).toBe('Type is required');
  });

  it('requires a vocabulary category only for vocabulary variables', () => {
    const vocabulary = validDraft({ type: 'vocabulary', vocabularyCategory: '' });
    expect(validateDraft(vocabulary, [], t_i18n).vocabularyCategory).toBe('Vocabulary category is required');
    expect(validateDraft({ ...vocabulary, vocabularyCategory: 'report_types_ov' }, [], t_i18n)).toEqual({});
    expect(validateDraft(validDraft({ vocabularyCategory: '' }), [], t_i18n).vocabularyCategory).toBeUndefined();
  });

  it('requires a kill chain name only for kill chain phase variables', () => {
    const phase = validDraft({ type: 'killChainPhase', killChainName: ' ' });
    expect(validateDraft(phase, [], t_i18n).killChainName).toBe('Kill chain is required');
    expect(validateDraft({ ...phase, killChainName: 'mitre-attack' }, [], t_i18n)).toEqual({});
    expect(validateDraft(validDraft({ killChainName: '' }), [], t_i18n).killChainName).toBeUndefined();
  });

  it('requires at least one entity type only for entity variables', () => {
    const entity = validDraft({ type: 'entity', entityTypes: [] });
    expect(validateDraft(entity, [], t_i18n).entityTypes).toBe('At least one entity type is required');
    expect(validateDraft({ ...entity, entityTypes: ['Malware'] }, [], t_i18n)).toEqual({});
    expect(validateDraft(validDraft({ entityTypes: [] }), [], t_i18n).entityTypes).toBeUndefined();
  });

  it('requires a default value', () => {
    expect(validateDraft(validDraft({ defaultValue: '  ' }), [], t_i18n).defaultValue).toBe('Default value is required');
  });

  it.each(['boolean', 'date'] as const)('accepts a %s variable without default value', (type) => {
    expect(validateDraft(validDraft({ type, defaultValue: '' }), [], t_i18n)).toEqual({});
  });

  it('requires a finite default value for numeric variables', () => {
    expect(validateDraft(validDraft({ type: 'numeric', defaultValue: 'abc' }), [], t_i18n).defaultValue)
      .toBe('Default value must be a number');
    expect(validateDraft(validDraft({ type: 'numeric', defaultValue: 'Infinity' }), [], t_i18n).defaultValue)
      .toBe('Default value must be a number');
    expect(validateDraft(validDraft({ type: 'numeric', defaultValue: '-12.5' }), [], t_i18n)).toEqual({});
  });

  it('refuses a default value referencing another variable', () => {
    expect(validateDraft(validDraft({ defaultValue: '$var:abc' }), [], t_i18n).defaultValue)
      .toBe('A value cannot reference another variable');
    expect(validateDraft(validDraft({ type: 'boolean', defaultValue: 'x $var:abc' }), [], t_i18n).defaultValue)
      .toBe('A value cannot reference another variable');
  });

  it('refuses the variable beyond the quota when creating', () => {
    const existing = Array.from({ length: DASHBOARD_VARIABLES_LIMITS.variables }, (_, i) => makeVariable('text', { id: `v${i}`, name: `Name ${i}` }));
    expect(validateDraft(validDraft(), existing, t_i18n).form).toBe('A dashboard cannot hold more than 50 variables');
    expect(validateDraft(validDraft(), existing.slice(1), t_i18n)).toEqual({});
  });

  it('does not apply the quota when editing an existing variable', () => {
    const existing = Array.from({ length: DASHBOARD_VARIABLES_LIMITS.variables }, (_, i) => makeVariable('text', { id: `v${i}`, name: `Name ${i}` }));
    expect(validateDraft(validDraft({ id: 'v3', name: 'Name 3' }), existing, t_i18n)).toEqual({});
  });
});
