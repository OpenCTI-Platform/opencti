import { describe, expect, it } from 'vitest';
import { DASHBOARD_VARIABLES_LIMITS, draftToVariable, emptyDraft, validateDraft, variableToDraft, type DashboardVariableDraft } from './dashboardVariableDraft';
import { DASHBOARD_VARIABLE_TYPES, type DashboardVariable, type DashboardVariableType } from '../dashboard-types';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';

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

  it('builds a filters restriction with an empty rule when none was edited yet', () => {
    const draft = validDraft({ type: 'entity', entityTypes: ['Sector'], restrictionMode: 'filters', filters: undefined });
    expect(draftToVariable(draft, 'i').restriction).toEqual({ mode: 'filters', filters: emptyFilterGroup });
  });

  it('sends only the restriction of the current mode', () => {
    const draft = validDraft({ type: 'label', restrictionMode: 'none', selectionValues: ['a'], filters: emptyFilterGroup });
    expect(draftToVariable(draft, 'i').restriction).toEqual({ mode: 'none' });
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

  it.each(['boolean', 'date'] as const)('requires an explicit default value for a %s variable', (type) => {
    expect(validateDraft(validDraft({ type, defaultValue: '' }), [], t_i18n).defaultValue).toBe('Default value is required');
    expect(validateDraft(validDraft({ type, defaultValue: '  ' }), [], t_i18n).defaultValue).toBe('Default value is required');
  });

  it('starts a new draft without default value', () => {
    expect(emptyDraft.defaultValue).toBe('');
    expect(validateDraft({ ...emptyDraft, name: 'Flag', type: 'boolean' }, [], t_i18n).defaultValue).toBe('Default value is required');
  });

  it('requires a finite default value for numeric variables', () => {
    expect(validateDraft(validDraft({ type: 'numeric', defaultValue: 'abc' }), [], t_i18n).defaultValue)
      .toBe('Default value must be a number');
    expect(validateDraft(validDraft({ type: 'numeric', defaultValue: 'Infinity' }), [], t_i18n).defaultValue)
      .toBe('Default value must be a number');
    expect(validateDraft(validDraft({ type: 'numeric', defaultValue: '-12.5' }), [], t_i18n)).toEqual({});
  });

  it('refuses a boolean default value that is neither true nor false', () => {
    expect(validateDraft(validDraft({ type: 'boolean', defaultValue: 'maybe' }), [], t_i18n).defaultValue)
      .toBe('Default value is not valid');
  });

  it.each(['true', 'false', '  true '])('accepts the boolean default value "%s"', (defaultValue) => {
    expect(validateDraft(validDraft({ type: 'boolean', defaultValue }), [], t_i18n)).toEqual({});
  });

  it('refuses a date default value that cannot be parsed', () => {
    expect(validateDraft(validDraft({ type: 'date', defaultValue: 'not a date' }), [], t_i18n).defaultValue)
      .toBe('Default value is not valid');
  });

  it.each(['2026-10-13T10:00:00.000Z'])('accepts the date default value "%s"', (defaultValue) => {
    expect(validateDraft(validDraft({ type: 'date', defaultValue }), [], t_i18n)).toEqual({});
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

  describe('selection restriction', () => {
    const selectionDraft = (overrides: Partial<DashboardVariableDraft> = {}) => validDraft({
      type: 'entity',
      entityTypes: ['Sector'],
      restrictionMode: 'selection',
      selectionValues: ['id-1', 'id-2'],
      defaultValue: 'id-1',
      ...overrides,
    });

    it('accepts a valid selection', () => {
      expect(validateDraft(selectionDraft(), [], t_i18n)).toEqual({});
    });

    it('refuses an empty selection', () => {
      expect(validateDraft(selectionDraft({ selectionValues: [] }), [], t_i18n).selectionValues).toBe('Select at least one value');
    });

    it('refuses a selection beyond 200 values', () => {
      const values = Array.from({ length: DASHBOARD_VARIABLES_LIMITS.selectionValues + 1 }, (_, i) => `id-${i + 1}`);
      expect(validateDraft(selectionDraft({ selectionValues: values }), [], t_i18n).selectionValues)
        .toBe('A selection cannot hold more than 200 values');
      expect(validateDraft(selectionDraft({ selectionValues: values.slice(1), defaultValue: 'id-2' }), [], t_i18n)).toEqual({});
    });

    it('refuses a default value outside of the selection', () => {
      expect(validateDraft(selectionDraft({ selectionValues: ['id-2'] }), [], t_i18n).defaultValue)
        .toBe('The default value must belong to the selection');
    });

    it('refuses a selection value referencing another variable', () => {
      expect(validateDraft(selectionDraft({ selectionValues: ['id-1', '$var:x'] }), [], t_i18n).selectionValues)
        .toBe('A value cannot reference another variable');
    });
  });

  describe('filters restriction', () => {
    const rule: FilterGroup = {
      mode: 'and',
      filters: [{ key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    const filtersDraft = (overrides: Partial<DashboardVariableDraft> = {}) => validDraft({
      type: 'entity',
      entityTypes: ['Sector'],
      restrictionMode: 'filters',
      filters: rule,
      defaultValue: 'id-1',
      ...overrides,
    });

    it('accepts a valid filters rule', () => {
      expect(validateDraft(filtersDraft(), [], t_i18n)).toEqual({});
    });

    it('refuses a filters restriction on a type other than entity', () => {
      expect(validateDraft(filtersDraft({ type: 'label' }), [], t_i18n).filters)
        .toBe('Only an entity variable can be restricted by filter');
    });

    it('refuses an empty filters rule', () => {
      expect(validateDraft(filtersDraft({ filters: emptyFilterGroup }), [], t_i18n).filters).toBe('At least one filter is required');
      const valueless: FilterGroup = { ...rule, filters: [{ key: 'objectLabel', values: [], operator: 'eq', mode: 'or' }] };
      expect(validateDraft(filtersDraft({ filters: valueless }), [], t_i18n).filters).toBe('At least one filter is required');
    });

    it('refuses a filters rule referencing another variable, at any depth', () => {
      const tokenFilter = { key: 'objectLabel', values: ['$var:x'], operator: 'eq', mode: 'or' } as const;
      expect(validateDraft(filtersDraft({ filters: { ...rule, filters: [tokenFilter] } }), [], t_i18n).filters)
        .toBe('A filter cannot reference another variable');
      const nested: FilterGroup = { ...rule, filterGroups: [{ mode: 'or', filters: [tokenFilter], filterGroups: [] }] };
      expect(validateDraft(filtersDraft({ filters: nested }), [], t_i18n).filters)
        .toBe('A filter cannot reference another variable');
    });
  });

  it('ignores the selection and the filters of another mode', () => {
    const draft = validDraft({ type: 'label', restrictionMode: 'none', selectionValues: [], filters: emptyFilterGroup, defaultValue: 'id-1' });
    expect(validateDraft(draft, [], t_i18n)).toEqual({});
  });
});

describe('draftToVariable - default value trimming', () => {
  it.each(['boolean', 'numeric', 'date'] as const)('stores the default of a %s variable trimmed', (type) => {
    expect(draftToVariable(validDraft({ type, defaultValue: '  42 ' }), 'i').defaultValue).toBe('42');
  });

  it.each(['boolean', 'numeric', 'date'] as const)('stores a blank default of a %s variable as null', (type) => {
    expect(draftToVariable(validDraft({ type, defaultValue: '   ' }), 'i').defaultValue).toBeNull();
  });

  it.each(['text', 'label', 'entity'] as const)('stores the default of a %s variable as typed', (type) => {
    expect(draftToVariable(validDraft({ type, entityTypes: ['Malware'], defaultValue: ' Energy ' }), 'i').defaultValue).toBe(' Energy ');
  });

  it('restores a valid typed variable unchanged', () => {
    const variable = makeVariable('numeric', { defaultValue: '42' });
    expect(draftToVariable(variableToDraft(variable), variable.id)).toEqual(variable);
  });
});

describe('dashboardVariableDraft - strict ISO-8601 date default', () => {
  // Parsed by some engines only (V8, not Safari), local time in some engines and UTC in others, or not a calendar day.
  it.each(['2024/01/01', 'March 7 2024', '2024-01-01 10:00', '2024-01-01T10:00:00', '2024-13-01', '2024-02-30'])(
    'refuses the date default value "%s"',
    (defaultValue) => {
      expect(validateDraft(validDraft({ type: 'date', defaultValue }), [], t_i18n).defaultValue).toBe('Default value is not valid');
    },
  );

  it('refuses a date default whose normalization leaves the strict ISO range', () => {
    const draft = validDraft({ type: 'date', defaultValue: '9999-12-31T20:00:00-05:00' });
    expect(validateDraft(draft, [], t_i18n).defaultValue).toBe('Default value is not valid');
  });

  it.each([
    ['2024-01-01', '2024-01-01T00:00:00.000Z'],
    ['2024-01-01T10:00:00Z', '2024-01-01T10:00:00.000Z'],
    ['2024-01-01T10:00:00.5+02:00', '2024-01-01T08:00:00.500Z'],
    [' 2024-01-01T10:00:00Z ', '2024-01-01T10:00:00.000Z'],
  ])('accepts the date default value "%s" and stores it normalized as "%s"', (defaultValue, expected) => {
    expect(validateDraft(validDraft({ type: 'date', defaultValue }), [], t_i18n)).toEqual({});
    expect(draftToVariable(validDraft({ type: 'date', defaultValue }), 'i').defaultValue).toBe(expected);
  });

  it('keeps a date default restricted to a selection as the pool value it matches', () => {
    const draft = validDraft({ type: 'date', restrictionMode: 'selection', selectionValues: ['2024-01-01'], defaultValue: '2024-01-01' });
    expect(draftToVariable(draft, 'i').defaultValue).toBe('2024-01-01');
  });
});
