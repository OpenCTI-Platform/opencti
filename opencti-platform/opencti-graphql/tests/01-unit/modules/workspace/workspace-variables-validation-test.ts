import { describe, expect, it } from 'vitest';
import { buildDashboardVariable, type DashboardVariableInputLike } from '../../../../src/modules/workspace/workspace-variables-validation';
import type { StoreDashboardVariable } from '../../../../src/modules/workspace/workspace-variables-types';

const NOW = new Date('2026-10-06T10:00:00.000Z');
const SECTOR_FILTERS = JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] });

const existing = (overrides: Partial<StoreDashboardVariable> = {}): StoreDashboardVariable => ({
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  name: 'Sector',
  type: 'entity',
  entityTypes: ['Sector'],
  restriction: { mode: 'none' },
  defaultValue: 'sector-id',
  ...overrides,
} as StoreDashboardVariable);

const build = (input: Partial<DashboardVariableInputLike>, variables: StoreDashboardVariable[] = []) => {
  return buildDashboardVariable({ name: 'My variable', type: 'text', defaultValue: 'abc', ...input } as DashboardVariableInputLike, variables, NOW);
};

describe('buildDashboardVariable - creation', () => {
  it('should create a text variable with a generated id and no restriction', () => {
    const variable = build({});
    expect(variable).toEqual({ id: expect.any(String), name: 'My variable', type: 'text', restriction: { mode: 'none' }, defaultValue: 'abc' });
    expect(variable.id).toMatch(/^[0-9a-f-]{36}$/);
  });
  it('should trim the name', () => {
    expect(build({ name: '  Sector  ' }).name).toEqual('Sector');
  });
  it.each([
    ['empty name', { name: '   ' }, 'Dashboard variable name is required'],
    ['too long name', { name: 'x'.repeat(201) }, 'Dashboard variable name is too long'],
    ['missing default value', { defaultValue: null }, 'Dashboard variable default value is required'],
    ['blank default value', { defaultValue: '  ' }, 'Dashboard variable default value is required'],
    ['vocabulary without category', { type: 'vocabulary' }, 'A vocabulary variable requires a vocabulary category'],
    ['category on another type', { type: 'text', vocabularyCategory: 'report_types_ov' }, 'A vocabulary category is only allowed on vocabulary variables'],
    ['kill chain phase without kill chain name', { type: 'killChainPhase' }, 'A kill chain phase variable requires a kill chain name'],
    ['kill chain name on another type', { killChainName: 'mitre-attack' }, 'A kill chain name is only allowed on kill chain phase variables'],
    ['entity without entity types', { type: 'entity', entityTypes: [] }, 'An entity variable requires at least one entity type'],
    ['entity with unknown entity type', { type: 'entity', entityTypes: ['Not-A-Type'] }, 'Unknown entity types'],
    ['entity types on another type', { entityTypes: ['Sector'] }, 'Entity types are only allowed on entity variables'],
    ['filters restriction on non entity', { restriction: { mode: 'filters', filters: SECTOR_FILTERS } }, 'A filters restriction is only allowed on entity variables'],
    ['empty selection', { restriction: { mode: 'selection', values: [] } }, 'A selection restriction requires at least one value'],
    ['default outside selection', { restriction: { mode: 'selection', values: ['a', 'b'] }, defaultValue: 'c' }, 'The default value must belong to the selection'],
    ['too many selection values', { restriction: { mode: 'selection', values: Array.from({ length: 201 }, (_, i) => `v${i}`) }, defaultValue: 'v0' }, 'A selection restriction cannot hold more than 200 values'],
    ['values on a none restriction', { restriction: { mode: 'none', values: ['a'] } }, 'This restriction mode does not accept values or filters'],
    ['invalid boolean', { type: 'boolean', defaultValue: 'yes' }, 'A boolean variable default value must be true or false'],
    ['invalid numeric', { type: 'numeric', defaultValue: 'ten' }, 'A numeric variable default value must be a number'],
    ['invalid date', { type: 'date', defaultValue: 'not a date' }, 'A date variable default value must be a valid date'],
    ['token as default value', { defaultValue: '$var:11111111-1111-4111-8111-111111111111' }, 'A variable value cannot reference another variable'],
    ['token in selection', { restriction: { mode: 'selection', values: ['a', '$var:11111111-1111-4111-8111-111111111111'] }, defaultValue: 'a' }, 'A variable value cannot reference another variable'],
  ])('should reject %s', (_, input, message) => {
    expect(() => build(input as Partial<DashboardVariableInputLike>)).toThrow(message);
  });
  it('should reject invalid restriction filters', () => {
    expect(() => build({ type: 'entity', entityTypes: ['Sector'], defaultValue: 'id', restriction: { mode: 'filters', filters: '{not json' } })).toThrow('Invalid restriction filters');
    expect(() => build({ type: 'entity', entityTypes: ['Sector'], defaultValue: 'id', restriction: { mode: 'filters', filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['$var:11111111-1111-4111-8111-111111111111'] }], filterGroups: [] }) } }))
      .toThrow('A variable restriction cannot reference another variable');
  });
  it('should store an entity variable with a filters restriction as an object', () => {
    const variable = build({ type: 'entity', entityTypes: ['Sector', 'Sector'], defaultValue: 'sector-id', restriction: { mode: 'filters', filters: SECTOR_FILTERS } });
    expect(variable).toMatchObject({ type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'filters', filters: JSON.parse(SECTOR_FILTERS) } });
  });
  it('should default a boolean to false and a date to now', () => {
    expect(build({ type: 'boolean', defaultValue: null }).defaultValue).toEqual('false');
    expect(build({ type: 'date', defaultValue: null }).defaultValue).toEqual(NOW.toISOString());
  });
  it('should accept a selection containing the default value', () => {
    expect(build({ restriction: { mode: 'selection', values: ['a', 'b', 'a'] }, defaultValue: 'b' }).restriction).toEqual({ mode: 'selection', values: ['a', 'b'] });
  });
  it('should reject a duplicated name, case and space insensitive', () => {
    expect(() => build({ name: ' sector ' }, [existing()])).toThrow('A dashboard variable with this name already exists');
  });
  it('should reject the 51st variable', () => {
    const variables = Array.from({ length: 50 }, (_, i) => existing({ id: `id-${i}`, name: `v${i}` }));
    expect(() => build({ name: 'one too many' }, variables)).toThrow('A dashboard cannot hold more than 50 variables');
  });
});

describe('buildDashboardVariable - update', () => {
  it('should keep the id and allow keeping the same name', () => {
    const current = existing();
    const variable = build({ id: current.id, name: 'Sector', type: 'entity', entityTypes: ['Sector'], defaultValue: 'other-id' }, [current]);
    expect(variable.id).toEqual(current.id);
    expect(variable.defaultValue).toEqual('other-id');
  });
  it('should recreate a deleted variable with its id so orphan tokens resolve again', () => {
    const variable = build({ id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, [existing()]);
    expect(variable.id).toEqual('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
  });
  it('should reject an unknown id that is not a uuid', () => {
    expect(() => build({ id: 'not-a-uuid' }, [existing()])).toThrow('Invalid dashboard variable id');
  });
  it('should reject an empty id instead of storing it', () => {
    expect(() => build({ id: '' }, [existing()])).toThrow('Invalid dashboard variable id');
  });
  it('should apply the quota when recreating with a given id', () => {
    const variables = Array.from({ length: 50 }, (_, i) => existing({ id: `id-${i}`, name: `v${i}` }));
    expect(() => build({ id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', name: 'recreated' }, variables)).toThrow('A dashboard cannot hold more than 50 variables');
  });
  it('should reject a type change', () => {
    const current = existing();
    expect(() => build({ id: current.id, name: 'Sector', type: 'text' }, [current])).toThrow('The type of a dashboard variable cannot be changed');
  });
  it('should not count the variable itself against the quota', () => {
    const variables = Array.from({ length: 50 }, (_, i) => existing({ id: `id-${i}`, name: `v${i}`, type: 'text', defaultValue: 'x' } as Partial<StoreDashboardVariable>));
    expect(() => build({ id: 'id-0', name: 'v0', type: 'text', defaultValue: 'y' }, variables)).not.toThrow();
  });
});
