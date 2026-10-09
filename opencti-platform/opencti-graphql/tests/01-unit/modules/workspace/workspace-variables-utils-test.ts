import { describe, expect, it } from 'vitest';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import {
  buildVariableAuditInput,
  preserveServerOwnedManifestKeys,
  toGraphqlDashboardVariables,
  validateManifestVariables,
} from '../../../../src/modules/workspace/workspace-variables-utils';

const VAR_ID = '11111111-1111-4111-8111-111111111111';
const FILTERS = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'] }], filterGroups: [] };

describe('toGraphqlDashboardVariables', () => {
  it('should return no variable for an investigation or an empty manifest', () => {
    expect(toGraphqlDashboardVariables({ type: 'investigation', manifest: toB64({ variables: [{ id: VAR_ID }] }) })).toEqual([]);
    expect(toGraphqlDashboardVariables({ type: 'dashboard', manifest: undefined })).toEqual([]);
    expect(toGraphqlDashboardVariables({ type: 'dashboard', manifest: toB64({ widgets: {} }) })).toEqual([]);
  });
  it('should serialize restrictions and compute usage', () => {
    const manifest = {
      widgets: { 'widget-1': { dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['createdBy'], values: [`$var:${VAR_ID}`] }], filterGroups: [] } }] } },
      variables: [{ id: VAR_ID, name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'filters', filters: FILTERS }, defaultValue: 'sector-id' }],
    };
    expect(toGraphqlDashboardVariables({ type: 'dashboard', manifest: toB64(manifest) })).toEqual([{
      id: VAR_ID,
      name: 'Sector',
      type: 'entity',
      vocabularyCategory: null,
      killChainName: null,
      entityTypes: ['Sector'],
      restriction: { mode: 'filters', values: null, filters: JSON.stringify(FILTERS) },
      defaultValue: 'sector-id',
      usedInWidgetIds: ['widget-1'],
    }]);
  });
});

describe('buildVariableAuditInput', () => {
  it('should only expose a bounded semantic payload', () => {
    expect(buildVariableAuditInput('upsert', { id: VAR_ID, name: 'Sector', type: 'entity' }))
      .toEqual([{ key: 'variables', value: [{ operation: 'upsert', id: VAR_ID, name: 'Sector', type: 'entity' }] }]);
  });
});

describe('preserveServerOwnedManifestKeys', () => {
  const stored = toB64({ widgets: {}, variables: [{ id: VAR_ID, name: 'Stored' }] });
  const manifestInput = (manifest: unknown) => [{ key: 'manifest', value: [toB64(manifest)] }];

  it('should leave inputs untouched when no server owned key is involved', () => {
    const inputs = [{ key: 'manifest', value: ['opaque-unchanged-b64'] }, { key: 'name', value: ['x'] }];
    expect(preserveServerOwnedManifestKeys(inputs, toB64({ widgets: {} }))).toEqual(inputs);
    const legacy = manifestInput({ widgets: { a: {} }, config: {} });
    expect(preserveServerOwnedManifestKeys(legacy, toB64({ widgets: {} }))).toEqual(legacy);
  });
  it('should reinject stored variables over a stale manifest', () => {
    const [result] = preserveServerOwnedManifestKeys(manifestInput({ widgets: { a: {} } }), stored);
    expect(fromB64(result.value[0])).toEqual({ widgets: { a: {} }, variables: [{ id: VAR_ID, name: 'Stored' }] });
  });
  it('should ignore variables and presets sent by a client', () => {
    const [result] = preserveServerOwnedManifestKeys(manifestInput({ widgets: {}, variables: [{ id: 'injected' }], presets: [{ id: 'p' }] }), toB64({ widgets: {} }));
    expect(fromB64(result.value[0])).toEqual({ widgets: {} });
  });
  it.each([
    ['an empty string', ['']],
    ['a null value', [null]],
    ['no value', []],
  ])('should refuse %s that would erase stored variables', (_, value) => {
    expect(() => preserveServerOwnedManifestKeys([{ key: 'manifest', value }], stored)).toThrow('Invalid dashboard manifest');
    const passthrough = [{ key: 'manifest', value }];
    expect(preserveServerOwnedManifestKeys(passthrough, toB64({ widgets: {} }))).toEqual(passthrough);
  });
  it('should refuse an unreadable manifest that would erase stored variables', () => {
    expect(() => preserveServerOwnedManifestKeys([{ key: 'manifest', value: ['%%%not-base64-json'] }], stored)).toThrow('Invalid dashboard manifest');
    const passthrough = [{ key: 'manifest', value: ['%%%not-base64-json'] }];
    expect(preserveServerOwnedManifestKeys(passthrough, toB64({ widgets: {} }))).toEqual(passthrough);
  });
});

describe('validateManifestVariables', () => {
  const variable = (overrides: Record<string, unknown> = {}) => ({
    id: VAR_ID, name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'filters', filters: FILTERS }, defaultValue: 'sector-id', ...overrides,
  });

  it('should leave a manifest without variables untouched', () => {
    const encoded = toB64({ widgets: { a: {} }, config: {} });
    expect(validateManifestVariables(encoded)).toEqual(encoded);
    expect(validateManifestVariables(undefined)).toBeUndefined();
  });
  it('should keep valid variables with their ids', () => {
    const result = fromB64(validateManifestVariables(toB64({ widgets: {}, variables: [variable()] })) as string);
    expect(result.variables).toEqual([variable()]);
  });
  it('should drop presets until they can be validated', () => {
    const result = fromB64(validateManifestVariables(toB64({ widgets: {}, variables: [], presets: [{ id: 'p' }] })) as string);
    expect(result.presets).toBeUndefined();
  });
  it.each([
    ['not an array', { variables: { id: VAR_ID } }, 'Invalid dashboard variables'],
    ['a non object variable', { variables: ['x'] }, 'Invalid dashboard variable'],
    ['an unknown type', { variables: [variable({ type: 'unknown' })] }, 'Invalid dashboard variable type'],
    ['an unknown vocabulary category', { variables: [variable({ type: 'vocabulary', entityTypes: undefined, vocabularyCategory: 'nope', restriction: { mode: 'none' } })] }, 'Invalid dashboard variable vocabulary category'],
    ['an empty object vocabulary category', { variables: [variable({ type: 'vocabulary', entityTypes: undefined, vocabularyCategory: {}, restriction: { mode: 'none' } })] }, 'Invalid dashboard variable vocabulary category'],
    ['an empty array vocabulary category', { variables: [variable({ type: 'vocabulary', entityTypes: undefined, vocabularyCategory: [], restriction: { mode: 'none' } })] }, 'Invalid dashboard variable vocabulary category'],
    ['an empty id', { variables: [variable({ id: '' })] }, 'Invalid dashboard variable id'],
    ['an unknown restriction mode', { variables: [variable({ restriction: { mode: 'other' } })] }, 'Invalid dashboard variable restriction'],
    ['a token default value', { variables: [variable({ defaultValue: `$var:${VAR_ID}` })] }, 'A variable value cannot reference another variable'],
    ['duplicated names', { variables: [variable(), variable({ id: '22222222-2222-4222-8222-222222222222' })] }, 'A dashboard variable with this name already exists'],
    ['too many variables', { variables: Array.from({ length: 51 }, (_, i) => variable({ id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, name: `v${i}` })) }, 'A dashboard cannot hold more than 50 variables'],
  ])('should reject %s', (_, manifest, message) => {
    expect(() => validateManifestVariables(toB64({ widgets: {}, ...manifest }))).toThrow(message);
  });
});
