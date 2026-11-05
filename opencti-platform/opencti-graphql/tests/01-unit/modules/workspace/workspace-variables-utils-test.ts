import { afterEach, describe, expect, it } from 'vitest';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import { ENABLED_FEATURE_FLAGS } from '../../../../src/config/conf';
import {
  buildVariableAuditInput,
  hasDashboardVariableWidget,
  findCurrentUserDefaultPresetId,
  preserveServerOwnedManifestKeys,
  sanitizeCustomViewManifest,
  stripServerOwnedManifestKeys,
  toGraphqlDashboardPresets,
  toGraphqlDashboardVariables,
  validateManifestVariables,
} from '../../../../src/modules/workspace/workspace-variables-utils';
import type { AuthUser } from '../../../../src/types/user';

const VAR_ID = '11111111-1111-4111-8111-111111111111';
const PRESET_ID = '55555555-5555-4555-8555-555555555555';
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

describe('toGraphqlDashboardPresets', () => {
  it('should return no preset for an investigation or an empty manifest', () => {
    expect(toGraphqlDashboardPresets({ type: 'investigation', manifest: toB64({ presets: [{ id: PRESET_ID }] }) })).toEqual([]);
    expect(toGraphqlDashboardPresets({ type: 'dashboard', manifest: undefined })).toEqual([]);
    expect(toGraphqlDashboardPresets({ type: 'dashboard', manifest: toB64({ widgets: {} }) })).toEqual([]);
  });
  it('should serialize the values as a list and complete the time range', () => {
    const manifest = { presets: [{ id: PRESET_ID, name: 'Energy', values: { [VAR_ID]: 'sector-energy' }, config: { relativeDate: 'days-7' } }] };
    expect(toGraphqlDashboardPresets({ type: 'dashboard', manifest: toB64(manifest) })).toEqual([{
      id: PRESET_ID,
      name: 'Energy',
      values: [{ variableId: VAR_ID, value: 'sector-energy' }],
      config: { startDate: null, endDate: null, relativeDate: 'days-7' },
    }]);
  });
});

describe('findCurrentUserDefaultPresetId', () => {
  const workspace = { id: 'dashboard-1', type: 'dashboard', manifest: toB64({ presets: [{ id: PRESET_ID, name: 'Energy', values: {}, config: {} }] }) };
  const user = (overrides: Record<string, unknown>) => ({ groups: [], organizations: [], ...overrides }) as unknown as AuthUser;

  it('should return the preset of the own choice of the user first', () => {
    const me = user({ default_dashboard: 'dashboard-1', default_dashboard_preset: PRESET_ID, groups: [{ default_dashboard: 'dashboard-1', default_dashboard_preset: 'other' }] });
    expect(findCurrentUserDefaultPresetId(me, workspace)).toEqual(PRESET_ID);
  });
  it('should fall back to the organizations then the groups pointing to this dashboard', () => {
    const me = user({ organizations: [{ default_dashboard: 'dashboard-2', default_dashboard_preset: PRESET_ID }], groups: [{ default_dashboard: 'dashboard-1', default_dashboard_preset: PRESET_ID }] });
    expect(findCurrentUserDefaultPresetId(me, workspace)).toEqual(PRESET_ID);
    expect(findCurrentUserDefaultPresetId(user({ groups: [{ default_dashboard: 'dashboard-1' }] }), workspace)).toBeNull();
  });
  it('should return null when the preset no longer exists, or outside a dashboard', () => {
    const me = user({ groups: [{ default_dashboard: 'dashboard-1', default_dashboard_preset: 'deleted' }] });
    expect(findCurrentUserDefaultPresetId(me, workspace)).toBeNull();
    expect(findCurrentUserDefaultPresetId(me, { ...workspace, type: 'investigation' })).toBeNull();
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
  it('should validate the presets against the validated variables, dropping the values of unknown variables', () => {
    const presets = [{ id: PRESET_ID, name: 'Energy', values: { [VAR_ID]: 'sector-energy', unknown: 'x' }, config: { relativeDate: 'days-7', startDate: '2026-01-01' } }];
    const result = fromB64(validateManifestVariables(toB64({ widgets: {}, variables: [variable()], presets })) as string);
    expect(result.presets).toEqual([{ id: PRESET_ID, name: 'Energy', values: { [VAR_ID]: 'sector-energy' }, config: { relativeDate: 'days-7', startDate: null, endDate: null } }]);
  });
  it('should keep presets without variables and refuse malformed ones', () => {
    const result = fromB64(validateManifestVariables(toB64({ widgets: {}, presets: [{ name: 'Only range', config: { relativeDate: 'months-1' } }] })) as string);
    expect(result.presets).toEqual([{ id: expect.any(String), name: 'Only range', values: {}, config: { relativeDate: 'months-1', startDate: null, endDate: null } }]);
    expect(() => validateManifestVariables(toB64({ widgets: {}, presets: { id: 'p' } }))).toThrow('Invalid dashboard presets');
    expect(() => validateManifestVariables(toB64({ widgets: {}, presets: [{ id: 'p' }] }))).toThrow('Invalid dashboard preset');
    expect(() => validateManifestVariables(toB64({ widgets: {}, presets: [{ name: 'Bad range', config: { relativeDate: 'soon' } }] }))).toThrow('Invalid dashboard preset time range');
    expect(() => validateManifestVariables(toB64({ widgets: {}, presets: [{ id: PRESET_ID, name: 'A' }, { id: PRESET_ID, name: 'B' }] }))).toThrow('Duplicated dashboard preset id');
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

describe('stripServerOwnedManifestKeys', () => {
  it('should remove variables and presets from a manifest', () => {
    const result = stripServerOwnedManifestKeys(toB64({ widgets: { a: {} }, variables: [{ id: VAR_ID }], presets: [] }));
    expect(fromB64(result as string)).toEqual({ widgets: { a: {} } });
  });
  it('should leave a manifest without them, an empty or an unreadable one untouched', () => {
    const encoded = toB64({ widgets: { a: {} } });
    expect(stripServerOwnedManifestKeys(encoded)).toEqual(encoded);
    expect(stripServerOwnedManifestKeys('')).toEqual('');
    expect(stripServerOwnedManifestKeys(undefined)).toBeUndefined();
    expect(stripServerOwnedManifestKeys('%%%not-base64-json')).toEqual('%%%not-base64-json');
  });
});

describe('hasDashboardVariableWidget', () => {
  const tokenFilters = { mode: 'and', filters: [{ key: ['entity_type'], values: [`$var:${VAR_ID}`] }], filterGroups: [] };
  it('should find a token in the filters, dynamicFrom and dynamicTo of a widget', () => {
    expect(hasDashboardVariableWidget({ a: { dataSelection: [{ filters: tokenFilters }] } })).toBe(true);
    expect(hasDashboardVariableWidget({ a: { dataSelection: [{ filters: FILTERS }, { dynamicTo: tokenFilters }] } })).toBe(true);
    expect(hasDashboardVariableWidget({ a: { dataSelection: [{ filters: FILTERS, dynamicFrom: FILTERS }] } })).toBe(false);
  });
  it('should ignore a token outside the filters, and malformed widgets', () => {
    expect(hasDashboardVariableWidget({ a: { parameters: { content: `$var:${VAR_ID}` }, dataSelection: [{ label: `$var:${VAR_ID}` }] } })).toBe(false);
    expect(hasDashboardVariableWidget({ a: null, b: { dataSelection: 'x' }, c: { dataSelection: [null, 1] } })).toBe(false);
    expect(hasDashboardVariableWidget(undefined)).toBe(false);
    expect(hasDashboardVariableWidget([{ dataSelection: [{ filters: tokenFilters }] }])).toBe(false);
  });
});

describe('sanitizeCustomViewManifest', () => {
  const previousFlags = [...ENABLED_FEATURE_FLAGS];
  const setFlags = (flags: string[]) => ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...flags);
  afterEach(() => setFlags(previousFlags));
  const tokenWidget = { dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['entity_type'], values: [`$var:${VAR_ID}`] }], filterGroups: [] } }] };

  it('should refuse a widget using a dashboard variable with the feature', () => {
    setFlags(['DASHBOARD_VARIABLES']);
    expect(() => sanitizeCustomViewManifest(toB64({ widgets: { a: tokenWidget } }))).toThrow('A widget using dashboard variables cannot be used in a custom view');
  });
  it('should strip the server-owned keys of an accepted manifest', () => {
    setFlags(['DASHBOARD_VARIABLES']);
    const result = sanitizeCustomViewManifest(toB64({ widgets: { a: { dataSelection: [{ filters: FILTERS }] } }, variables: [{ id: VAR_ID }], presets: [] }));
    expect(fromB64(result as string)).toEqual({ widgets: { a: { dataSelection: [{ filters: FILTERS }] } } });
    expect(sanitizeCustomViewManifest(undefined)).toBeUndefined();
    expect(sanitizeCustomViewManifest('%%%not-base64-json')).toEqual('%%%not-base64-json');
  });
  it('should accept a widget using a dashboard variable without the feature, as before', () => {
    setFlags([]);
    const encoded = toB64({ widgets: { a: tokenWidget } });
    expect(sanitizeCustomViewManifest(encoded)).toEqual(encoded);
  });
});
