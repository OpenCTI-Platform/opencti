import { describe, expect, it } from 'vitest';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import { buildVariableAuditInput, preserveServerOwnedManifestKeys, toGraphqlDashboardVariables } from '../../../../src/modules/workspace/workspace-variables-utils';

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
