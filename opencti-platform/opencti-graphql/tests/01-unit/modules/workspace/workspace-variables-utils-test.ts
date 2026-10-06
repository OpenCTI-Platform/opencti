import { describe, expect, it } from 'vitest';
import { toB64 } from '../../../../src/utils/base64';
import { buildVariableAuditInput, toGraphqlDashboardVariables } from '../../../../src/modules/workspace/workspace-variables-utils';

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
