import { describe, expect, it, vi } from 'vitest';
import '../../../src/modules/index';
import { registerModules } from '../../../src/composition-root';
import * as cacheModule from '../../../src/database/cache';
import { buildEntityData, buildRelationData } from '../../../src/database/data-builder';
import { ADMIN_USER } from '../../utils/testQuery';

registerModules();

const customFieldValues = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_note', string_value: 'note' }];
const from = { internal_id: 'from-id', standard_id: 'malware--8b3e1c3a-2a6f-4a8e-9c3a-1b2c3d4e5f60', entity_type: 'Malware' };
const to = { internal_id: 'to-id', standard_id: 'location--8b3e1c3a-2a6f-4a8e-9c3a-1b2c3d4e5f61', entity_type: 'Administrative-Area' };

describe('buildRelationData custom fields', () => {
  it.each(['targets', 'stix-sighting-relationship'])('should keep the custom field values of a %s', async (relationshipType) => {
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue([]);
    vi.spyOn(cacheModule, 'getEntitiesMapFromCache').mockResolvedValue(new Map());
    vi.spyOn(cacheModule, 'getEntityFromCache').mockResolvedValue({} as any);
    const context = { user_inside_platform_organization: true } as any;
    const input = { from, to, fromId: from.internal_id, toId: to.internal_id, relationship_type: relationshipType, custom_field_values: customFieldValues };
    const { element } = await buildRelationData(context, ADMIN_USER, input);
    expect(element.custom_field_values).toEqual(customFieldValues);
  });
});

describe('buildEntityData default workflow status', () => {
  const entityType = 'Report';
  const statuses = [
    { id: 'status-ra-new', type: entityType, scope: 'REQUEST_ACCESS' },
    { id: 'status-global-new', type: entityType, scope: 'GLOBAL' },
  ];
  const build = async (input: Record<string, unknown>) => {
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(statuses as any);
    const context = { user_inside_platform_organization: true } as any;
    const { element } = await buildEntityData(context, ADMIN_USER, { name: 'report', entity_type: entityType, ...input }, entityType);
    return element as unknown as Record<string, unknown>;
  };

  it('should never default to a request access status', async () => {
    expect((await build({}))['x_opencti_workflow_id']).toEqual('status-global-new');
  });

  it('should keep no default status when only request access statuses exist', async () => {
    statuses.splice(1, 1);
    expect((await build({}))['x_opencti_workflow_id']).toBeUndefined();
  });

  it('should keep a request access status supplied explicitly', async () => {
    expect((await build({ x_opencti_workflow_id: 'status-ra-new' }))['x_opencti_workflow_id']).toEqual('status-ra-new');
  });
});
