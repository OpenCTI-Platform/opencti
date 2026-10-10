import { describe, expect, it, vi } from 'vitest';
import { registerModules } from '../../../src/composition-root';
import * as cacheModule from '../../../src/database/cache';
import { buildRelationData } from '../../../src/database/data-builder';
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
