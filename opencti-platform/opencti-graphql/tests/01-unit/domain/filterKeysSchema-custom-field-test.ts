import { describe, expect, it, vi } from 'vitest';
import '../../../src/modules/index';
import * as cacheModule from '../../../src/database/cache';
import * as customFieldCache from '../../../src/modules/customField/custom-field-cache';
import { generateFilterKeysSchema } from '../../../src/domain/filterKeysSchema';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../src/schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';

describe('Filter keys schema for custom fields', () => {
  it('should keep all the entity types of a custom field attached to several types, as a standard attribute', async () => {
    vi.spyOn(cacheModule, 'getEntityFromCache').mockResolvedValue({} as any);
    // No entity setting customizes the headline dates of a timeline type.
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue([]);
    const definition = { name: 'x_opencti_cf_note', label: 'Note', field_type: 'string', entity_types: [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER_CASE_INCIDENT] };
    vi.spyOn(customFieldCache, 'getCustomFieldDefinitionsForEntityType')
      .mockImplementation(async (_, __, entityType) => (definition.entity_types.includes(entityType) ? [definition] : []) as any);
    const filterKeysSchema = await generateFilterKeysSchema();
    const getDefinition = (entityType: string) => filterKeysSchema
      .find((n) => n.entity_type === entityType)?.filters_schema
      .find((f) => f.filterKey === 'x_opencti_cf_note')?.filterDefinition;
    expect(getDefinition(ENTITY_TYPE_CONTAINER_REPORT)?.subEntityTypes).toEqual([ENTITY_TYPE_CONTAINER_REPORT]);
    expect(getDefinition(ABSTRACT_STIX_DOMAIN_OBJECT)?.label).toEqual('Note');
    expect(getDefinition(ABSTRACT_STIX_DOMAIN_OBJECT)?.subEntityTypes)
      .toEqual(expect.arrayContaining([ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER_CASE_INCIDENT]));
  });
});
