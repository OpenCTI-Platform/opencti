import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../src/modules/index';
import * as cacheModule from '../../../src/database/cache';
import { getSchemaAttributes } from '../../../src/domain/attribute';
import { INTERNAL_ATTRIBUTES } from '../../../src/domain/attribute-utils';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { xOpenctiHuntedAt, xOpenctiHuntMatchedAt } from '../../../src/schema/attribute-definition';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_META_OBJECT } from '../../../src/schema/general';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaTypesDefinition } from '../../../src/schema/schema-types';
import { validateUpdatableAttribute } from '../../../src/schema/schema-validator';
import { ENTITY_IPV4_ADDR } from '../../../src/schema/stixCyberObservable';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;
const HUNT_DATES = [xOpenctiHuntedAt.name, xOpenctiHuntMatchedAt.name];
const HUNTED_TYPES = [ENTITY_IPV4_ADDR, ENTITY_TYPE_INDICATOR];
// The types the CSV and JSON mappers create, whose attributes they offer unless listed as internal
const MAPPED_TYPES = [
  ...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE),
  ...schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT),
  ...schemaTypesDefinition.get(ABSTRACT_STIX_META_OBJECT),
  ...schemaTypesDefinition.get(ABSTRACT_STIX_CORE_RELATIONSHIP),
  STIX_SIGHTING_RELATIONSHIP,
];

describe('Attributes only the platform writes', () => {
  beforeEach(() => {
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue([]);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(MAPPED_TYPES)('should keep the attributes of %s that users cannot update out of the mappers', (type) => {
    const notUpdatable = Array.from(schemaAttributesDefinition.getAttributes(type).values())
      .filter((attribute) => attribute.update === false)
      .map((attribute) => attribute.name);
    expect(notUpdatable.filter((name) => !INTERNAL_ATTRIBUTES.includes(name))).toEqual([]);
  });

  it('should not offer the hunt dates in the schema the forms are built from', async () => {
    const schema = await getSchemaAttributes(CONTEXT, USER);
    HUNTED_TYPES.forEach((type) => {
      const names = schema.find((typeAttributes) => typeAttributes.type === type)?.attributes.map((attribute) => attribute.name) ?? [];
      expect(names).toContain('x_opencti_score');
      expect(names.filter((name) => HUNT_DATES.includes(name))).toEqual([]);
    });
  });

  it('should refuse the hunt dates as an update', () => {
    HUNTED_TYPES.forEach((type) => {
      expect(validateUpdatableAttribute(type, { x_opencti_hunted_at: '2026-10-16T00:00:00.000Z', x_opencti_hunt_matched_at: '2026-10-16T00:00:00.000Z' })).toEqual(HUNT_DATES);
    });
  });

  it('should keep the hunt dates filterable', () => {
    HUNTED_TYPES.forEach((type) => {
      HUNT_DATES.forEach((name) => {
        expect(schemaAttributesDefinition.getAttribute(type, name)).toMatchObject({ type: 'date', isFilterable: true });
      });
    });
  });
});
