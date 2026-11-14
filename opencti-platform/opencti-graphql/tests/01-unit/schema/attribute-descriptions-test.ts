import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { ATTRIBUTE_DESCRIPTIONS, ATTRIBUTE_DESCRIPTIONS_BY_TYPE, resolveAttributeDescription } from '../../../src/schema/attribute-descriptions';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_REPORT, isStixDomainObject } from '../../../src/schema/stixDomainObject';
import { INTERNAL_ATTRIBUTES } from '../../../src/domain/attribute-utils';
import { RELATION_TARGETS } from '../../../src/schema/stixCoreRelationship';
import { ENTITY_TYPE_EVENT } from '../../../src/modules/event/event-types';

describe('resolveAttributeDescription', () => {
  it('should use the description of the definition first', () => {
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_NOTE, { name: 'content', description: 'Explicit' })).toEqual('Explicit');
  });

  it('should use the override of the type before the dictionary', () => {
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_NOTE, { name: 'content' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_CONTAINER_NOTE].content);
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_REPORT, { name: 'content' })).toEqual(ATTRIBUTE_DESCRIPTIONS.content);
    // start_time is the validity of a relationship, but the start of an event
    expect(resolveAttributeDescription(RELATION_TARGETS, { name: 'start_time' })).toEqual(ATTRIBUTE_DESCRIPTIONS.start_time);
    expect(resolveAttributeDescription(ENTITY_TYPE_EVENT, { name: 'start_time' })).toEqual(ATTRIBUTE_DESCRIPTIONS_BY_TYPE[ENTITY_TYPE_EVENT].start_time);
  });

  it('should return null for an attribute without description', () => {
    expect(resolveAttributeDescription(ENTITY_TYPE_CONTAINER_REPORT, { name: 'undescribed_attribute' })).toBeNull();
  });

  it('should describe every attribute and ref of the STIX Domain Objects', () => {
    const undescribed: string[] = [];
    const types = schemaAttributesDefinition.getRegisteredTypes().filter((type) => isStixDomainObject(type));
    for (const type of types) {
      const attributes = Array.from(schemaAttributesDefinition.getAttributes(type).values())
        .filter((attribute) => !INTERNAL_ATTRIBUTES.includes(attribute.name));
      let refs: { name: string; description?: string }[];
      try {
        refs = schemaRelationsRefDefinition.getRelationsRef(type);
      } catch {
        refs = [];
      }
      for (const attribute of [...attributes, ...refs]) {
        if (!resolveAttributeDescription(type, attribute)) undescribed.push(`${type}.${attribute.name}`);
      }
    }
    // A new SDO attribute needs a description in src/schema/attribute-descriptions.ts
    expect(undescribed).toEqual([]);
  });
});
