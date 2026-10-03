import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import type { Client as OpenClient } from '@opensearch-project/opensearch';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { engineMappingGenerator } from '../../../../src/database/engine-mapping-generator';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_IPV4_ADDR } from '../../../../src/schema/stixCyberObservable';
import { RELATION_TARGETS, RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { ENTITY_TYPE_LABEL } from '../../../../src/schema/stixMetaObject';
import {
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_FRESHNESS_STALE,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_PROCEDURES,
  ATTRIBUTE_SINGLE_SOURCED,
  PROVENANCE_SIDE_CHANNEL_FIELDS,
} from '../../../../src/modules/provenance/provenance-types';

const PROVENANCE_ATTRIBUTES = [
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_SINGLE_SOURCED,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_FRESHNESS_STALE,
];

describe('Provenance attributes registration', () => {
  it.each([
    ENTITY_TYPE_MALWARE,
    ENTITY_TYPE_ATTACK_PATTERN,
    ENTITY_TYPE_INDICATOR,
    ENTITY_IPV4_ADDR,
    ENTITY_HASHED_OBSERVABLE_STIX_FILE,
    RELATION_USES,
    RELATION_TARGETS,
    STIX_SIGHTING_RELATIONSHIP,
  ])('should register provenance attributes on %s', (type) => {
    const names = schemaAttributesDefinition.getAttributeNames(type);
    PROVENANCE_ATTRIBUTES.forEach((attribute) => expect(names).toContain(attribute));
  });

  it.each([ENTITY_TYPE_USER, ENTITY_TYPE_LABEL])('should not register provenance attributes on %s', (type) => {
    const names = schemaAttributesDefinition.getAttributeNames(type);
    PROVENANCE_ATTRIBUTES.forEach((attribute) => expect(names).not.toContain(attribute));
  });

  it('should register procedures only on uses relationships', () => {
    expect(schemaAttributesDefinition.getAttribute(RELATION_USES, ATTRIBUTE_PROCEDURES)).toBeDefined();
    expect(schemaAttributesDefinition.getAttribute(RELATION_TARGETS, ATTRIBUTE_PROCEDURES)).toBeUndefined();
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_MALWARE, ATTRIBUTE_PROCEDURES)).toBeUndefined();
  });

  it('should keep the assertion shape stable', () => {
    const assertions = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_MALWARE, ATTRIBUTE_ASSERTIONS);
    expect(assertions?.type).toEqual('object');
    const mappings = (assertions as { mappings: { name: string }[] }).mappings.map((m) => m.name);
    expect(mappings).toEqual([
      'source_id',
      'source_kind',
      'source_name',
      'first_asserted_at',
      'last_asserted_at',
      'assert_count',
      'confidence',
      'work_id',
    ]);
  });

  it('should never let clients update side-channel provenance fields', () => {
    PROVENANCE_SIDE_CHANNEL_FIELDS.forEach((field) => {
      const definition = schemaAttributesDefinition.getAttribute(RELATION_USES, field);
      expect(definition?.update).toEqual(false);
      expect(definition?.upsert).toEqual(false);
    });
  });

  it('should generate the engine mappings', () => {
    const mappings = engineMappingGenerator({} as OpenClient);
    expect(mappings[ATTRIBUTE_ASSERTIONS].type).toEqual('nested');
    expect(mappings[ATTRIBUTE_ASSERTIONS].dynamic).toEqual('strict');
    expect(mappings[ATTRIBUTE_ASSERTIONS].properties.source_id.fields.keyword.type).toEqual('keyword');
    expect(mappings[ATTRIBUTE_ASSERTIONS].properties.first_asserted_at.type).toEqual('date');
    expect(mappings[ATTRIBUTE_ASSERTIONS].properties.assert_count.type).toEqual('integer');
    expect(mappings[ATTRIBUTE_CORROBORATION_COUNT].type).toEqual('integer');
    expect(mappings[ATTRIBUTE_LAST_ASSERTED_AT].type).toEqual('date');
    expect(mappings[ATTRIBUTE_SINGLE_SOURCED].type).toEqual('boolean');
    expect(mappings[ATTRIBUTE_HAS_CONFLICTS].type).toEqual('boolean');
    expect(mappings[ATTRIBUTE_CONFLICTS].type).toEqual('nested');
    expect(mappings[ATTRIBUTE_CONFLICTS].properties.values.properties.display.type).toEqual('text');
    expect(mappings[ATTRIBUTE_PROCEDURES].properties.text.type).toEqual('text');
  });
});
