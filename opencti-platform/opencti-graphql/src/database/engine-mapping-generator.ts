import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
import { UnsupportedError } from '../config/errors';
import { rule_definitions } from '../rules/rules-definition';
import {
  type AttributeDefinition,
  booleanMapping,
  dateMapping,
  longStringFormats,
  numericMapping,
  shortMapping,
  shortStringFormats,
  textMapping,
} from '../schema/attribute-definition';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../schema/general';
import { INTERNAL_RELATIONSHIPS } from '../schema/internalRelationship';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import { STIX_CORE_RELATIONSHIPS } from '../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';

export const engineMappingGenerator = (engine: ElkClient | OpenClient): Record<string, any> => {
  return { ...attributesMappingGenerator(engine), ...ruleMappingGenerator(engine), ...denormalizeRelationsMappingGenerator() };
};

// Engine mapping generation on attributes definition
const attributeMappingGenerator = (entityAttribute: AttributeDefinition, engine: ElkClient | OpenClient): any => {
  if (entityAttribute.type === 'string') {
    if (shortStringFormats.includes(entityAttribute.format)) {
      return shortMapping;
    }
    if (longStringFormats.includes(entityAttribute.format)) {
      return textMapping;
    }
    throw UnsupportedError('Cant generated string mapping', { format: entityAttribute.format });
  }
  if (entityAttribute.type === 'date') {
    return dateMapping;
  }
  if (entityAttribute.type === 'numeric') {
    return numericMapping(entityAttribute.precision);
  }
  if (entityAttribute.type === 'boolean') {
    return booleanMapping;
  }
  if (entityAttribute.type === 'object') {
    // For flat object
    if (entityAttribute.format === 'flat') {
      return { type: engine instanceof ElkClient ? 'flattened' : 'flat_object' };
    }
    // For standard object
    const properties: Record<string, any> = {};
    for (let i = 0; i < entityAttribute.mappings.length; i += 1) {
      const mapping = entityAttribute.mappings[i];
      properties[mapping.name] = attributeMappingGenerator(mapping, engine);
    }
    const config: { dynamic: string; properties: any; type?: string } = { dynamic: 'strict', properties };
    // Add nested option if needed
    if (entityAttribute.format === 'nested') {
      config.type = 'nested';
    }
    return config;
  }
  throw UnsupportedError('Cant generated mapping', { type: entityAttribute.type });
};
const ruleMappingGenerator = (engine: ElkClient | OpenClient): Record<string, { dynamic: string; properties: any }> => {
  const schemaProperties: Record<string, { dynamic: string; properties: any }> = {};
  for (let attrIndex = 0; attrIndex < rule_definitions.length; attrIndex += 1) {
    const rule = rule_definitions[attrIndex];
    schemaProperties[`i_rule_${rule.id}`] = {
      dynamic: 'strict',
      properties: {
        explanation: shortMapping,
        dependencies: shortMapping,
        hash: shortMapping,
        data: { type: engine instanceof ElkClient ? 'flattened' : 'flat_object' },
      },
    };
  }
  return schemaProperties;
};
const denormalizeRelationsMappingGenerator = (): Record<string, { dynamic: string; properties: any }> => {
  const databaseRelationshipsName = [
    STIX_SIGHTING_RELATIONSHIP,
    ...STIX_CORE_RELATIONSHIPS,
    ...INTERNAL_RELATIONSHIPS,
    ...schemaTypesDefinition.get(ABSTRACT_STIX_REF_RELATIONSHIP),
  ];
  const schemaProperties: Record<string, { dynamic: string; properties: any }> = {};
  for (let attrIndex = 0; attrIndex < databaseRelationshipsName.length; attrIndex += 1) {
    const relName = databaseRelationshipsName[attrIndex];
    schemaProperties[`rel_${relName}`] = {
      dynamic: 'strict',
      properties: {
        internal_id: shortMapping,
        inferred_id: shortMapping,
      },
    };
  }
  return schemaProperties;
};

const attributesMappingGenerator = (engine: ElkClient | OpenClient): Record<string, any> => {
  const entityAttributes = schemaAttributesDefinition.getAllAttributes();
  const schemaProperties: Record<string, any> = {};
  for (let attrIndex = 0; attrIndex < entityAttributes.length; attrIndex += 1) {
    const entityAttribute = entityAttributes[attrIndex];
    schemaProperties[entityAttribute.name] = attributeMappingGenerator(entityAttribute, engine);
  }
  return schemaProperties;
};
