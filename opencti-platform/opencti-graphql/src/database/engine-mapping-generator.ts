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

// Only useful for option ES_INIT_RETRO_MAPPING_MIGRATION
// This mode let the platform initialize old mapping protection before direct stop
// Its only useful when old platform needs to be reindex
export const getRetroCompatibleMappings = (engine: ElkClient | OpenClient): any => {
  const flattenedType = engine instanceof ElkClient ? 'flattened' : 'flat_object';
  return {
    internal_id: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    standard_id: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    user_email: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    name: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    height: {
      type: 'nested',
      properties: {
        measure: { type: 'float' },
        date_seen: { type: 'date' },
      },
    },
    weight: {
      type: 'nested',
      properties: {
        measure: { type: 'float' },
        date_seen: { type: 'date' },
      },
    },
    timestamp: {
      type: 'date',
    },
    created: {
      type: 'date',
    },
    created_at: {
      type: 'date',
    },
    modified: {
      type: 'date',
    },
    modified_at: {
      type: 'date',
    },
    indexed_at: {
      type: 'date',
    },
    uploaded_at: {
      type: 'date',
    },
    first_seen: {
      type: 'date',
    },
    last_seen: {
      type: 'date',
    },
    start_time: {
      type: 'date',
    },
    stop_time: {
      type: 'date',
    },
    published: {
      type: 'date',
    },
    valid_from: {
      type: 'date',
    },
    valid_until: {
      type: 'date',
    },
    observable_date: {
      type: 'date',
    },
    event_date: {
      type: 'date',
    },
    received_time: {
      type: 'date',
    },
    processed_time: {
      type: 'date',
    },
    completed_time: {
      type: 'date',
    },
    ctime: {
      type: 'date',
    },
    mtime: {
      type: 'date',
    },
    atime: {
      type: 'date',
    },
    current_state_date: {
      type: 'date',
    },
    confidence: {
      type: 'integer',
    },
    attribute_order: {
      type: 'integer',
    },
    base_score: {
      type: 'integer',
    },
    is_family: {
      type: 'boolean',
    },
    number_observed: {
      type: 'integer',
    },
    x_opencti_negative: {
      type: 'boolean',
    },
    default_assignation: {
      type: 'boolean',
    },
    x_opencti_detection: {
      type: 'boolean',
    },
    x_opencti_order: {
      type: 'integer',
    },
    import_expected_number: {
      type: 'integer',
    },
    import_processed_number: {
      type: 'integer',
    },
    x_opencti_score: {
      type: 'integer',
    },
    connections: {
      type: 'nested',
    },
    manager_setting: {
      type: flattenedType,
    },
    context_data: {
      properties: {
        input: { type: flattenedType },
      },
    },
    size: {
      type: 'integer',
    },
    lastModifiedSinceMin: {
      type: 'integer',
    },
    lastModified: {
      type: 'date',
    },
    metaData: {
      properties: {
        order: {
          type: 'integer',
        },
        inCarousel: {
          type: 'boolean',
        },
        messages: { type: flattenedType },
        errors: { type: flattenedType },
      },
    },
  };
};
