import type { StoreEntity } from './store';
import type { ConvertFn } from '../database/stix-converter';
import { registerStixDomainConverter } from '../database/stix-converter';
import { registerStixDomainAliased, registerStixDomainType, resolveAliasesField } from '../schema/stixDomainObject';
import { registerGraphqlSchema } from '../graphql/schema';
import { registerModelIdentifier } from '../schema/identifier';
import { schemaTypes, STIX_META_RELATIONSHIPS_INPUTS } from '../schema/general';
import { booleanAttributes, dateAttributes, dictAttributes, jsonAttributes, multipleAttributes, numericAttributes } from '../schema/fieldDataAdapter';
import { STIX_CORE_RELATIONSHIPS } from '../schema/stixCoreRelationship';
import { CHECK_META_RELATIONSHIP_VALUES, RelationDefinition, stixCoreRelationshipsMapping as coreRels, } from '../database/stix';
import { STIX_EXTERNAL_META_RELATIONSHIPS, STIX_META_RELATION_TO_FIELD } from '../schema/stixMetaRelationship';
import { RELATION_DATA_SOURCE } from '../modules/dataComponent/dataComponent-domain';
import { STIX_ATTRIBUTE_TO_META_FIELD } from '../schema/stixEmbeddedRelationship';

export type AttrType = 'string' | 'date' | 'numeric' | 'boolean' | 'dictionary' | 'json';
export interface ModuleDefinition<T extends StoreEntity> {
  type: {
    id: string;
    name: string;
    aliased: boolean;
    category: 'StixDomainEntity';
  };
  graphql: {
    schema: any,
    resolver: any,
  };
  identifier: {
    definition: {
      [k: string]: Array<{ src: string }>
    };
    resolvers: {
      [f: string]: (data: object) => string
    };
  };
  attributes: Array<{
    name: string;
    type: AttrType;
    multiple: boolean;
    upsert: boolean;
  }>;
  relations: Array<{
    name: string;
    targets: Array<RelationDefinition>;
  }>;
  relationsRefs?: Array<{
    attribute: string;
    input: string;
    relation: string;
    checker: (fromType: string, toType: string) => boolean;
  }>;
  converter: ConvertFn<T>;
}

export const registerDefinition = <T extends StoreEntity>(definition: ModuleDefinition<T>) => {
  const attrsForType = (type: AttrType) => {
    return definition.attributes.filter((attr) => attr.type === type).map((attr) => attr.name);
  };
    // Register types
  if (definition.type.category === 'StixDomainEntity') {
    registerStixDomainType(definition.type.name);
    if (definition.type.aliased) {
      registerStixDomainAliased(definition.type.name);
    }
  }
  // Register graphQL schema
  registerGraphqlSchema(definition.graphql);
  // Register key identification
  registerModelIdentifier(definition.identifier);
  // Register model attributes
  const attributes = ['standard_id'];
  attributes.push(...definition.attributes.map((attr) => attr.name));
  if (definition.type.aliased) {
    attributes.push(...[resolveAliasesField(definition.type.name), 'i_aliases_ids']);
  }
  if (definition.type.category === 'StixDomainEntity') {
    attributes.push(...['x_opencti_stix_ids', 'revoked', 'confidence', 'lang']);
  }
  schemaTypes.registerAttributes(definition.type.name, attributes);
  // Register upsert attributes
  const upsertAttributes = definition.attributes.filter((attr) => attr.upsert).map((attr) => attr.name);
  if (definition.type.category === 'StixDomainEntity') {
    upsertAttributes.push(...['x_opencti_stix_ids', 'revoked', 'confidence']);
  }
  schemaTypes.registerUpsertAttributes(definition.type.name, upsertAttributes);
  registerStixDomainConverter(definition.type.name, definition.converter);
  // Register attribute types
  dateAttributes.push(...attrsForType('date')); // --- dateAttributes
  numericAttributes.push(...attrsForType('numeric')); // --- numericAttributes
  booleanAttributes.push(...attrsForType('boolean')); // --- booleanAttributes
  dictAttributes.push(...attrsForType('dictionary')); // --- dictAttributes
  const multipleAttrs = definition.attributes.filter((attr) => attr.multiple).map((attr) => attr.name);
  multipleAttributes.push(...multipleAttrs); // --- multipleAttributes
  jsonAttributes.push(...attrsForType('json')); // --- jsonAttributes
  // Register relations
  definition.relations.forEach((source) => {
    STIX_CORE_RELATIONSHIPS.push(source.name);
    source.targets.forEach((target) => {
      const key: `${string}_${string}` = `${definition.type.name}_${target.name}`;
      coreRels[key] = [...(coreRels[key] ?? []), { name: source.name, type: target.type }];
    });
  });
  // Register relations ref
  definition.relationsRefs?.forEach((source) => {
    STIX_META_RELATIONSHIPS_INPUTS.push(source.input);
    STIX_EXTERNAL_META_RELATIONSHIPS.push(source.relation);
    STIX_META_RELATION_TO_FIELD[source.relation] = source.input;
    CHECK_META_RELATIONSHIP_VALUES[RELATION_DATA_SOURCE] = source.checker;
    STIX_ATTRIBUTE_TO_META_FIELD[source.attribute] = source.input;
  });
};
