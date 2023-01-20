import type { StoreEntity } from './store';
import type { ConvertFn, RepresentativeFn } from '../database/stix-converter';
import {
  registerStixDomainConverter,
  registerStixMetaConverter,
  registerStixRepresentativeConverter
} from '../database/stix-converter';
import { registerStixDomainAliased, registerStixDomainType, resolveAliasesField } from '../schema/stixDomainObject';
import { registerGraphqlSchema } from '../graphql/schema';
import { registerModelIdentifier } from '../schema/identifier';
import {
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_OBJECT,
  DEPS_KEYS,
  ENTITY_TYPE_CONTAINER, ENTITY_TYPE_LOCATION,
  schemaTypes,
  STIX_META_RELATIONSHIPS_INPUTS
} from '../schema/general';
import {
  booleanAttributes,
  dateAttributes,
  dictAttributes,
  jsonAttributes,
  multipleAttributes,
  numericAttributes
} from '../schema/fieldDataAdapter';
import { STIX_CORE_RELATIONSHIPS } from '../schema/stixCoreRelationship';
import {
  CHECK_META_RELATIONSHIP_VALUES,
  RelationDefinition,
  stixCoreRelationshipsMapping as coreRels,
} from '../database/stix';
import { UnsupportedError } from '../config/errors';
import {
  SINGLE_STIX_META_RELATIONSHIPS,
  SINGLE_STIX_META_RELATIONSHIPS_INPUTS,
  STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD,
  STIX_EXTERNAL_META_RELATIONSHIPS,
  STIX_META_RELATION_TO_FIELD
} from '../schema/stixMetaRelationship';
import { STIX_ATTRIBUTE_TO_META_FIELD } from '../schema/stixEmbeddedRelationship';
import type { StixObject } from './stix-common';
import { registerInternalObject } from '../schema/internalObject';

export type AttrType = 'string' | 'date' | 'numeric' | 'boolean' | 'dictionary' | 'json';
export interface ModuleDefinition<T extends StoreEntity, Z extends StixObject> {
  type: {
    id: string;
    name: string;
    aliased?: boolean;
    category: 'Container' | 'Location' | 'Stix-Domain-Object' | 'Stix-Meta-Object' | 'Internal-Object';
  };
  graphql: {
    schema: any,
    resolver: any,
  };
  identifier: {
    definition: {
      [k: string]: Array<{ src: string }> | (() => string)
    };
    resolvers?: {
      [f: string]: (data: object) => string
    };
  };
  representative: RepresentativeFn<Z>;
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
    multiple: boolean;
    checker: (fromType: string, toType: string) => boolean;
  }>;
  converter: ConvertFn<T, Z>;
  depsKeys?: { src: string, types?: string[] }[]
}

export const registerDefinition = <T extends StoreEntity, Z extends StixObject>(definition: ModuleDefinition<T, Z>) => {
  const attrsForType = (type: AttrType) => {
    return definition.attributes.filter((attr) => attr.type === type).map((attr) => attr.name);
  };
    // Register types
  if (definition.type.category) {
    switch (definition.type.category) {
      case ENTITY_TYPE_LOCATION:
        schemaTypes.add(ENTITY_TYPE_LOCATION, definition.type.name);
        registerStixDomainType(definition.type.name);
        registerStixDomainConverter(definition.type.name, definition.converter);
        break;
      case ENTITY_TYPE_CONTAINER:
        schemaTypes.add(ENTITY_TYPE_CONTAINER, definition.type.name);
        registerStixDomainType(definition.type.name);
        registerStixDomainConverter(definition.type.name, definition.converter);
        break;
      case ABSTRACT_STIX_DOMAIN_OBJECT:
        registerStixDomainType(definition.type.name);
        registerStixDomainConverter(definition.type.name, definition.converter);
        break;
      case ABSTRACT_STIX_META_OBJECT:
        schemaTypes.add(ABSTRACT_STIX_META_OBJECT, definition.type.name);
        registerStixMetaConverter(definition.type.name, definition.converter);
        break;
      case ABSTRACT_INTERNAL_OBJECT:
        schemaTypes.add(ABSTRACT_INTERNAL_OBJECT, definition.type.name);
        registerInternalObject(definition.type.name);
        break;
      default:
        throw UnsupportedError('Unsupported category');
    }
    if (definition.type.aliased) {
      registerStixDomainAliased(definition.type.name);
    }
  }

  // Register representative
  registerStixRepresentativeConverter(definition.type.name, definition.representative);

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
  if (definition.type.category === ABSTRACT_STIX_DOMAIN_OBJECT) {
    attributes.push(...['x_opencti_stix_ids', 'revoked', 'confidence', 'lang']);
  }
  schemaTypes.registerAttributes(definition.type.name, attributes);

  // Register upsert attributes
  const upsertAttributes = definition.attributes.filter((attr) => attr.upsert).map((attr) => attr.name);
  if (definition.type.category === ABSTRACT_STIX_DOMAIN_OBJECT) {
    upsertAttributes.push(...['x_opencti_stix_ids', 'revoked', 'confidence']);
  }
  schemaTypes.registerUpsertAttributes(definition.type.name, upsertAttributes);

  // Register attribute types
  dateAttributes.push(...attrsForType('date')); // --- dateAttributes
  numericAttributes.push(...attrsForType('numeric')); // --- numericAttributes
  booleanAttributes.push(...attrsForType('boolean')); // --- booleanAttributes
  dictAttributes.push(...attrsForType('dictionary')); // --- dictAttributes
  const multipleAttrs = definition.attributes.filter((attr) => attr.multiple).map((attr) => attr.name);
  multipleAttributes.push(...multipleAttrs); // --- multipleAttributes
  jsonAttributes.push(...attrsForType('json')); // --- jsonAttributes

  // Register dependency keys for input resolved refs
  schemaTypes.add(DEPS_KEYS, definition.depsKeys ?? []);

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
    CHECK_META_RELATIONSHIP_VALUES[source.relation] = source.checker;
    STIX_ATTRIBUTE_TO_META_FIELD[source.attribute] = source.input;
    STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD[source.attribute] = source.input;
    if (!source.multiple) {
      SINGLE_STIX_META_RELATIONSHIPS.push(source.relation);
      SINGLE_STIX_META_RELATIONSHIPS_INPUTS.push(source.input);
    }
  });
};
