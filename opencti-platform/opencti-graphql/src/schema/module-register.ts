import type { StoreEntity } from '../types/store';
import type { RelationDefinition } from '../database/stix';
import type { ConvertFn } from '../database/stix-converter';
import type { AttrType } from '../types/module';
import {
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_META_OBJECT,
  DEPS_KEYS,
  ENTITY_TYPE_CONTAINER,
  schemaTypes,
  STIX_META_RELATIONSHIPS_INPUTS
} from './general';
import {
  registerStixDomainAliased,
  registerStixDomainType,
  resolveAliasesFieldComplex
} from './stixDomainObject';
import { registerStixDomainConverter, registerStixMetaConverter } from '../database/stix-converter';
import { UnsupportedError } from '../config/errors';
import { registerGraphqlSchema } from '../graphql/schema';
import { registerModelIdentifier } from './identifier';
import { confidence, iAliasedIds, lang, revoked, standardId, xOpenctiStixIds } from './entity-attributes';
import { schemaDefinition } from './schema-register';
import { STIX_CORE_RELATIONSHIPS } from './stixCoreRelationship';
import { CHECK_META_RELATIONSHIP_VALUES, stixCoreRelationshipsMapping as coreRels } from '../database/stix';
import {
  SINGLE_STIX_META_RELATIONSHIPS, SINGLE_STIX_META_RELATIONSHIPS_INPUTS,
  STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD,
  STIX_EXTERNAL_META_RELATIONSHIPS,
  STIX_META_RELATION_TO_FIELD
} from './stixMetaRelationship';
import { STIX_ATTRIBUTE_TO_META_FIELD } from './stixEmbeddedRelationship';
import { registerInternalObject } from './internalObject';
import type { ValidatorFn } from './validator-register';
import { registerEntityValidator } from './validator-register';

export type MandatoryType = 'internal' | 'external' | 'customizable' | 'no';

export interface AttributeDefinition {
  name: string
  type: AttrType
  mandatoryType: MandatoryType
  multiple: boolean
  upsert: boolean
  label?: string
  description?: string
  schemaDef?: Record<string, any> // if the type is json, need-it
}

export interface ModuleRegisterDefinition<T extends StoreEntity> {
  type: {
    id: string;
    name: string;
    aliased: boolean;
    category: 'Container' | 'Stix-Domain-Object' | 'Stix-Meta-Object' | 'Internal-Object';
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
  attributes: Array<AttributeDefinition>;
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
  converter: ConvertFn<T>;
  validators: {
    validatorCreation?: ValidatorFn,
    validatorUpdate?: ValidatorFn
  }
  depsKeys?: { src: string, types?: string[] }[]
}

export const moduleRegisterDefinition = <T extends StoreEntity>(definition: ModuleRegisterDefinition<T>) => {
  // Register types
  if (definition.type.category) {
    switch (definition.type.category) {
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
  }
  if (definition.type.aliased) {
    registerStixDomainAliased(definition.type.name);
  }
  // Register validator
  if (definition.validators) {
    registerEntityValidator(definition.type.name, definition.validators);
  }

  // Register graphQL schema
  registerGraphqlSchema(definition.graphql);
  // Register key identification
  registerModelIdentifier(definition.identifier);
  // Register model attributes
  const attributes: AttributeDefinition[] = [standardId];
  attributes.push(...definition.attributes.map((attr) => attr));
  if (definition.type.aliased) {
    attributes.push(...[resolveAliasesFieldComplex(definition.type.name), iAliasedIds]);
  }
  if (definition.type.category === ABSTRACT_STIX_DOMAIN_OBJECT) {
    attributes.push(...[xOpenctiStixIds, revoked, confidence, lang]);
  }
  schemaDefinition.registerAttributes(definition.type.name, attributes);

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
