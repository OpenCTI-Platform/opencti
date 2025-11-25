/* eslint-disable no-param-reassign */
import { DateTime } from 'luxon';
import type { AttributeDefinition, AttrType, ObjectAttribute } from '../schema/attribute-definition';
import { entityType, relationshipType, standardId } from '../schema/attribute-definition';
import { generateStandardId } from '../schema/identifier';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { handleInnerType } from '../domain/stixDomainObject';
import { extractValueFromCsv } from './csv-helper';
import { isStixRelationshipExceptRef } from '../schema/stixRelationship';
import type { AttributeColumn, CsvMapperParsed, CsvMapperRepresentation, CsvMapperRepresentationAttribute } from '../modules/internal/csvMapper/csvMapper-types';
import { CsvMapperRepresentationType } from '../modules/internal/csvMapper/csvMapper-types';
import { getHashesNames, isCsvValidRepresentationType } from '../modules/internal/csvMapper/csvMapper-utils';
import { fillDefaultValues, getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import type { AuthContext, AuthUser } from '../types/user';
import { UnsupportedError } from '../config/errors';
import { internalFindByIdsMapped } from '../database/middleware-loader';
import type { BasicStoreObject } from '../types/store';
import { INPUT_MARKINGS } from '../schema/general';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { CsvMapperOperator } from '../generated/graphql';
import type { ComplexAttributePath, JsonMapperParsed, JsonMapperRepresentation, SimpleAttributePath } from '../modules/internal/jsonMapper/jsonMapper-types';

export type InputType = string | string[] | boolean | number | Record<string, any>;
const USER_CHOICE_MARKING_CONFIG = 'user-choice';

// -- HANDLE VALUE --

export const formatValue = (value: string | boolean, type: AttrType, column: AttributeColumn | SimpleAttributePath | ComplexAttributePath | undefined) => {
  const pattern_date = column?.configuration?.pattern_date;
  const timezone = column?.configuration?.timezone;
  if ((type === 'string' || type === 'ref') && typeof value === 'string') {
    return value.trim();
  }
  if (type === 'numeric' && typeof value === 'string') {
    const formattedValue = Number(value);
    return Number.isNaN(formattedValue) ? null : formattedValue;
  }
  if (type === 'date' && typeof value === 'string') {
    try {
      if (isNotEmptyField(pattern_date)) {
        if (isNotEmptyField(timezone)) {
          return DateTime.fromFormat(value, pattern_date, { zone: timezone }).toUTC().toISO();
        }
        return DateTime.fromFormat(value, pattern_date).toUTC().toISO();
      }
      return DateTime.fromISO(value).toUTC().toISO();
    } catch (_error: any) {
      return null;
    }
  }
  if (type === 'boolean') {
    if (typeof value === 'boolean') {
      return value;
    }
    const stringBoolean = (value ?? '').toLowerCase().trim();
    // TODO Matching value must be configurable in parser option
    return stringBoolean === 'true' || stringBoolean === 'yes' || stringBoolean === '1';
  }
  return value;
};

export const computeValue = (value: string | undefined, column: AttributeColumn, attributeDef: AttributeDefinition) => {
  if (value === undefined || isEmptyField(value)) {
    return null;
  }
  // Handle multiple
  if (attributeDef.multiple) {
    if (column.configuration?.separator) {
      return value.split(column.configuration.separator).map((v) => formatValue(v, attributeDef.type, column));
    }
    return [formatValue(value, attributeDef.type, column)];
  }
  // Handle single
  return formatValue(value, attributeDef.type, column);
};

export const computeDefaultValue = (
  defaultValue: string[],
  attribute: CsvMapperRepresentationAttribute,
  definition: AttributeDefinition,
) => {
  // Handle multiple
  if (definition.multiple) {
    return defaultValue.map((v) => formatValue(v, definition.type, attribute.column));
  }
  // Handle single
  return formatValue(defaultValue[0], definition.type, attribute.column);
};

// -- VALIDATION --

const isValidTarget = (record: string[], representation: CsvMapperRepresentation) => {
  // Target type
  isCsvValidRepresentationType(representation);
  // Column based
  const columnBased = representation.target.column_based;
  if (columnBased && columnBased.column_reference) {
    const recordValue = extractValueFromCsv(record, columnBased.column_reference);
    if (columnBased.operator === CsvMapperOperator.Eq) {
      return recordValue === columnBased.value;
    }
    if (columnBased.operator === CsvMapperOperator.NotEq) {
      return recordValue !== columnBased.value;
    }
    return false;
  }
  return true;
};

const isValidInput = (input: Record<string, InputType>) => {
  // Verify from and to are filled for relationship
  if (isStixRelationshipExceptRef(input[entityType.name] as string)) {
    if (isEmptyField(input.from) || isEmptyField(input.to)) {
      return false;
    }
  }

  // Verify mandatory attributes are filled
  // TODO: Removed it when it will be handle in schema-validator
  const mandatoryAttributes = Array.from(schemaAttributesDefinition.getAttributes(input[entityType.name] as string).values())
    .filter((attr) => attr.mandatoryType === 'external')
    .map((attr) => attr.name);
  const mandatoryRefs = schemaRelationsRefDefinition.getRelationsRef(input[entityType.name] as string)
    .filter((ref) => ref.mandatoryType === 'external')
    .map((ref) => ref.name);

  return [...mandatoryAttributes, ...mandatoryRefs].every((key) => isNotEmptyField(input[key]));
};

// -- COMPUTE --

const handleType = (representation: CsvMapperRepresentation, input: Record<string, InputType>) => {
  const { entity_type } = representation.target;
  input[entityType.name] = entity_type;
  if (representation.type === CsvMapperRepresentationType.Relationship) {
    input[relationshipType.name] = entity_type;
  }
};
const handleId = (representation: CsvMapperRepresentation, input: Record<string, InputType>) => {
  input[standardId.name] = generateStandardId(representation.target.entity_type, input);
};

const handleDirectAttribute = (
  attribute: CsvMapperRepresentationAttribute,
  input: Record<string, InputType>,
  record: string[],
  definition: AttributeDefinition,
  hashesNames: string[],
) => {
  const isAttributeHash = hashesNames.includes(attribute.key);

  if (attribute.default_values !== null && attribute.default_values !== undefined && !isAttributeHash) {
    const computedDefault = computeDefaultValue(attribute.default_values, attribute, definition);
    if (computedDefault !== null && computedDefault !== undefined) {
      input[attribute.key] = computedDefault;
    }
  }
  if (attribute.column && isNotEmptyField(attribute.column?.column_name)) {
    const recordValue = extractValueFromCsv(record, attribute.column.column_name);
    const computedValue = computeValue(recordValue, attribute.column, definition);
    if (computedValue !== null && computedValue !== undefined) {
      if (isAttributeHash) {
        const values = (input.hashes ?? {}) as Record<string, any>;
        input.hashes = { ...values, [attribute.key]: computedValue };
      } else {
        input[attribute.key] = computedValue;
      }
    }
  }
};

const handleBasedOnAttribute = (
  attribute: CsvMapperRepresentationAttribute,
  input: Record<string, InputType>,
  definition: AttributeDefinition | null,
  otherEntities: Map<string, Record<string, InputType>>,
  refEntities: Record<string, BasicStoreObject>
) => {
  // Handle default value based_on attribute except markings which are handled later on.
  if (definition && attribute.default_values && attribute.default_values.length > 0 && attribute.key !== INPUT_MARKINGS) {
    if (definition.multiple) {
      input[attribute.key] = attribute.default_values.flatMap((id) => {
        const entity = refEntities[id];
        if (!entity) return [];
        return [entity];
      });
    } else {
      const entity = refEntities[attribute.default_values[0]];
      if (entity) {
        input[attribute.key] = entity;
      }
    }
  }
  if (attribute.based_on) {
    if (isEmptyField(attribute.based_on)) {
      throw UnsupportedError('Unknown value(s)', { key: attribute.key });
    }
    const entities = (attribute.based_on.representations ?? [])
      .map((id) => otherEntities.get(id))
      .filter((e) => e !== undefined) as Record<string, InputType>[];
    if (entities.length > 0) {
      const entity_type = input[entityType.name] as string;
      // Is relation from or to (stix-core || stix-sighting)
      if (isStixRelationshipExceptRef(entity_type) && ['from', 'to'].includes(attribute.key)) {
        if (attribute.key === 'from') {
          const entity = entities[0];
          if (isNotEmptyField(entity)) {
            input.from = entity;
            input.fromType = entity[entityType.name];
          }
        } else if (attribute.key === 'to') {
          const entity = entities[0];
          if (isNotEmptyField(entity)) {
            input.to = entity;
            input.toType = entity[entityType.name];
          }
        }
        // Is relation ref
      } else if (definition) {
        const refs = definition.multiple ? entities : entities[0];
        if (isNotEmptyField(refs)) {
          input[attribute.key] = refs;
        }
      }
    }
  }
};

const handleAttributes = (
  record: string[],
  representation: CsvMapperRepresentation,
  input: Record<string, InputType>,
  otherEntities: Map<string, Record<string, InputType>>,
  refEntities: Record<string, BasicStoreObject>
) => {
  const { entity_type } = representation.target;
  const hashesNames = getHashesNames(entity_type);

  (representation.attributes ?? []).forEach((attribute) => {
    let attributeKey = attribute.key;
    if (hashesNames.includes(attribute.key)) {
      attributeKey = 'hashes';
    }
    const attributeDef = schemaAttributesDefinition.getAttribute(entity_type, attributeKey);
    const refDef = schemaRelationsRefDefinition.getRelationRef(entity_type, attributeKey);

    if (attributeDef) {
      if (hashesNames.includes(attribute.key)) {
        const definitionHash = (attributeDef as ObjectAttribute).mappings
          .find((definition) => (definition.name === attribute.key));
        if (definitionHash) {
          handleDirectAttribute(attribute, input, record, definitionHash, hashesNames);
        }
      } else {
        // Handle column attribute
        handleDirectAttribute(attribute, input, record, attributeDef, []);
      }
    } else if (refDef || ['from', 'to'].includes(attribute.key)) {
      handleBasedOnAttribute(attribute, input, refDef, otherEntities, refEntities);
    } else {
      throw UnsupportedError('Unknown schema for attribute:', { attribute });
    }
  });
};

/**
 * We handle markings in a specific function instead of doing it inside the
 * handleAttributes() one because we need to do specific logic for this attribute.
 */
export const handleDefaultMarkings = (
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  representation: CsvMapperRepresentation | JsonMapperRepresentation,
  input: Record<string, InputType>,
  refEntities: Record<string, BasicStoreObject>,
  chosenMarkings: string[],
  user: AuthUser,
) => {
  if (input[INPUT_MARKINGS]) {
    return;
  }

  // Find default markings policy in entity settings ("true" or undefined).
  const settingAttributes = entitySetting ? getAttributesConfiguration(entitySetting) : undefined;
  const settingMarkingValue = settingAttributes
    ?.find((attribute) => attribute.name === INPUT_MARKINGS)
    ?.default_values?.[0];
  // Find default markings policy in mapper representation ("user-default" or "user-choice"  or undefined).
  const representationMarkingValue = representation.attributes
    .find((attribute) => attribute.key === INPUT_MARKINGS)
    ?.default_values?.[0];

  // Retrieve default markings of the user.
  const userDefaultMarkings = (user.default_marking ?? [])
    .find((entry) => entry.entity_type === 'GLOBAL')
    ?.values ?? [];

  if (representationMarkingValue) {
    if (representationMarkingValue === USER_CHOICE_MARKING_CONFIG) {
      input[INPUT_MARKINGS] = chosenMarkings.flatMap((id) => {
        const entity = refEntities[id];
        if (!entity) return [];
        return [entity];
      });
    } else {
      input[INPUT_MARKINGS] = userDefaultMarkings;
    }
  } else if (settingMarkingValue) {
    input[INPUT_MARKINGS] = userDefaultMarkings;
  }
};

const mapRecord = async (
  context: AuthContext,
  user: AuthUser,
  record: string[],
  representation: CsvMapperRepresentation,
  otherEntities: Map<string, Record<string, InputType>>,
  refEntities: Record<string, BasicStoreObject>,
  chosenMarkings: string[]
) => {
  if (!isValidTarget(record, representation)) {
    return null;
  }
  const { entity_type } = representation.target;

  let input: Record<string, InputType> = {};
  handleType(representation, input);
  input = handleInnerType(input, entity_type);

  handleAttributes(record, representation, input, otherEntities, refEntities);

  const entitySetting = await getEntitySettingFromCache(context, entity_type);
  handleDefaultMarkings(entitySetting, representation, input, refEntities, chosenMarkings, user);

  const filledInput = fillDefaultValues(user, input, entitySetting);
  if (!isValidInput(filledInput)) {
    return null;
  }

  handleId(representation, filledInput);
  return filledInput;
};

export const handleRefEntities = async (
  context: AuthContext,
  user: AuthUser,
  mapper: CsvMapperParsed | JsonMapperParsed
) => {
  const { representations, user_chosen_markings } = mapper;
  // IDs of entity refs retrieved from default values of based_on attributes in csv mapper.
  const refIdsToResolve = new Set(representations.flatMap((representation) => {
    const { target } = representation;
    return representation.attributes.flatMap((attribute) => {
      if (attribute.default_values && attribute.default_values.length > 0) {
        const refDef = schemaRelationsRefDefinition.getRelationRef(target.entity_type, attribute.key);
        if (refDef) {
          return attribute.default_values;
        }
      }
      return [];
    });
  }));

  return internalFindByIdsMapped(
    context,
    user,
    [
      ...refIdsToResolve,
      // Also resolve the markings chosen by the user if any.
      ...(user_chosen_markings || []),
    ]
  );
};

export const mappingProcess = async (
  context: AuthContext,
  user: AuthUser,
  mapper: CsvMapperParsed,
  record: string[],
  refEntities: Record<string, BasicStoreObject>,
): Promise<Record<string, InputType>[]> => {
  // Resolution des representations & markings - refIds = default values for representation attributes
  const { representations, user_chosen_markings } = mapper;

  const representationRelationships = representations.filter((r) => r.type === CsvMapperRepresentationType.Relationship);

  const representationEntitiesWithoutBasedOnRelationships = representations
    .filter((r) => {
      const isEntity = r.type === CsvMapperRepresentationType.Entity;
      const entityHasRefToRelations = !r.attributes.some((a) => {
      // Check for each attribute of entity if it has based_on representations
        return a.based_on?.representations?.some((b) => {
        // Check if at least one of based_on ref is a relation in CSV Mapper
          return representationRelationships.some((rel) => rel.id === b);
        });
      });
      return isEntity && entityHasRefToRelations;
    })
    .sort((r1, r2) => r1.attributes.filter((attr) => attr.based_on).length - r2.attributes.filter((attr) => attr.based_on).length);

  // representations thar are not in representationEntitiesWithoutBasedOnRelationships
  const representationEntitiesWithBasedOnRelationships = representations
    .filter((r) => r.type === CsvMapperRepresentationType.Entity && !representationEntitiesWithoutBasedOnRelationships.some((r1) => r1.id === r.id));

  const results = new Map<string, Record<string, InputType>>();

  // 1. entities sort by no based on at first
  for (let i = 0; i < representationEntitiesWithoutBasedOnRelationships.length; i += 1) {
    const representation = representationEntitiesWithoutBasedOnRelationships[i];
    const input = await mapRecord(
      context,
      user,
      record,
      representation,
      results,
      refEntities,
      user_chosen_markings ?? []
    );
    if (input) {
      results.set(representation.id, input);
    }
  }

  // 2. relationships
  for (let i = 0; i < representationRelationships.length; i += 1) {
    const representation = representationRelationships[i];
    const input = await mapRecord(
      context,
      user,
      record,
      representation,
      results,
      refEntities,
      user_chosen_markings ?? []
    );
    if (input) {
      results.set(representation.id, input);
    }
  }

  // 3. entities with based on relationships at last
  for (let i = 0; i < representationEntitiesWithBasedOnRelationships.length; i += 1) {
    const representation = representationEntitiesWithBasedOnRelationships[i];
    const input = await mapRecord(
      context,
      user,
      record,
      representation,
      results,
      refEntities,
      user_chosen_markings ?? []
    );
    if (input) {
      results.set(representation.id, input);
    }
  }
  return Array.from(results.values());
};
