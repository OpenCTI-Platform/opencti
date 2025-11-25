/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as JSONPath from 'jsonpath-plus';

import '../modules';
import { v4 as uuidv4 } from 'uuid';
import ejs from 'ejs';
import {
  type BasedRepresentationAttribute,
  type ComplexAttributePath,
  type JsonMapperParsed,
  type JsonMapperRepresentation,
  JsonMapperRepresentationType,
  type RepresentationAttribute,
  type SimpleAttributePath
} from '../modules/internal/jsonMapper/jsonMapper-types';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { generateStandardId } from '../schema/identifier';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { UnsupportedError } from '../config/errors';
import { type AttributeDefinition, entityType, id as idType, type ObjectAttribute, relationshipType } from '../schema/attribute-definition';
import { isNotEmptyField } from '../database/utils';
import { computeDefaultValue, formatValue, handleDefaultMarkings, handleRefEntities, type InputType } from './csv-mapper';
import { getHashesNames } from '../modules/internal/csvMapper/csvMapper-utils';
import { SYSTEM_USER } from '../utils/access';
import type { BasicStoreObject, StoreCommon } from '../types/store';
import { INPUT_MARKINGS } from '../schema/general';
import { isStixRelationshipExceptRef } from '../schema/stixRelationship';
import { BundleBuilder } from './bundle-creator';
import { handleInnerType } from '../domain/stixDomainObject';
import { createStixPatternSync } from '../python/pythonBridge';
import { logApp } from '../config/conf';
import { getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import type { AuthContext, AuthUser } from '../types/user';
import { fromRef, toRef } from '../schema/stixRefRelationship';

import { convertStoreToStix_2_1 } from '../database/stix-2-1-converter';

const format = (value: string | string[], def: AttributeDefinition, attribute: SimpleAttributePath | ComplexAttributePath | undefined) => {
  if (Array.isArray(value)) {
    if (def.multiple) {
      return value.map((val) => formatValue(val, def.type, attribute));
    }
    if (value.length > 1) {
      throw UnsupportedError('Only one value expected as attribute definition is not multiple', { value });
    }
    return formatValue(value[0], def.type, attribute);
  }
  return formatValue(value, def.type, attribute);
};

const extractComplexPathFromJson = async (
  base: JSON,
  metaData: Record<string, any>,
  record: JSON,
  attribute: ComplexAttributePath,
  attrDef?: AttributeDefinition
) => {
  const { variables, formula } = attribute;
  const data: any = { ...metaData };
  for (let i = 0; i < (variables ?? []).length; i += 1) {
    const variable = (variables ?? [])[i];
    const onBase = variable.independent === true;
    data[variable.variable] = JSONPath.JSONPath({
      path: variable.path,
      json: onBase ? base : record,
      wrap: attrDef?.multiple ?? false,
      flatten: true
    });
  }
  data.patternFromValue = (k: string, value: string) => {
    try {
      return createStixPatternSync(k, value);
    } catch {
      return 'invalid';
    }
  };
  data.extractWithRegexp = (regexp: string, groupIndex: number, value: string) => {
    const myRegexp = new RegExp(regexp, 'g');
    const matches = myRegexp.exec(value);
    if (matches != null) {
      return matches[groupIndex];
    }
    return value;
  };
  data.decisionMatrix = (value: any, defaultValue: any, matrix: { value: any, result: any }[]) => {
    for (let i = 0; i < matrix.length; i += 1) {
      const v = matrix[i];
      if (v.value === value) {
        return v.result;
      }
    }
    return defaultValue;
  };
  const val = await ejs.render(`<?- ${formula} ?>`, data, { delimiter: '?', async: true });
  return attrDef ? format(val, attrDef, attribute) : val;
};

const extractSimpleMultiPathFromJson = (
  base: JSON,
  record: JSON,
  attribute: SimpleAttributePath,
  attrDef: AttributeDefinition,
) => {
  const { path } = attribute;
  const onBase = attribute.independent === true;
  const val = JSONPath.JSONPath({
    path,
    json: onBase ? base : record,
    wrap: attrDef.multiple ?? false,
    flatten: true
  });
  if (Array.isArray(val)) {
    const formattedValues = val.map((value) => {
      const formatedData = format(value, attrDef, attribute);
      return formatedData ? String(formatedData).trim() : '';
    });
    if (attrDef.multiple) {
      return formattedValues;
    }
    return formattedValues.join(',');
  }
  const formattedValue = format(val, attrDef, attribute);
  if (attrDef.multiple) {
    return [formattedValue];
  }
  return formattedValue;
};

const extractSimpleIdentifierFromJson = (
  base: JSON,
  record: JSON,
  attribute: SimpleAttributePath,
  attrDef: AttributeDefinition,
) => {
  const value = extractSimpleMultiPathFromJson(base, record, attribute, attrDef);
  return Array.isArray(value) ? value.join('-') : value;
};

const extractIdentifierFromJson = (base: JSON, record: JSON, identifier: string, attrDef: AttributeDefinition) => {
  const identifiers = identifier.split(',');
  return identifiers.map((id) => extractSimpleIdentifierFromJson(base, record, { path: id }, attrDef)).join('-');
};

const orderedIdentifiersCombinations = <T>(arrays: T[][]): T[][] => {
  if (!arrays.length) {
    return [[]];
  }
  const firstArray = arrays[0];
  const restOfArrays = arrays.slice(1);
  const restCombinations = orderedIdentifiersCombinations(restOfArrays);
  const result: T[][] = [];
  for (let i = 0; i < firstArray.length; i += 1) {
    const item = firstArray[i];
    for (let i1 = 0; i1 < restCombinations.length; i1 += 1) {
      const combination = restCombinations[i1];
      result.push([item, ...combination]);
    }
  }
  return result;
};

const extractTargetIdentifierFromJson = (base: JSON, record: JSON, identifier: string, attrDef: AttributeDefinition): string[] => {
  const identifiers = identifier.split(',');
  const arrayOfMappedIdentifiers = [];
  for (let i = 0; i < identifiers.length; i += 1) {
    const id = identifiers[i];
    const value = extractSimpleMultiPathFromJson(base, record, { path: id }, attrDef);
    arrayOfMappedIdentifiers.push(Array.isArray(value) ? value : [value]);
  }
  return orderedIdentifiersCombinations(arrayOfMappedIdentifiers).map((comb) => comb.join('-'));
};

/* eslint-disable no-param-reassign */
const handleDirectAttribute = async (
  base: JSON,
  metaData: Record<string, any>,
  attribute: RepresentationAttribute,
  input: Record<string, InputType>,
  record: JSON,
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
  if (attribute.mode === 'simple' && attribute.attr_path) {
    const computedValue = extractSimpleMultiPathFromJson(base, record, attribute.attr_path, definition);
    if (isNotEmptyField(computedValue)) {
      if (isAttributeHash) {
        const values = (input.hashes ?? {}) as Record<string, any>;
        input.hashes = { ...values, [attribute.key]: computedValue };
      } else {
        input[attribute.key] = computedValue;
      }
    }
  }
  if (attribute.mode === 'complex' && attribute.complex_path) {
    const computedValue = await extractComplexPathFromJson(base, metaData, record, attribute.complex_path, definition);
    if (isNotEmptyField(computedValue)) {
      if (isAttributeHash) {
        const values = (input.hashes ?? {}) as Record<string, any>;
        input.hashes = { ...values, [attribute.key]: computedValue };
      } else {
        input[attribute.key] = computedValue;
      }
    }
  }
};

const handleBasedOnAttribute = async (
  context: AuthContext,
  user: AuthUser,
  base: JSON,
  attribute: BasedRepresentationAttribute,
  input: Record<string, InputType>,
  record: JSON,
  definition: AttributeDefinition,
  otherEntities: Map<string, Record<string, InputType>[]>,
  refEntities: Record<string, BasicStoreObject>,
  representation: JsonMapperRepresentation,
  chosenMarkings: string[],
) => {
  // region take care of default values
  if (definition && attribute.default_values && attribute.default_values.length > 0) {
    if (attribute.key !== INPUT_MARKINGS) {
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
    } else {
      const entitySetting = await getEntitySettingFromCache(context, representation.target.entity_type);
      handleDefaultMarkings(entitySetting, representation, input, refEntities, chosenMarkings, user);
    }
  }
  // endregion
  // region bind the value and override default if needed
  if (attribute.based_on && attribute.based_on.representations) {
    let entities;
    if (attribute.based_on.identifier) {
      const mappedIdentifiers = extractTargetIdentifierFromJson(base, record, attribute.based_on.identifier, definition);
      entities = attribute.based_on.representations
        .map((id) => otherEntities.get(id)).flat()
        .filter((e) => e !== undefined && mappedIdentifiers.includes(e.__identifier as string)) as Record<string, InputType>[];
    } else {
      entities = attribute.based_on.representations
        .map((id) => otherEntities.get(id)).flat()
        .filter((e) => e !== undefined) as Record<string, InputType>[];
    }
    if (entities.length > 0) {
      const entity_type = input[entityType.name] as string;
      // Is relation from or to (stix-core || stix-sighting)
      if (isStixRelationshipExceptRef(entity_type) && ['from', 'to'].includes(attribute.key)) {
        if (attribute.key === 'from') {
          input.__froms = entities.map((e) => ({
            from: e,
            fromType: e[entityType.name]
          }));
        }
        if (attribute.key === 'to') {
          input.__tos = entities.map((e) => ({
            to: e,
            toType: e[entityType.name]
          }));
        }
        // Is relation ref
      } else if (definition) {
        if (!definition.multiple && entities.length > 1) {
          throw UnsupportedError('Too many entities found for the mapping');
        }
        const refs = definition.multiple ? entities : entities[0];
        if (isNotEmptyField(refs)) {
          input[attribute.key] = refs;
        }
      }
    }
  }
  // endregion
};

const addResult = (representation: JsonMapperRepresentation, results: Map<string, Record<string, InputType>[]>, input: any) => {
  if (results.has(representation.id)) {
    const current = results.get(representation.id) ?? [];
    if (!current.map((c) => c.__identifier).includes(input.__identifier)) {
      current?.push(input);
      results.set(representation.id, current);
    }
  } else {
    results.set(representation.id, [input]);
  }
};

const computeOrderedRepresentations = (representations: JsonMapperRepresentation[]) => {
  const relationships = representations.filter((r) => r.type === JsonMapperRepresentationType.Relationship);
  const baseEntities = representations.filter((r) => {
    const isEntity = r.type === JsonMapperRepresentationType.Entity;
    const entityHasRefToRelations = !r.attributes.some((a) => {
      // Check for each attribute of entity if it has based_on representations
      return a.mode === 'base' && a.based_on?.representations?.some((b) => {
        // Check if at least one of based_on ref is a relation in CSV Mapper
        return relationships.some((rel) => rel.id === b);
      });
    });
    return isEntity && entityHasRefToRelations;
  }).sort((r1, r2) => r1.attributes.filter((attr) => attr.mode === 'base' && attr.based_on).length
      - r2.attributes.filter((attr) => attr.mode === 'base' && attr.based_on).length);
  // representations thar are not in representationEntitiesWithoutBasedOnRelationships
  const basedOnEntities = representations
    .filter((r) => r.type === JsonMapperRepresentationType.Entity && !baseEntities.some((r1) => r1.id === r.id));
  return [baseEntities, basedOnEntities, relationships];
};

const jsonMappingExecution = async (context: AuthContext, user: AuthUser, data: string | object, mapper: JsonMapperParsed, variables: Record<string, unknown> = {}) => {
  const refEntities = await handleRefEntities(context, SYSTEM_USER, mapper);
  const chosenMarkings = mapper.user_chosen_markings ?? [];
  const results = new Map<string, Record<string, InputType>[]>();
  const baseJson = typeof data === 'string' ? JSON.parse(data) : data;
  const baseArray = Array.isArray(baseJson) ? baseJson : [baseJson];
  for (let index = 0; index < baseArray.length; index += 1) {
    const element = baseArray[index];
    // region variables
    const dataVars: any = { ...variables };
    for (let indexVar = 0; indexVar < (mapper.variables ?? []).length; indexVar += 1) {
      const variable = (mapper.variables ?? [])[indexVar];
      dataVars[variable.name] = await extractComplexPathFromJson(baseJson, {}, element, variable.path);
    }
    // endregion
    // region representations
    const orderedRepresentations = computeOrderedRepresentations(mapper.representations);
    for (let orderIndex = 0; orderIndex < orderedRepresentations.length; orderIndex += 1) {
      const representationsArray = orderedRepresentations[orderIndex];
      for (let i = 0; i < representationsArray.length; i += 1) {
        const representation = representationsArray[i];
        const { entity_type, path: base_path } = representation.target;
        const hashesNames = getHashesNames(entity_type);
        const baseData = JSONPath.JSONPath({ path: base_path, json: element, flatten: true });
        const baseDatas = (Array.isArray(baseData) ? baseData : [baseData]);
        for (let baseInfo = 0; baseInfo < baseDatas.length; baseInfo += 1) {
          let input: any = {};
          input[entityType.name] = entity_type;
          if (representation.type === JsonMapperRepresentationType.Relationship) {
            input[relationshipType.name] = entity_type;
          }
          input = handleInnerType(input, entity_type);
          const baseDatum = baseDatas[baseInfo];
          for (let attr = 0; attr < representation.attributes.length; attr += 1) {
            const attribute = representation.attributes[attr];
            let attributeKey = attribute.key;
            if (hashesNames.includes(attribute.key)) {
              attributeKey = 'hashes';
            }
            const refDef = schemaRelationsRefDefinition.getRelationRef(entity_type, attributeKey);
            if (attribute.mode === 'simple' || attribute.mode === 'complex') {
              const attributeDef = schemaAttributesDefinition.getAttribute(entity_type, attributeKey);
              if (attributeDef) {
                if (hashesNames.includes(attribute.key)) {
                  const definitionHash = (attributeDef as ObjectAttribute).mappings.find((definition) => (definition.name === attribute.key));
                  if (definitionHash) {
                    await handleDirectAttribute(baseJson, dataVars, attribute, input, baseDatum, attributeDef, hashesNames);
                  }
                } else {
                  await handleDirectAttribute(baseJson, dataVars, attribute, input, baseDatum, attributeDef, []);
                }
              } else {
                throw UnsupportedError('Unknown schema for attribute:', { attribute });
              }
            } else if (attribute.mode === 'base') {
              if (refDef) {
                await handleBasedOnAttribute(context, user, baseJson, attribute, input, baseDatum, refDef, results, refEntities, representation, chosenMarkings);
              } else if (attribute.key === 'from') {
                await handleBasedOnAttribute(context, user, baseJson, attribute, input, baseDatum, fromRef, results, refEntities, representation, chosenMarkings);
              } else if (attribute.key === 'to') {
                await handleBasedOnAttribute(context, user, baseJson, attribute, input, baseDatum, toRef, results, refEntities, representation, chosenMarkings);
              } else {
                throw UnsupportedError('Unknown schema for attribute:', { attribute });
              }
            } else {
              throw UnsupportedError('Unknown schema for attribute:', { attribute });
            }
          }
          // Take care of explicit relations cardinality
          if (input.__froms && input.__tos) {
            for (let fromIndex = 0; fromIndex < input.__froms.length; fromIndex += 1) {
              const { from, fromType } = input.__froms[fromIndex];
              for (let toIndex = 0; toIndex < input.__tos.length; toIndex += 1) {
                const { to, toType } = input.__tos[toIndex];
                const inputNew = structuredClone(input);
                inputNew.__identifier = uuidv4();
                inputNew.from = from;
                inputNew.fromType = fromType;
                inputNew.to = to;
                inputNew.toType = toType;
                inputNew.standard_id = generateStandardId(inputNew.entity_type, inputNew);
                addResult(representation, results, inputNew);
              }
            }
          } else {
            input.standard_id = generateStandardId(entity_type, input);
            if (representation.identifier) {
              const identifier = extractIdentifierFromJson(baseJson, baseDatum, representation.identifier, idType);
              input.__identifier = identifier ? identifier.trim() : identifier;
            } else {
              input.__identifier = uuidv4();
            }
            addResult(representation, results, input);
          }
        }
      }
    }
    // endregion
  }
  // Generate the final bundle
  const objects = Array.from(results.values()).flat();
  const stixObjects = objects.map((e) => {
    try {
      return convertStoreToStix_2_1(e as unknown as StoreCommon);
    } catch (_err) {
      logApp.error('JSON mapper convert error', { cause: e });
    }
    return null;
  }).filter((elem) => isNotEmptyField(elem));
  const bundleBuilder = new BundleBuilder();
  bundleBuilder.addObjects(stixObjects);
  return bundleBuilder.build();
};

export default jsonMappingExecution;
