import * as JSONPath from 'jsonpath-plus';

import './modules';
import fs from 'node:fs';
import ejs from 'ejs';
import {
  type AttributePath,
  type ComplexPath,
  type JsonMapperParsed,
  type JsonMapperRepresentation,
  type JsonMapperRepresentationAttribute,
  JsonMapperRepresentationType
} from './modules/internal/jsonMapper/jsonMapper-types';
import { schemaAttributesDefinition } from './schema/schema-attributes';
import { generateStandardId } from './schema/identifier';
import { schemaRelationsRefDefinition } from './schema/schema-relationsRef';
import { UnsupportedError } from './config/errors';
import { type AttributeDefinition, entityType, type ObjectAttribute, relationshipType } from './schema/attribute-definition';
import { isEmptyField, isNotEmptyField } from './database/utils';
import { computeDefaultValue, handleRefEntities, type InputType } from './parser/csv-mapper';
import { getHashesNames } from './modules/internal/csvMapper/csvMapper-utils';
import { executionContext, SYSTEM_USER } from './utils/access';
import type { BasicStoreObject, StoreCommon } from './types/store';
import { INPUT_MARKINGS } from './schema/general';
import { isStixRelationshipExceptRef } from './schema/stixRelationship';
import { convertStoreToStix } from './database/stix-converter';
import { BundleBuilder } from './parser/bundle-creator';
import { handleInnerType } from './domain/stixDomainObject';
import { createStixPatternSync } from './python/pythonBridge';
import type { AuthContext } from './types/user';

export const isComplexPath = (attribute: AttributePath | ComplexPath): attribute is ComplexPath => 'complex' in attribute;

const extractValueFromJson = async (
  iter: number,
  record: JSON,
  attribute: AttributePath | ComplexPath,
  wrap: boolean
) => {
  if (isComplexPath(attribute)) {
    const { variables, formula } = attribute.complex;
    const data: any = {};
    for (let i = 0; i < variables.length; i += 1) {
      const variable = variables[i];
      const p = variable.path.replaceAll('{iter}', iter.toString());
      data[variable.variable] = JSONPath.JSONPath({
        path: p,
        json: record,
        wrap,
        flatten: true
      });
    }
    // Enrich functions
    data.patternFromValue = (k: string, value: string) => {
      try {
        return createStixPatternSync(k, value);
      } catch {
        return 'invalid';
      }
    };
    return ejs.render(`<?- ${formula} ?>`, data, { delimiter: '?', async: true });
  }
  if (!attribute.path) {
    throw UnsupportedError('extractValueFromJson path must be defined');
  }
  const { path } = attribute;
  const p = path.replaceAll('{iter}', iter.toString());
  return JSONPath.JSONPath({
    path: p,
    json: record,
    wrap,
    flatten: true
  });
};

/* eslint-disable no-param-reassign */
const handleDirectAttribute = async (
  context: AuthContext,
  iter: number,
  attribute: JsonMapperRepresentationAttribute,
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
  if (attribute.attr_path) {
    const computedValue = await extractValueFromJson(iter, record, attribute.attr_path, definition.multiple);
    // const computedValue = computeValue(recordValue, attribute.column, definition);
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

const handleBasedOnAttribute = async (
  context: AuthContext,
  iter: number,
  attribute: JsonMapperRepresentationAttribute,
  input: Record<string, InputType>,
  record: JSON,
  definition: AttributeDefinition | null,
  otherEntities: Map<string, Record<string, InputType>[]>,
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
    let entities;
    if (attribute.based_on.identifier_path) {
      const computedValue = await extractValueFromJson(iter, record, attribute.based_on.identifier_path, definition?.multiple ?? false);
      const compareValues = Array.isArray(computedValue) ? computedValue : [computedValue];
      entities = (attribute.based_on.representations ?? [])
        .map((id) => otherEntities.get(id)).flat()
        .filter((e) => e !== undefined && compareValues.includes(e.__identifier)) as Record<string, InputType>[];
    } else {
      entities = (attribute.based_on.representations ?? [])
        .map((id) => otherEntities.get(id)).flat()
        .filter((e) => e !== undefined) as Record<string, InputType>[];
    }
    // console.log(attribute.key, otherEntities);
    if (entities.length > 0) {
      const entity_type = input[entityType.name] as string;
      // Is relation from or to (stix-core || stix-sighting)
      if (isStixRelationshipExceptRef(entity_type) && ['from', 'to'].includes(attribute.key)) {
        if (entities.length > 1) {
          throw UnsupportedError('Too many entities found for the mapping');
        }
        if (attribute.key === 'from') {
          const entity = entities[0];
          // console.log(attribute.key, entity);
          if (isNotEmptyField(entity)) {
            input.from = entity;
            input.fromType = entity[entityType.name];
          }
        } else if (attribute.key === 'to') {
          const entity = entities[0];
          // console.log(attribute.key, entity);
          if (isNotEmptyField(entity)) {
            input.to = entity;
            input.toType = entity[entityType.name];
          }
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

const testJsonMapper = async (data: string, mapper: JsonMapperParsed) => {
  const context = executionContext('JsonMapper');
  const refEntities = await handleRefEntities(context, SYSTEM_USER, mapper);
  const results = new Map<string, Record<string, InputType>[]>();
  const baseJson = JSON.parse(data);
  const baseArray = Array.isArray(baseJson) ? baseJson : [baseJson];
  for (let index = 0; index < baseArray.length; index += 1) {
    const element = baseArray[index];
    for (let i = 0; i < (mapper.representations ?? []).length; i += 1) {
      const representation = (mapper.representations ?? [])[i];
      const { entity_type } = representation.target;
      const hashesNames = getHashesNames(entity_type);
      // console.log('baseJson', baseJson);
      // console.log('representation.base_path.path', representation.base_path.path);
      const baseData = JSONPath.JSONPath({ path: representation.base_path.path, json: element, flatten: true });
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
          const attributeDef = schemaAttributesDefinition.getAttribute(entity_type, attributeKey);
          const refDef = schemaRelationsRefDefinition.getRelationRef(entity_type, attributeKey);
          // console.log(hashesNames, test);
          if (attributeDef) {
            if (hashesNames.includes(attribute.key)) {
              const definitionHash = (attributeDef as ObjectAttribute).mappings
                .find((definition) => (definition.name === attribute.key));
              if (definitionHash) {
                await handleDirectAttribute(context, baseInfo, attribute, input, baseDatum, attributeDef, hashesNames);
              }
            } else {
              await handleDirectAttribute(context, baseInfo, attribute, input, baseDatum, attributeDef, []);
            }
          } else if (refDef || ['from', 'to'].includes(attribute.key)) {
            await handleBasedOnAttribute(context, baseInfo, attribute, input, baseDatum, refDef, results, refEntities);
          } else {
            console.log('Unknown schema for attribute:', { attribute });
            throw UnsupportedError('Unknown schema for attribute:', { attribute });
          }
        }
        // console.log(entity_type, input);
        input.standard_id = generateStandardId(entity_type, input);
        if (representation.identifier) {
          input.__identifier = await extractValueFromJson(baseInfo, baseDatum, representation.identifier, false);
        }
        addResult(representation, results, input);
      }
      // console.log('buildElements', JSON.stringify(results.values()));
    }
  }

  const stixObjects = Array.from(results.values()).flat()
    .map((e) => convertStoreToStix(e as unknown as StoreCommon));
  const bundleBuilder = new BundleBuilder();
  bundleBuilder.addObjects(stixObjects);
  const bundle = bundleBuilder.build();
  fs.writeFileSync('./src/temp.json', JSON.stringify(bundle), {});
};

export default testJsonMapper;
