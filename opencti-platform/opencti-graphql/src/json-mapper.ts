import * as JSONPath from 'jsonpath-plus';

import './modules';
import fs from 'node:fs';
import { v4 as uuidv4 } from 'uuid';
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
import { type AttributeDefinition, entityType, id as idType, type ObjectAttribute, relationshipType } from './schema/attribute-definition';
import { isEmptyField, isNotEmptyField } from './database/utils';
import { computeDefaultValue, formatValue, handleRefEntities, type InputType } from './parser/csv-mapper';
import { getHashesNames } from './modules/internal/csvMapper/csvMapper-utils';
import { executionContext, SYSTEM_USER } from './utils/access';
import type { BasicStoreObject, StoreCommon } from './types/store';
import { INPUT_MARKINGS } from './schema/general';
import { isStixRelationshipExceptRef } from './schema/stixRelationship';
import { convertStoreToStix } from './database/stix-converter';
import { BundleBuilder } from './parser/bundle-creator';
import { handleInnerType } from './domain/stixDomainObject';
import { createStixPatternSync } from './python/pythonBridge';
import { from as fromDef, to as toDef } from './schema/stixRefRelationship';

export const isComplexPath = (attribute: AttributePath | ComplexPath): attribute is ComplexPath => 'complex' in attribute;

const format = (value: string | string[], def: AttributeDefinition, attribute: AttributePath | ComplexPath | undefined) => {
  if (Array.isArray(value)) {
    if (def.multiple) {
      return value.map((val) => formatValue(val, def.type, attribute));
    }
    if (value.length > 1) {
      throw UnsupportedError('Only one response expected');
    }
    return formatValue(value[0], def.type, attribute);
  }
  return formatValue(value, def.type, attribute);
};

const extractValueFromJson = async (
  base: JSON,
  metaData: Record<string, any>,
  record: JSON,
  attribute: AttributePath | ComplexPath,
  attrDef?: AttributeDefinition
) => {
  if (isComplexPath(attribute)) {
    const { variables, formula } = attribute.complex;
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
  }
  if (!attribute.path) {
    throw UnsupportedError('extractValueFromJson path must be defined');
  }
  const { path } = attribute;
  const onBase = attribute.independent === true;
  const val = JSONPath.JSONPath({
    path,
    json: onBase ? base : record,
    wrap: attrDef?.multiple ?? false,
    flatten: true
  });
  return attrDef ? format(val, attrDef, attribute) : val;
};

/* eslint-disable no-param-reassign */
const handleDirectAttribute = async (
  base: JSON,
  metaData: Record<string, any>,
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
    const computedValue = await extractValueFromJson(base, metaData, record, attribute.attr_path, definition);
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
  base: JSON,
  metaData: Record<string, any>,
  attribute: JsonMapperRepresentationAttribute,
  input: Record<string, InputType>,
  record: JSON,
  definition: AttributeDefinition,
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
    // region fetch entities
    let entities;
    if (attribute.based_on.identifier_path) {
      const computedValue = await extractValueFromJson(base, metaData, record, attribute.based_on.identifier_path, definition);
      const compareValues = Array.isArray(computedValue) ? computedValue : [computedValue];
      entities = (attribute.based_on.representations ?? [])
        .map((id) => otherEntities.get(id)).flat()
        .filter((e) => e !== undefined && compareValues.includes(e.__identifier as string)) as Record<string, InputType>[];
    } else {
      entities = (attribute.based_on.representations ?? [])
        .map((id) => otherEntities.get(id)).flat()
        .filter((e) => e !== undefined) as Record<string, InputType>[];
    }
    // endregion
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
  const start = new Date().getTime();
  const context = executionContext('JsonMapper');
  const refEntities = await handleRefEntities(context, SYSTEM_USER, mapper);
  const results = new Map<string, Record<string, InputType>[]>();
  const baseJson = JSON.parse(data);
  const baseArray = Array.isArray(baseJson) ? baseJson : [baseJson];
  for (let index = 0; index < baseArray.length; index += 1) {
    const element = baseArray[index];
    // variables
    const dataVars: any = { externalUri: 'https://4.233.151.63:444' };
    for (let indexVar = 0; indexVar < (mapper.variables ?? []).length; indexVar += 1) {
      const variable = (mapper.variables ?? [])[indexVar];
      dataVars[variable.name] = await extractValueFromJson(baseJson, {}, element, variable.path);
    }
    // representations
    for (let i = 0; i < (mapper.representations ?? []).length; i += 1) {
      const representation = (mapper.representations ?? [])[i];
      const { entity_type } = representation.target;
      const hashesNames = getHashesNames(entity_type);
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
              const definitionHash = (attributeDef as ObjectAttribute).mappings.find((definition) => (definition.name === attribute.key));
              if (definitionHash) {
                await handleDirectAttribute(baseJson, dataVars, attribute, input, baseDatum, attributeDef, hashesNames);
              }
            } else {
              await handleDirectAttribute(baseJson, dataVars, attribute, input, baseDatum, attributeDef, []);
            }
          } else if (refDef) {
            await handleBasedOnAttribute(baseJson, dataVars, attribute, input, baseDatum, refDef, results, refEntities);
          } else if (attribute.key === 'from') {
            await handleBasedOnAttribute(baseJson, dataVars, attribute, input, baseDatum, fromDef, results, refEntities);
          } else if (attribute.key === 'to') {
            await handleBasedOnAttribute(baseJson, dataVars, attribute, input, baseDatum, toDef, results, refEntities);
          } else {
            console.log('Unknown schema for attribute:', { attribute });
            throw UnsupportedError('Unknown schema for attribute:', { attribute });
          }
        }
        // console.log(input);
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
            input.__identifier = await extractValueFromJson(baseJson, dataVars, baseDatum, representation.identifier, idType) as string;
          } else {
            input.__identifier = uuidv4();
          }
          addResult(representation, results, input);
        }
      }
    }
  }
  // Generate the final bundle
  const objects = Array.from(results.values()).flat();
  const stixObjects = objects.map((e) => convertStoreToStix(e as unknown as StoreCommon));
  const bundleBuilder = new BundleBuilder();
  bundleBuilder.addObjects(stixObjects);
  const bundle = bundleBuilder.build();
  console.log(`Event built in ${new Date().getTime() - start} ms with ${bundle.objects.length} objects`);
  fs.writeFileSync('./src/temp.json', JSON.stringify(bundle), {});
};

export default testJsonMapper;
