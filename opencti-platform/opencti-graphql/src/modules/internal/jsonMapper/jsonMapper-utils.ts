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

import type { AuthContext, AuthUser } from '../../../types/user';
import {
  type BasedRepresentationAttribute,
  type BasicStoreEntityJsonMapper,
  type JsonMapperParsed,
  type JsonMapperRepresentation,
  JsonMapperRepresentationType,
  type JsonMapperResolved,
} from './jsonMapper-types';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_REFS } from '../../../domain/attribute-utils';
import { internalFindByIds } from '../../../database/middleware-loader';
import type { BasicStoreEntity } from '../../../types/store';
import { extractRepresentative } from '../../../database/entity-representative';
import { FunctionalError } from '../../../config/errors';
import { fillDefaultValues, getEntitySettingFromCache } from '../../entitySetting/entitySetting-utils';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { isEmptyField, isNotEmptyField } from '../../../database/utils';
import { representationLabel } from '../mapper-utils';
import { isStixRelationshipExceptRef } from '../../../schema/stixRelationship';
import { isStixObject } from '../../../schema/stixCoreObject';

export const parseJsonMapper = (mapper: any): JsonMapperParsed => {
  let representations: JsonMapperRepresentation[] = [];
  if (typeof mapper?.representations === 'string') {
    try {
      representations = JSON.parse(mapper.representations);
    } catch (error) {
      throw FunctionalError('Could not parse JSON mapper: representations is not a valid JSON', { name: mapper?.name, error });
    }
  } else {
    representations = mapper?.representations ?? [];
  }

  return {
    ...mapper,
    representations,
  };
};

export const parseJsonMapperWithDefaultValues = async (context: AuthContext, user: AuthUser, mapper: any): Promise<JsonMapperResolved> => {
  if (typeof mapper?.representations !== 'string') {
    return mapper;
  }

  const { representations: parsedRepresentations } = parseJsonMapper(mapper);
  const refAttributesIndexes: string[] = [];
  const refDefaultValues = parsedRepresentations.flatMap((representation, i) => {
    const refsDefinition = schemaRelationsRefDefinition
      .getRelationsRef(representation.target.entity_type)
      .filter((ref) => !INTERNAL_REFS.includes(ref.name));
    return representation.attributes.flatMap((attribute, j) => {
      if (
        attribute.default_values
        && attribute.key !== 'objectMarking'
        && refsDefinition.map((ref) => ref.name).includes(attribute.key)
      ) {
        refAttributesIndexes.push(`${i}-${j}`);
        return attribute.default_values;
      }
      return [];
    });
  });

  const entities = await internalFindByIds<BasicStoreEntity>(context, user, refDefaultValues) as BasicStoreEntity[];
  return {
    ...mapper,
    representations: parsedRepresentations.map((representation, i) => ({
      ...representation,
      attributes: representation.attributes.map((attribute, j) => ({
        ...attribute,
        default_values: attribute.default_values?.map((val) => {
          const refEntity = entities.find((e) => e.id === val);
          const representative = refEntity ? extractRepresentative(refEntity).main : undefined;

          return {
            id: val,
            name: refAttributesIndexes.includes(`${i}-${j}`) && representative
              ? representative
              : val,
          };
        }),
      })),
    })),
  };
};

// TS typeguard on JsonMapperRepresentation
const isJsonMapperRepresentation = (object: any): object is JsonMapperRepresentation => {
  // this is a basic validation; TODO: json validation
  return object.id && (object.type === JsonMapperRepresentationType.Entity || object.type === JsonMapperRepresentationType.Relationship);
};

export const isValidJsonRepresentationType = (representation: JsonMapperRepresentation) => {
  if (isEmptyField(representation.target.path)) {
    throw FunctionalError('Missing entity path mapping');
  }
  if (representation.type === JsonMapperRepresentationType.Relationship) {
    if (!isStixRelationshipExceptRef(representation.target.entity_type)) {
      throw FunctionalError('Unknown relationship', { type: representation.target.entity_type });
    }
  } else if (representation.type === JsonMapperRepresentationType.Entity) {
    if (!isStixObject(representation.target.entity_type)) {
      throw FunctionalError('Unknown entity', { type: representation.target.entity_type });
    }
  } else {
    throw FunctionalError('Unknown representation type', { type: representation.type });
  }
};

export const validateJsonMapper = async (context: AuthContext, user: AuthUser, mapper: JsonMapperParsed) => {
  if (!Array.isArray(mapper.representations) || mapper.representations.some((rep) => !isJsonMapperRepresentation(rep))) {
    throw FunctionalError('JSON mapper representations is not an array of JsonMapperRepresentation objects', { mapper_name: mapper.name });
  }

  // consider empty csv mapper as invalid to avoid being used in the importer
  if (mapper.representations.length === 0) {
    throw FunctionalError('JSON Mapper has no representation', { mapper_name: mapper.name });
  }

  await Promise.all(Array.from(mapper.representations.entries()).map(async ([idx, representation]) => {
    // Validate target type
    isValidJsonRepresentationType(representation);

    // Validate required attributes
    const entitySetting = await getEntitySettingFromCache(context, representation.target.entity_type);
    const defaultValues = fillDefaultValues(user, {}, entitySetting);
    const attributesDefs = [
      ...schemaAttributesDefinition.getAttributes(representation.target.entity_type).values(),
    ].map((def) => ({
      name: def.name,
      mandatory: def.mandatoryType === 'external',
      multiple: def.multiple,
    }));
    const refsDefs = [
      ...schemaRelationsRefDefinition.getRelationsRef(representation.target.entity_type),
    ].map((def) => ({
      name: def.name,
      mandatory: def.mandatoryType === 'external',
      multiple: def.multiple,
    }));
    [...attributesDefs, ...refsDefs].filter((schemaAttribute) => schemaAttribute.mandatory)
      .forEach((schemaAttribute) => {
        const attribute = representation.attributes.find((a) => schemaAttribute.name === a.key);
        let isPathEmpty = true;
        if (attribute?.mode === 'simple') {
          isPathEmpty = isEmptyField(attribute?.attr_path);
        }
        if (attribute?.mode === 'complex') {
          isPathEmpty = isEmptyField(attribute?.complex_path);
        }
        const isDefaultValueEmpty = isEmptyField(defaultValues[schemaAttribute.name]);
        const isAttributeDefaultValueEmpty = isEmptyField(attribute?.default_values);
        if (isPathEmpty && isDefaultValueEmpty && isAttributeDefaultValueEmpty) {
          throw FunctionalError('Missing values for required attribute', {
            representation: representationLabel(idx, representation),
            attribute: schemaAttribute.name,
          });
        }
      });

    // Validate representation attribute configuration
    representation.attributes.forEach((attribute) => {
      // Validate based on configuration
      if (attribute.mode === 'base') {
        const schemaAttribute = [...attributesDefs, ...refsDefs].find((attr) => attr.name === attribute.key);
        // Multiple
        if (!schemaAttribute?.multiple && (attribute.based_on?.representations?.length ?? 0) > 1) {
          throw FunctionalError('Attribute can\'t be multiple', { representation: representationLabel(idx, representation), attribute: attribute.key });
        }
        // Auto reference
        if (attribute.based_on?.representations?.includes(representation.id)) {
          throw FunctionalError('Can\'t reference the representation itself', { representation: representationLabel(idx, representation), attribute: attribute.key });
        }
        // Possible cycle
        const representationRefs = mapper.representations.filter((r) => attribute.mode === 'base' && attribute.based_on?.representations?.includes(r.id));
        const attributeRepresentationRefs = representationRefs.map((rr) => rr.attributes
          .filter((rra) => rra.mode === 'base' && isNotEmptyField(rra.based_on?.representations))
          .map((rra) => (rra as BasedRepresentationAttribute).based_on?.representations as string[] ?? [])
          .flat())
          .flat();
        if (attributeRepresentationRefs.includes(representation.id)) {
          throw FunctionalError('Reference cycle found', { representation: representationLabel(idx, representation) });
        }
      }
    });
  }));
};

export const getJsonMapperErrorMessage = async (context: AuthContext, user: AuthUser, jsonMapper: BasicStoreEntityJsonMapper) => {
  try {
    const parsedMapper = parseJsonMapper(jsonMapper); // can throw JSON parsing errors
    await validateJsonMapper(context, user, parsedMapper); // can throw model validation error
    return null; // no error
  } catch (error) {
    if (error instanceof Error) {
      return error.message;
    }
    return 'Unknown error';
  }
};
