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
import type { BasicStoreEntityJsonMapper, JsonMapperParsed, JsonMapperRepresentation, JsonMapperResolved } from './jsonMapper-types';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_REFS } from '../../../domain/attribute-utils';
import { internalFindByIds } from '../../../database/middleware-loader';
import type { BasicStoreEntity } from '../../../types/store';
import { extractRepresentative } from '../../../database/entity-representative';
import { FunctionalError } from '../../../config/errors';

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

  const entities = await internalFindByIds<BasicStoreEntity>(context, user, refDefaultValues);
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
              : val
          };
        })
      }))
    })),
  };
};

export const getJsonMapperErrorMessage = async (_context: AuthContext, _user: AuthUser, _jsonMapper: BasicStoreEntityJsonMapper) => {
  try {
    return null; // no error
  } catch (error) {
    if (error instanceof Error) {
      return error.message;
    }
    return 'Unknown error';
  }
};
