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

import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../../types/user';
import { type EditInput, FilterMode, type JsonMapperAddInput, type QueryJsonMappersArgs } from '../../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER, type JsonMapperRepresentation, type StoreEntityJsonMapper } from './jsonMapper-types';
import { extractContentFrom } from '../../../utils/fileToContent';
import { createEntity } from '../../../database/middleware';
import { publishUserAction } from '../../../listener/UserActionListener';
import pjson from '../../../../package.json';
import { type BasicStoreEntityIngestionJson, ENTITY_TYPE_INGESTION_JSON } from '../../ingestion/ingestion-types';
import { FunctionalError } from '../../../config/errors';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../../domain/internalObject';
import { parseJsonMapper, parseJsonMapperWithDefaultValues, validateJsonMapper } from './jsonMapper-utils';
import type { FileUploadData } from '../../../database/file-storage';
import { streamConverter } from '../../../database/file-storage';
import jsonMappingExecution from '../../../parser/json-mapper';
import { convertRepresentationsIds } from '../mapper-utils';
import { isCompatibleVersionWithMinimal } from '../../../utils/version';

const MINIMAL_COMPATIBLE_VERSION = '6.6.0';

export const findById = async (context: AuthContext, user: AuthUser, jsonMapperId: string) => {
  return storeLoadById<BasicStoreEntityJsonMapper>(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const findJsonMapperPaginated = (context: AuthContext, user: AuthUser, opts: QueryJsonMappersArgs) => {
  return pageEntitiesConnection<BasicStoreEntityJsonMapper>(context, user, [ENTITY_TYPE_JSON_MAPPER], opts);
};

export const jsonMapperTest = async (context: AuthContext, user: AuthUser, configuration: string, fileUpload: Promise<FileUploadData>) => {
  let parsedConfiguration;
  try {
    parsedConfiguration = JSON.parse(configuration);
  } catch (error) {
    throw FunctionalError('Could not parse CSV mapper configuration', { error });
  }
  const jsonMapperParsed = parseJsonMapper(parsedConfiguration);
  const { createReadStream } = await fileUpload;
  const data: string = await streamConverter(createReadStream());
  const stixBundle = await jsonMappingExecution(context, user, data, jsonMapperParsed);
  const allObjects = stixBundle.objects;
  return {
    objects: JSON.stringify(allObjects.slice(0, 50), null, 2), // Max 50 records to display
    nbRelationships: allObjects.filter((object) => object.type === 'relationship').length,
    nbEntities: allObjects.filter((object) => object.type !== 'relationship').length,
    state: '-',
  };
};

export const getParsedRepresentations = async (context: AuthContext, user: AuthUser, jsonMapper: BasicStoreEntityJsonMapper) => {
  const parsedMapper = await parseJsonMapperWithDefaultValues(context, user, jsonMapper);
  return parsedMapper.representations;
};

export const jsonMapperImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  // check platform version compatibility
  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }
  const config = parsedData.configuration;
  const importData = {
    name: config.name,
    representations: JSON.stringify(config.representations),
    variables: JSON.stringify(config.variables),
  };
  const importMapper = await createEntity(context, user, importData, ENTITY_TYPE_JSON_MAPPER);
  const importMapperId = importMapper.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import ${importMapper.name} json mapper`,
    context_data: {
      id: importMapperId,
      entity_type: ENTITY_TYPE_JSON_MAPPER,
      input: importMapper,
    },
  });
  return importMapperId;
};

export const jsonMapperExport = async (context: AuthContext, user: AuthUser, jsonMapper: BasicStoreEntityJsonMapper) => {
  const { name, representations, variables } = jsonMapper;
  const parsedRepresentations: JsonMapperRepresentation[] = JSON.parse(representations);
  await convertRepresentationsIds(context, user, parsedRepresentations, 'internal');
  return JSON.stringify({
    openCTI_version: pjson.version,
    type: 'jsonMapper',
    configuration: {
      name,
      variables: variables ? JSON.parse(variables) : [],
      representations: parsedRepresentations,
    }
  });
};

export const deleteJsonMapper = async (context: AuthContext, user: AuthUser, jsonMapperId: string) => {
  const opts = {
    filters: {
      mode: FilterMode.Or,
      filterGroups: [],
      filters: [{ key: ['json_mapper_id'], values: [jsonMapperId] }]
    }
  };
  const ingesters = await fullEntitiesList<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON], opts);
  // prevent deletion if an ingester uses the mapper
  if (ingesters.length > 0) {
    throw FunctionalError('Cannot delete this JSON Mapper: it is used by one or more IngestionJson ingester(s)', { id: jsonMapperId });
  }

  return deleteInternalObject(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const createJsonMapper = async (context: AuthContext, user: AuthUser, jsonMapperInput: JsonMapperAddInput) => {
  // attempt to parse and validate the mapper representations ; this can throw errors
  const parsedMapper = parseJsonMapper(jsonMapperInput);
  await validateJsonMapper(context, user, parsedMapper);

  return createInternalObject<StoreEntityJsonMapper>(context, user, jsonMapperInput, ENTITY_TYPE_JSON_MAPPER);
};

export const fieldPatchJsonMapper = async (context: AuthContext, user: AuthUser, jsonMapperId: string, input: EditInput[]) => {
  return editInternalObject<StoreEntityJsonMapper>(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER, input);
};
