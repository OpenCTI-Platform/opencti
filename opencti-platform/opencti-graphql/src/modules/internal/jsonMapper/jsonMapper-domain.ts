import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../../types/user';
import { FilterMode, type QueryJsonMappersArgs } from '../../../generated/graphql';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER, type JsonMapperRepresentation } from './jsonMapper-types';
import { extractContentFrom } from '../../../utils/fileToContent';
import { createEntity } from '../../../database/middleware';
import { publishUserAction } from '../../../listener/UserActionListener';
import { checkConfigurationImport } from '../../workspace/workspace-domain';
import { convertRepresentationsIds } from '../csvMapper/csvMapper-utils';
import pjson from '../../../../package.json';
import { type BasicStoreEntityIngestionJson, ENTITY_TYPE_INGESTION_JSON } from '../../ingestion/ingestion-types';
import { FunctionalError } from '../../../config/errors';
import { deleteInternalObject } from '../../../domain/internalObject';

export const findById = async (context: AuthContext, user: AuthUser, jsonMapperId: string) => {
  return storeLoadById<BasicStoreEntityJsonMapper>(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryJsonMappersArgs) => {
  return listEntitiesPaginated<BasicStoreEntityJsonMapper>(context, user, [ENTITY_TYPE_JSON_MAPPER], opts);
};

export const jsonMapperImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  checkConfigurationImport('jsonMapper', parsedData);
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
      variables: JSON.parse(variables),
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
  const ingesters = await listAllEntities<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON], opts);
  // prevent deletion if an ingester uses the mapper
  if (ingesters.length > 0) {
    throw FunctionalError('Cannot delete this JSON Mapper: it is used by one or more IngestionJson ingester(s)', { id: jsonMapperId });
  }

  return deleteInternalObject(context, user, jsonMapperId, ENTITY_TYPE_JSON_MAPPER);
};
