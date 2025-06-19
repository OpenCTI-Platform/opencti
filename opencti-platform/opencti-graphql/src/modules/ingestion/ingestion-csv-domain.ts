import { v4 as uuid } from 'uuid';
import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityIngestionCsv, ENTITY_TYPE_INGESTION_CSV } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { type CsvMapperTestResult, type EditInput, type IngestionCsvAddInput, IngestionCsvMapperType } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS, isFeatureEnabled, PLATFORM_VERSION } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type BasicStoreEntityCsvMapper, type CsvMapperParsed, type CsvMapperRepresentation, ENTITY_TYPE_CSV_MAPPER } from '../internal/csvMapper/csvMapper-types';
import { type CsvBundlerTestOpts, getCsvTestObjects, removeHeaderFromFullFile } from '../../parser/csv-bundler';
import { findById as findCsvMapperById, transformCsvMapperConfig } from '../internal/csvMapper/csvMapper-domain';
import { parseCsvMapper } from '../internal/csvMapper/csvMapper-utils';
import { type GetHttpClient, getHttpClient, OpenCTIHeaders } from '../../utils/http-client';
import { verifyIngestionAuthenticationContent } from './ingestion-common';
import { IngestionAuthType } from '../../generated/graphql';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import type { StixObject } from '../../types/stix-2-1-common';
import { extractContentFrom } from '../../utils/fileToContent';
import { isCompatibleVersionWithMinimal } from '../../utils/version';
import { FunctionalError } from '../../config/errors';
import { convertRepresentationsIds } from '../internal/mapper-utils';

const MINIMAL_CSV_FEED_COMPATIBLE_VERSION = '6.6.0';
export const CSV_FEED_FEATURE_FLAG = 'CSV_FEED';

export const findById = (context: AuthContext, user: AuthUser, ingestionId: string) => {
  return storeLoadById<BasicStoreEntityIngestionCsv>(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV);
};

// findLastCSVIngestion

export const findAllPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listEntitiesPaginated<BasicStoreEntityIngestionCsv>(context, user, [ENTITY_TYPE_INGESTION_CSV], opts);
};

export const findAllCsvIngestions = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listAllEntities<BasicStoreEntityIngestionCsv>(context, user, [ENTITY_TYPE_INGESTION_CSV], opts);
};

export const findCsvMapperForIngestionById = (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  return storeLoadById<BasicStoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
};

export const addIngestionCsv = async (context: AuthContext, user: AuthUser, input: IngestionCsvAddInput) => {
  const parsedInput: IngestionCsvAddInput = {
    ...input,
    csv_mapper: input.csv_mapper ? JSON.stringify({
      ...JSON.parse(input.csv_mapper),
      id: uuid()
    }) : input.csv_mapper
  };
  if (parsedInput.authentication_value) {
    verifyIngestionAuthenticationContent(parsedInput.authentication_type, parsedInput.authentication_value);
  }

  const { element, isCreation } = await createEntity(context, user, parsedInput, ENTITY_TYPE_INGESTION_CSV, { complete: true });
  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'CSV',
      name: element.name,
      is_running: element.ingestion_running ?? false,
      connector_user_id: parsedInput.user_id
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates csv ingestion \`${parsedInput.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_CSV, input: parsedInput as unknown } // input was known as unknown
    });
  }
  return element;
};

export const patchCsvIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_CSV, patch);
  return patched.element;
};

export const ingestionCsvEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  if (input.some(((editInput) => editInput.key === 'authentication_value'))) {
    const ingestionConfiguration = await findById(context, user, ingestionId);
    const authenticationValueField = input.find(((editInput) => editInput.key === 'authentication_value'));
    if (authenticationValueField && authenticationValueField.value[0]) {
      verifyIngestionAuthenticationContent(ingestionConfiguration.authentication_type, authenticationValueField.value[0]);
    }
  }
  const parsedInput = input.map((editInput) => {
    if (editInput.key === 'csv_mapper') {
      return {
        ...editInput,
        value: editInput.value ? JSON.stringify({
          ...JSON.parse(editInput.value as unknown as string),
          id: uuid()
        }) : editInput.value
      };
    }
    return editInput;
  });

  const { element } = await updateAttribute(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV, parsedInput);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'CSV',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${parsedInput.map((i) => i.key).join(', ')}\` for csv ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_CSV, input: parsedInput as unknown }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const ingestionCsvResetState = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  await patchCsvIngestion(context, user, ingestionId, { current_state_hash: '' });
  const ingestionUpdated = await findById(context, user, ingestionId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `reset state of csv ingestion ${ingestionUpdated.name}`,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_CSV, input: ingestionUpdated }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, ingestionUpdated, user);
};

export const deleteIngestionCsv = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes csv ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_CSV, input: deleted }
  });
  return ingestionId;
};

interface CsvResponseData {
  csvLines: string[],
  addedLast: string | undefined | null
}

export const fetchCsvFromUrl = async (csvMapper: CsvMapperParsed, ingestion: BasicStoreEntityIngestionCsv, opts: { limit?: number } = {}): Promise<CsvResponseData> => {
  const { limit = undefined } = opts;
  const headers = new OpenCTIHeaders();
  headers.Accept = 'application/csv';
  if (ingestion.authentication_type === IngestionAuthType.Basic) {
    const auth = Buffer.from(ingestion.authentication_value || '', 'utf-8').toString('base64');
    headers.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Bearer) {
    headers.Authorization = `Bearer ${ingestion.authentication_value}`;
  }
  let certificates;
  if (ingestion.authentication_type === IngestionAuthType.Certificate) {
    const [cert, key, ca] = (ingestion.authentication_value || '').split(':');
    certificates = { cert, key, ca };
  }
  const httpClientOptions: GetHttpClient = { headers, rejectUnauthorized: false, responseType: 'arraybuffer', certificates };
  const httpClient = getHttpClient(httpClientOptions);
  const { data, headers: resultHeaders } = await httpClient.get(ingestion.uri);
  const dataLines = data.toString().split('\n');
  const csvLines = dataLines
    .filter((line: string) => (
      (!!csvMapper.skipLineChar && !line.startsWith(csvMapper.skipLineChar))
          || (!csvMapper.skipLineChar && !!line)
    ))
    .slice(0, limit ?? dataLines.length);
  return { csvLines, addedLast: resultHeaders['x-csv-date-added-last'] };
};

export const testCsvIngestionMapping = async (context: AuthContext, user: AuthUser, input: IngestionCsvAddInput): Promise<CsvMapperTestResult> => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }
  const csvMapper = input.csv_mapper_type === IngestionCsvMapperType.Inline ? JSON.parse(input.csv_mapper ?? '') : await findCsvMapperById(context, user, input.csv_mapper_id!);
  const parsedMapper = parseCsvMapper(csvMapper);
  const ingestion = {
    uri: input.uri,
    authentication_type: input.authentication_type,
    authentication_value: input.authentication_value
  } as BasicStoreEntityIngestionCsv;
  const { csvLines } = await fetchCsvFromUrl(parsedMapper, ingestion, { limit: 50 });
  if (parsedMapper.has_header) {
    removeHeaderFromFullFile(csvLines, parsedMapper.skipLineChar);
  }

  const bundlerOpts : CsvBundlerTestOpts = {
    applicantUser: user,
    csvMapper: parsedMapper
  };
  const allObjects = await getCsvTestObjects(context, csvLines, bundlerOpts);

  return {
    objects: JSON.stringify(allObjects, null, 2),
    nbRelationships: allObjects.filter((object: StixObject) => object.type === 'relationship').length,
    nbEntities: allObjects.filter((object: StixObject) => object.type !== 'relationship').length,
  };
};

export const csvFeedAddInputFromImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  if (!isFeatureEnabled(CSV_FEED_FEATURE_FLAG)) {
    throw new Error(`${CSV_FEED_FEATURE_FLAG} feature is disabled`);
  }
  const parsedData = await extractContentFrom(file);

  // check platform version compatibility
  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_CSV_FEED_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_CSV_FEED_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }

  return {
    markings: [], // On some config, marking is missing
    ...parsedData.configuration,
    csvMapper: transformCsvMapperConfig(parsedData.configuration.csv_mapper.configuration, context, user),
  };
};

export const csvFeedGetCsvMapper = (context: AuthContext, ingestionCsv: BasicStoreEntityIngestionCsv) => {
  return ingestionCsv.csv_mapper_type === 'inline' ? {
    ...JSON.parse(ingestionCsv.csv_mapper!)
  } : findCsvMapperForIngestionById(context, context.user!, ingestionCsv.csv_mapper_id!);
};

const getCsvMapper = async (context: AuthContext, ingestionCsv: BasicStoreEntityIngestionCsv) => {
  if (ingestionCsv.csv_mapper_type === 'inline') {
    return {
      ...JSON.parse(ingestionCsv.csv_mapper!)
    };
  }
  const csvMapper = await findCsvMapperForIngestionById(context, context.user!, ingestionCsv.csv_mapper_id!);
  const {
    name,
    has_header,
    separator,
    representations,
    skipLineChar,
  } = csvMapper;
  return {
    name,
    has_header,
    separator,
    skipLineChar,
    representations: JSON.parse(representations)
  };
};

export const csvFeedMapperExport = async (context: AuthContext, user: AuthUser, ingestionCsv: BasicStoreEntityIngestionCsv) => {
  const {
    name,
    description,
    uri,
    authentication_type,
    markings,
    scheduling_period
  } = ingestionCsv;
  const csv_mapper = await getCsvMapper(context, ingestionCsv);
  const parsedRepresentations: CsvMapperRepresentation[] = csv_mapper.representations;
  await convertRepresentationsIds(context, user, parsedRepresentations, 'internal');
  return JSON.stringify({
    openCTI_version: PLATFORM_VERSION,
    type: 'csvFeeds',
    configuration: {
      name,
      description,
      uri,
      authentication_type,
      authentication_value: '',
      markings,
      scheduling_period,
      csv_mapper_type: 'inline',
      csv_mapper: {
        configuration: {
          ...csv_mapper,
          representations: parsedRepresentations,
        }
      }
    }
  });
};
