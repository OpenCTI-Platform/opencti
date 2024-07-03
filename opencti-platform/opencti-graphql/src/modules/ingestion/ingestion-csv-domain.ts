import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityIngestionCsv, ENTITY_TYPE_INGESTION_CSV } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import type { CsvMapperTestResult, EditInput, IngestionCsvAddInput } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type BasicStoreEntityCsvMapper, type CsvMapperParsed, ENTITY_TYPE_CSV_MAPPER } from '../internal/csvMapper/csvMapper-types';
import { bundleProcess } from '../../parser/csv-bundler';
import { findById as findCsvMapperById } from '../internal/csvMapper/csvMapper-domain';
import { parseCsvMapper } from '../internal/csvMapper/csvMapper-utils';
import { type GetHttpClient, getHttpClient, OpenCTIHeaders } from '../../utils/http-client';
import { CsvAuthType } from '../../generated/graphql';

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
  const { element, isCreation } = await createEntity(context, user, input, ENTITY_TYPE_INGESTION_CSV, { complete: true });
  if (isCreation) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates csv ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_CSV, input }
    });
  }
  return element;
};

export const patchCsvIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_CSV, patch);
  return patched.element;
};

export const ingestionCsvEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for csv ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_CSV, input }
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const deleteIngestionCsv = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById(context, user, ingestionId, ENTITY_TYPE_INGESTION_CSV);
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
  if (ingestion.authentication_type === CsvAuthType.Basic) {
    const auth = Buffer.from(ingestion.authentication_value || '', 'utf-8').toString('base64');
    headers.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === CsvAuthType.Bearer) {
    headers.Authorization = `Bearer ${ingestion.authentication_value}`;
  }
  let certificates;
  if (ingestion.authentication_type === CsvAuthType.Certificate) {
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
  const csvMapper = await findCsvMapperById(context, user, input.csv_mapper_id);
  const parsedMapper = parseCsvMapper(csvMapper);
  const ingestion = {
    csv_mapper_id: input.csv_mapper_id,
    uri: input.uri,
    authentication_type: input.authentication_type,
    authentication_value: input.authentication_value
  } as BasicStoreEntityIngestionCsv;
  const { csvLines } = await fetchCsvFromUrl(parsedMapper, ingestion, { limit: 50 });
  const bundle = await bundleProcess(context, user, csvLines, parsedMapper); // pass ingestion creator user
  return {
    objects: JSON.stringify(bundle.objects, null, 2),
    nbRelationships: bundle.objects.filter((object) => object.type === 'relationship').length,
    nbEntities: bundle.objects.filter((object) => object.type !== 'relationship').length,
  };
};
