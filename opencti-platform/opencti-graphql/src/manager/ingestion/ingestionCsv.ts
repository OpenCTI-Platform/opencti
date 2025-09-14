import type { BasicStoreEntityIngestionCsv } from '../../modules/ingestion/ingestion-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { findById as findUserById } from '../../domain/user';
import { findById as findCsvMapperById } from '../../modules/internal/csvMapper/csvMapper-domain';
import { type CsvBundlerIngestionOpts, generateAndSendBundleProcess, removeHeaderFromFullFile } from '../../parser/csv-bundler';
import { now, utcDate } from '../../utils/format';
import { SYSTEM_USER } from '../../utils/access';
import { logApp } from '../../config/conf';
import type { CsvMapperParsed } from '../../modules/internal/csvMapper/csvMapper-types';
import { compareHashSHA256, hashSHA256 } from '../../utils/hash';
import { fetchCsvFromUrl, findAllCsvIngestion } from '../../modules/ingestion/ingestion-csv-domain';
import { parseCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
import { IngestionCsvMapperType } from '../../generated/graphql';
import { reportExpectation, updateExpectationsNumber } from '../../domain/work';
import { connectorIdFromIngestId } from '../../domain/connector';
import { createWorkForIngestion } from './ingestionUtils';
import { ingestionQueueExecution } from './ingestionExecutor';

export const processCsvLines = async (
  context: AuthContext,
  ingestion: BasicStoreEntityIngestionCsv,
  csvMapperParsed: CsvMapperParsed,
  csvLines: string[],
  addedLast: string | undefined | null
) => {
  const linesContent = csvLines.join('');
  const hashedIncomingData = hashSHA256(linesContent);
  const isUnchangedData = compareHashSHA256(linesContent, ingestion.current_state_hash ?? '');
  if (isUnchangedData) {
    logApp.info(`[OPENCTI-MODULE] INGESTION - Unchanged data for csv ingest: ${ingestion.name}`);
    return { size: 0, ingestionPatch: {}, connectorInfo: {} };
  }
  const ingestionUser = await findUserById(context, context.user ?? SYSTEM_USER, ingestion.user_id) ?? SYSTEM_USER;
  if (csvMapperParsed.has_header) {
    removeHeaderFromFullFile(csvLines, csvMapperParsed.skipLineChar);
  }
  logApp.info(`[OPENCTI-MODULE] INGESTION - ingesting ${csvLines.length} csv lines`);
  const work = await createWorkForIngestion(context, ingestion);
  const bundlerOpts : CsvBundlerIngestionOpts = {
    workId: work.id,
    applicantUser: ingestionUser as AuthUser,
    entity: undefined, // TODO is it possible to ingest in entity context ?
    csvMapper: csvMapperParsed,
    connectorId: connectorIdFromIngestId(ingestion.id),
  };
    // start UI count, import of file = 1 operation.
  await updateExpectationsNumber(context, ingestionUser, work.id, 1);
  const { bundleCount, objectCount } = await generateAndSendBundleProcess(context, csvLines, bundlerOpts);
  await reportExpectation(context, ingestionUser, work.id);// csv file ends = 1 operation done.
  logApp.info(`[OPENCTI-MODULE] INGESTION Csv - Sent: ${bundleCount} bundles for ${objectCount} objects.`);
  const state = { current_state_hash: hashedIncomingData, added_after_start: utcDate(addedLast).toISOString(), last_execution_date: now() };
  return { size: objectCount, ingestionPatch: state, connectorInfo: { state } };
};

const csvDataHandler = async (context: AuthContext, ingestion: BasicStoreEntityIngestionCsv) => {
  const user = context.user ?? SYSTEM_USER;
  const csvMapper = ingestion.csv_mapper_type === IngestionCsvMapperType.Inline
    ? JSON.parse(ingestion.csv_mapper!) : await findCsvMapperById(context, user, ingestion.csv_mapper_id!);
  const csvMapperParsed = parseCsvMapper(csvMapper);
  csvMapperParsed.user_chosen_markings = ingestion.markings ?? [];
  const { csvLines, addedLast } = await fetchCsvFromUrl(csvMapperParsed, ingestion);
  return processCsvLines(context, ingestion, csvMapperParsed, csvLines, addedLast);
};

export const csvExecutor = async (context: AuthContext) => {
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, noFiltersChecking: true };
  const ingestions = await findAllCsvIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    const dataHandlerFn = () => csvDataHandler(context, ingestion);
    ingestionPromises.push(ingestionQueueExecution(context, ingestion, dataHandlerFn));
  }
  return Promise.all(ingestionPromises);
};
