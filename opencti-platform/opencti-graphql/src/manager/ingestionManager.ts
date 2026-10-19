import TurndownService from 'turndown';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import type { SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { AxiosError } from 'axios';
import { lockResources } from '../lock/master-lock';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnknownError, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { isNotEmptyField } from '../database/utils';
import { isDateInRange, now, schedulingPeriodToMs, sinceNowInMinutes, utcDate } from '../utils/format';
import { findAllRssIngestion, patchRssIngestion } from '../modules/ingestion/ingestion-rss-domain';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntityIngestionCsv, BasicStoreEntityIngestionRss, BasicStoreEntityIngestionTaxii } from '../modules/ingestion/ingestion-types';
import { findAllTaxiiIngestion, patchTaxiiIngestion } from '../modules/ingestion/ingestion-taxii-domain';
import { TaxiiVersion } from '../generated/graphql';
import { fetchCsvFromUrl, findAllCsvIngestion, patchCsvIngestion, resolveCsvMapperParsed } from '../modules/ingestion/ingestion-csv-domain';
import { type CsvBundlerIngestionOpts, generateAndSendBundleProcess, removeHeaderFromFullFile } from '../parser/csv-bundler';
import { reportExpectation, updateExpectationsNumber } from '../domain/work';
import { findById as findUserById } from '../modules/user/user-domain';
import { compareHashSHA256, hashSHA256 } from '../utils/hash';
import type { StixBundle, StixObject } from '../types/stix-2-1-common';
import { queueDetails } from '../modules/connector/connector-domain';
import { connectorIdFromIngestId } from '../domain/connector';
import type { CsvMapperParsed } from '../modules/internal/csvMapper/csvMapper-types';
import { executeJsonQuery, findAllJsonIngestion, mergeIngestionJsonState, patchJsonIngestion } from '../modules/ingestion/ingestion-json-domain';
import { FEED_REQUEST_TIMEOUT, runningIngestionsFilters } from '../modules/ingestion/ingestion-common';
import { buildRssReportsBundle, rssDataParser, type RssGetter, rssHttpGetter } from '../modules/ingestion/ingestion-rss-utils';
import { computeTaxiiNextState, handleConfidenceToScoreTransformation, taxiiHttpGet, type TaxiiResponseData } from '../modules/ingestion/ingestion-taxii-utils';
import { createWorkForIngestion, pushBundleToConnectorQueue, updateBuiltInConnectorInfo } from './ingestionManager/ingestionManagerPushToQueue';
import { INGESTION_MANAGER_SCHEDULE_TIME } from './ingestionManager/ingestionManagerConfiguration';
import { buildIngestionErrorMeta, createIngestionLogger } from './ingestionManager/ingestionManagerUtils';
import { assertIngestionExecutionIdentityAllowed } from '../modules/ingestion/ingestion-execution-identity';

// Ingestion manager responsible to cleanup old data
// Each API will start is ingestion manager.
// If the lock is free, every API as the right to take it.

const INGESTION_MANAGER_KEY = conf.get('ingestion_manager:lock_key') || 'ingestion_manager_lock';
const RSS_FEED_MIN_INTERVAL_MINUTES = conf.get('ingestion_manager:rss_feed:min_interval_minutes') || 5;
const CSV_FEED_MIN_INTERVAL_MINUTES = conf.get('ingestion_manager:csv_feed:min_interval_minutes') || 5;

let running = false;

// region utils
/**
 * Checks whether the user-configured scheduling period has elapsed since the last execution.
 * This is schedule as string (e.g. PT1H, PT6H, PT1D).
 * Returns true (must execute) when:
 *  - last_execution_date is undefined (never executed before)
 *  - scheduling_period is empty or set to 'auto'
 *  - the configured period has fully elapsed since last_execution_date
 * Used by all ingestion types (RSS, TAXII, CSV, JSON).
 */
export const isMustExecuteIteration = (last_execution_date: Date | string | undefined, scheduling_period: string) => {
  if (isNotEmptyField(scheduling_period) && scheduling_period !== 'auto' && last_execution_date) {
    const schedulingPeriod = schedulingPeriodToMs(scheduling_period);
    const isInRange = isDateInRange(last_execution_date, schedulingPeriod, utcDate());
    return !isInRange;
  }
  return true;
};

/**
 * Enforces a system-level minimum interval between executions to prevent
 * calling external feeds too frequently, regardless of the user scheduling period.
 * Returns true when no previous execution exists, or at least min_interval_minutes have passed.
 */
const shouldExecuteIngestion = (ingestion: BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv, min_interval_minutes: number) => {
  const { last_execution_date } = ingestion;
  return !last_execution_date || sinceNowInMinutes(last_execution_date) >= min_interval_minutes;
};

// endregion

// region Rss ingestion
const rssDataHandler = async (context: AuthContext, httpRssGet: RssGetter, turndownService: TurndownService, ingestion: BasicStoreEntityIngestionRss) => {
  logApp.info(`[OPENCTI-MODULE] Executing Rss ingestion for ${ingestion.name}`);
  const data = await httpRssGet(ingestion.uri);
  const items = await rssDataParser(turndownService, data, ingestion.current_state_date);
  let lastPubDate;
  if (items.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Rss ingestion execution for ${items.length} items`);
    const bundle = buildRssReportsBundle(ingestion, items);
    // Push the bundle to absorption queue
    await pushBundleToConnectorQueue(context, ingestion, bundle);
    // Update the state
    lastPubDate = R.last(items)?.pubDate.toISOString();
    logApp.info('[OPENCTI-MODULE] lastPubDate:', { lastPubDate });
    await patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { current_state_date: lastPubDate, last_execution_date: now() });
    // Patch the related connector
    const state = { current_state_date: lastPubDate };
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state });
  } else {
    logApp.info('[OPENCTI-MODULE] Rss ingestion execution done, but no new item to ingest.');
    await patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now() });
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id);
  }
};

export const rssExecutor = async (context: AuthContext, turndownService: TurndownService) => {
  const opts = { filters: runningIngestionsFilters(), noFiltersChecking: true };
  const ingestions = await findAllRssIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    if (isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
      // If ingestion have remaining messages in the queue dont fetch any new data
      if (messages_number > 0) {
        logApp.info(`[OPENCTI-MODULE] INGESTION Rss, skipping ${ingestion.name} - queue already filled with messages (${messages_number})`);
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
        ingestionPromises.push(ingestionPromise);
        // If last execution was done before RSS_FEED_MIN_INTERVAL_MINUTES minutes, dont fetch any new data
      } else if (!shouldExecuteIngestion(ingestion, RSS_FEED_MIN_INTERVAL_MINUTES)) {
        logApp.info(`[OPENCTI-MODULE] INGESTION Rss, skipping ${ingestion.name} - last run is more recent than ${RSS_FEED_MIN_INTERVAL_MINUTES} minutes.`);
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { messages_size });
        ingestionPromises.push(ingestionPromise);
        // If no message in queue and last execution is old enough, fetch new data
      } else {
        const httpGet = rssHttpGetter(ingestion);
        const ingestionLogger = createIngestionLogger(ingestion.internal_id, ingestion.name, 'rss');
        ingestionLogger.info('Feed execution started', { uri: ingestion.uri });
        const ingestionPromise = rssDataHandler(context, httpGet, turndownService, ingestion)
          .then(async () => {
            await patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, {
              last_execution_status: 'success',
              last_execution_date: now(),
            });
            await ingestionLogger.success('Feed execution succeeded');
          })
          .catch((e) => {
            logApp.warn('[OPENCTI-MODULE] INGESTION - RSS ingestion execution', { cause: e, name: ingestion.name });
            if (e instanceof AxiosError) {
              if (e?.response?.headers) {
                if (e.response.headers['cf-mitigated']) {
                  logApp.warn(`[OPENCTI-MODULE] INGESTION Rss - Cloudflare challenge fail for ${ingestion.uri}`);
                }
              }
            }
            ingestionLogger.error('Feed execution failed', buildIngestionErrorMeta(e))
              .catch((reason) => logApp.warn('[OPENCTI-MODULE] INGESTION Rss, error on pushing ingestion error log', { cause: reason }));
            // In case of error we need also to take in account the min_interval_minutes with last_execution_date update.
            patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now(), last_execution_status: 'error' })
              .catch((reason) => logApp.error('[OPENCTI-MODULE] INGESTION Rss, error on updating ingestion status', { cause: reason }));
          });
        ingestionPromises.push(ingestionPromise);
      }
    }
  }
  return Promise.all(ingestionPromises);
};
// endregion

// region Taxii ingestion
type TaxiiHandlerFn = (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => Promise<TaxiiExecutionResult>;

interface TaxiiExecutionResult {
  objectsCount: number;
  objects: StixObject[];
}

export const processTaxiiResponse = async (
  context: AuthContext,
  ingestion: BasicStoreEntityIngestionTaxii,
  taxiResponse: TaxiiResponseData,
): Promise<TaxiiExecutionResult> => {
  const { data, addedLastHeader } = taxiResponse;
  let objects: StixObject[] = [];
  if (data.objects && data.objects.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Taxii ingestion execution for ${data.objects.length} items, sending stix bundle to workers.`, { ingestionId: ingestion.id });
    objects = handleConfidenceToScoreTransformation(ingestion, data.objects);
    const bundle: StixBundle = { type: 'bundle', spec_version: '2.1', id: `bundle--${uuidv4()}`, objects };
    // Push the bundle to absorption queue
    await pushBundleToConnectorQueue(context, ingestion, bundle);
  }
  // Update the state
  const ingestionUpdate = await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, computeTaxiiNextState(taxiResponse));
  const connectorState = { current_state_cursor: ingestionUpdate.current_state_cursor, added_after_start: ingestionUpdate.added_after_start };
  await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state: connectorState });
  if (objects.length === 0) {
    logApp.info('[OPENCTI-MODULE] Taxii ingestion - taxii server has not sent any object.', {
      next: data.next,
      more: data.more,
      addedLastHeader,
      ingestionId: ingestion.id,
      ingestionName: ingestion.name,
    });
  }
  return { objectsCount: objects.length, objects };
};

const taxiiV21DataHandler: TaxiiHandlerFn = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => {
  logApp.info(`[OPENCTI-MODULE] Executing Taxii ingestion for ${ingestion.name}`);
  const taxiResponse = await taxiiHttpGet(ingestion);
  return processTaxiiResponse(context, ingestion, taxiResponse);
};
const TAXII_HANDLERS: { [k: string]: TaxiiHandlerFn } = {
  [TaxiiVersion.V21]: taxiiV21DataHandler,
};
export const taxiiExecutor = async (context: AuthContext) => {
  const opts = { filters: runningIngestionsFilters(), noFiltersChecking: true };
  const ingestions = await findAllTaxiiIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    if (isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      // If ingestion have remaining messages in the queue, dont fetch any new data
      const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
      if (messages_number === 0) {
        const taxiiHandler = TAXII_HANDLERS[ingestion.version];
        if (!taxiiHandler) {
          throw UnsupportedError(`[OPENCTI-MODULE] Taxii version ${ingestion.version} is not yet supported`);
        }
        const ingestionLogger = createIngestionLogger(ingestion.internal_id, ingestion.name, 'taxii');
        ingestionLogger.info('Feed execution started', { uri: ingestion.uri, collection: ingestion.collection });
        const ingestionPromise = taxiiHandler(context, ingestion)
          .then(async ({ objectsCount }: TaxiiExecutionResult) => {
            logApp.info('[OPENCTI-MODULE] INGESTION - Taxii handler resolved', { count: objectsCount, name: ingestion.name });
            try {
              await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_status: 'success' });
            } catch (patchErr) {
              logApp.warn('[OPENCTI-MODULE] Failed to patch taxii ingestion success status', { cause: patchErr });
            }
            await ingestionLogger.success('Feed fetched successfully', {
              objects_count: objectsCount,
              collection: ingestion.collection,
              uri: ingestion.uri,
            });
          })
          .catch(async (e: Error) => {
            logApp.warn('[OPENCTI-MODULE] INGESTION - Taxii handler rejected', { cause: e, name: ingestion.name });
            try {
              await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now(), last_execution_status: 'error' });
            } catch (patchErr) {
              logApp.warn('[OPENCTI-MODULE] Failed to patch taxii ingestion error status', { cause: patchErr });
            }
            await ingestionLogger.error('Feed fetch failed', buildIngestionErrorMeta(e));
          });
        ingestionPromises.push(ingestionPromise);
      } else {
        // Queue not empty — log buffering state and skip fetch
        const ingestionLogger = createIngestionLogger(ingestion.internal_id, ingestion.name, 'taxii');
        ingestionLogger.info('Feed is buffering, waiting for queue to drain', { messages_number, messages_size });
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
        ingestionPromises.push(ingestionPromise);
      }
    }
  }
  return Promise.all(ingestionPromises);
};
// endregion

// region Csv ingestion
export const processCsvLines = async (
  context: AuthContext,
  ingestion: BasicStoreEntityIngestionCsv,
  csvMapperParsed: CsvMapperParsed,
  csvLines: string[],
  addedLast: string | undefined | null,
) => {
  const linesContent = csvLines.join('');
  const hashedIncomingData = hashSHA256(linesContent);
  const isUnchangedData = compareHashSHA256(linesContent, ingestion.current_state_hash ?? '');
  let objectsInBundleCount = 0;
  if (isUnchangedData) {
    logApp.info(`[OPENCTI-MODULE] INGESTION - Unchanged data for csv ingest: ${ingestion.name}`);
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id);
  } else {
    // The execution identity of an ingestion can never exceed the rights of its creator.
    await assertIngestionExecutionIdentityAllowed(context, ingestion);
    const ingestionUser = await findUserById(context, context.user ?? SYSTEM_USER, ingestion.user_id!) ?? SYSTEM_USER;
    if (csvMapperParsed.has_header) {
      removeHeaderFromFullFile(csvLines, csvMapperParsed.skipLineChar);
    }
    logApp.info(`[OPENCTI-MODULE] INGESTION - ingesting ${csvLines.length} csv lines`);
    const work = await createWorkForIngestion(context, ingestion);
    const bundlerOpts: CsvBundlerIngestionOpts = {
      workId: work.id,
      applicantUser: ingestionUser as AuthUser,
      entity: undefined, // TODO is it possible to ingest in entity context ?
      csvMapper: csvMapperParsed,
      connectorId: connectorIdFromIngestId(ingestion.id),
    };

    // start UI count, import of file = 1 operation.
    await updateExpectationsNumber(context, ingestionUser, work.id, 1);
    const { bundleCount, objectCount } = await generateAndSendBundleProcess(context, csvLines, bundlerOpts);
    objectsInBundleCount = objectCount;
    await reportExpectation(context, ingestionUser, work.id);// csv file ends = 1 operation done.

    logApp.info(`[OPENCTI-MODULE] INGESTION Csv - Sent: ${bundleCount} bundles for ${objectsInBundleCount} objects.`);
    const state = { current_state_hash: hashedIncomingData, added_after_start: utcDate(addedLast).toISOString(), last_execution_date: now() };
    await patchCsvIngestion(context, SYSTEM_USER, ingestion.internal_id, state);
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state });
  }
  return { isUnchangedData, objectsInBundleCount };
};

const csvDataHandler = async (context: AuthContext, ingestion: BasicStoreEntityIngestionCsv) => {
  const user = context.user ?? SYSTEM_USER;
  const csvMapperParsed = await resolveCsvMapperParsed(context, user, ingestion);
  csvMapperParsed.user_chosen_markings = ingestion.markings ?? [];
  try {
    logApp.info(`[OPENCTI-MODULE] Executing CSV ingestion for ${ingestion.name}`);
    const { csvLines, addedLast } = await fetchCsvFromUrl(csvMapperParsed, ingestion, { timeout: FEED_REQUEST_TIMEOUT });
    return await processCsvLines(context, ingestion, csvMapperParsed, csvLines, addedLast);
  } catch (e: any) {
    throw UnknownError(e, { ingestionName: ingestion.name, ingestionId: ingestion.id });
  }
};

export const csvExecutor = async (context: AuthContext) => {
  const opts = { filters: runningIngestionsFilters(), noFiltersChecking: true };
  const ingestions = await findAllCsvIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    if (isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
      // If ingestion have remaining messages in the queue dont fetch any new data
      if (messages_number > 0) {
        logApp.info(`[OPENCTI-MODULE] INGESTION Csv, skipping ${ingestion.name} - queue already filled with messages (${messages_number})`);
        const ingestionLogger = createIngestionLogger(ingestion.internal_id, ingestion.name, 'csv');
        ingestionLogger.info('Feed is buffering, waiting for queue to drain', { messages_number, messages_size });
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
        ingestionPromises.push(ingestionPromise);
        // If last execution was done before CSV_FEED_MIN_INTERVAL_MINUTES minutes, dont fetch any new data
      } else if (!shouldExecuteIngestion(ingestion, CSV_FEED_MIN_INTERVAL_MINUTES)) {
        logApp.info(`[OPENCTI-MODULE] INGESTION Csv, skipping ${ingestion.name} - last run is more recent than ${CSV_FEED_MIN_INTERVAL_MINUTES} minutes.`);
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { messages_size });
        ingestionPromises.push(ingestionPromise);
        // If no message in queue and last execution is old enough, fetch new data
      } else {
        const ingestionLogger = createIngestionLogger(ingestion.internal_id, ingestion.name, 'csv');
        ingestionLogger.info('Feed execution started', { uri: ingestion.uri });
        const ingestionPromise = csvDataHandler(context, ingestion)
          .then(async ({ objectsInBundleCount }) => {
            try {
              await patchCsvIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_status: 'success', last_execution_date: now() });
            } catch (patchErr) {
              logApp.warn('[OPENCTI-MODULE] Failed to patch csv ingestion success status', { cause: patchErr });
            }
            await ingestionLogger.success('Feed fetched successfully', { objects_count: objectsInBundleCount, uri: ingestion.uri });
          })
          .catch(async (e) => {
            logApp.warn('[OPENCTI-MODULE] INGESTION - Csv ingestion execution', { cause: e, name: ingestion.name });
            // In case of error we need also to take in account the min_interval_minutes with last_execution_date update.
            try {
              await patchCsvIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now(), last_execution_status: 'error' });
            } catch (reason) {
              logApp.error('[OPENCTI-MODULE] INGESTION Csv, Error on updating ingestion status in database', { cause: reason });
            }
            await ingestionLogger.error('Feed fetch failed', buildIngestionErrorMeta(e));
          });
        ingestionPromises.push(ingestionPromise);
      }
    }
  }
  return Promise.all(ingestionPromises);
};
// endregion

// region json ingestion
export const jsonExecutor = async (context: AuthContext) => {
  const opts = { filters: runningIngestionsFilters(), noFiltersChecking: true };
  const ingestions = await findAllJsonIngestion(context, SYSTEM_USER, opts);
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    if (isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
      if (messages_number === 0) { // If no more ingestion to do
        const ingestionLogger = createIngestionLogger(ingestion.internal_id, ingestion.name, 'json');
        ingestionLogger.info('Feed execution started', { uri: ingestion.uri });
        try {
          logApp.info(`[OPENCTI-MODULE] Executing Json ingestion for ${ingestion.name}`);
          const { objects, variables, nextExecutionState } = await executeJsonQuery(context, ingestion, {
            timeout: FEED_REQUEST_TIMEOUT,
          });
          logApp.info(`[OPENCTI-MODULE] Json ingestion execution for ${objects.length} items`);
          // Push the bundle to absorption queue if required
          if (objects.length > 0) {
            const bundle: StixBundle = {
              id: `bundle--${uuidv4()}`,
              spec_version: '2.1',
              type: 'bundle',
              objects,
            };
            await pushBundleToConnectorQueue(context, ingestion, bundle);
          }
          // Save new state for next execution
          const ingestionState = mergeIngestionJsonState(ingestion.query_attributes, variables, nextExecutionState);
          const state = { ingestion_json_state: ingestionState, last_execution_date: now(), last_execution_status: 'success' };
          await patchJsonIngestion(context, SYSTEM_USER, ingestion.internal_id, state);
          await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state: ingestionState });
          await ingestionLogger.success('Feed execution succeeded', { itemCount: objects.length });
        } catch (e) {
          logApp.warn('[OPENCTI-MODULE] INGESTION - Json ingestion execution', { cause: e, name: ingestion.name });
          await ingestionLogger.error('Feed execution failed', buildIngestionErrorMeta(e as Error))
            .catch((reason) => logApp.warn('[OPENCTI-MODULE] INGESTION Json, error on pushing ingestion error log', { cause: reason }));
          // In case of error we need also to take in account the min_interval_minutes with last_execution_date update.
          await patchJsonIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now(), last_execution_status: 'error' })
            .catch((reason) => logApp.error('[OPENCTI-MODULE] INGESTION Json, error on updating status', { cause: reason }));
        }
      } else {
        // Update the state
        await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
      }
    }
  }
};
// endregion

const ingestionHandler = async () => {
  logApp.debug('[OPENCTI-MODULE] INGESTION - Running ingestion handlers');
  let lock;
  try {
    // Lock the manager
    const turndownService = new TurndownService();
    lock = await lockResources([INGESTION_MANAGER_KEY], { retryCount: 0 });
    running = true;
    // noinspection JSUnusedLocalSymbols
    const context = executionContext('ingestion_manager');
    const ingestionPromises = [];
    ingestionPromises.push(rssExecutor(context, turndownService));
    ingestionPromises.push(taxiiExecutor(context));
    ingestionPromises.push(csvExecutor(context));
    ingestionPromises.push(jsonExecutor(context));
    await Promise.all(ingestionPromises);
  } catch (e: any) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] INGESTION - Ingestion manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Ingestion manager handling error', { cause: e, manager: 'INGESTION_MANAGER' });
    }
  } finally {
    running = false;
    if (lock) await lock.unlock();
  }
};

const initIngestionManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] INGESTION - Starting ingestion manager');
      scheduler = setIntervalAsync(async () => {
        await ingestionHandler();
      }, INGESTION_MANAGER_SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'INGESTION_MANAGER',
        enable: booleanConf('ingestion_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      const startTime = Date.now();
      logApp.info('[OPENCTI-MODULE] INGESTION - Stopping ingestion manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      logApp.info(`[OPENCTI-MODULE] Ingestion manager stopped in ${Date.now() - startTime} ms`);
      return true;
    },
  };
};
const ingestionManager = initIngestionManager();

export default ingestionManager;
