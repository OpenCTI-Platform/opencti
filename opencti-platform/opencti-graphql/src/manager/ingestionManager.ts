import type { convertableToString } from 'xml2js';
import { parseStringPromise as xmlParse } from 'xml2js';
import TurndownService from 'turndown';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import type { SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import type { Moment } from 'moment';
import { AxiosError } from 'axios';
import { lockResources } from '../lock/master-lock';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { type GetHttpClient, getHttpClient, OpenCTIHeaders } from '../utils/http-client';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { FROM_START_STR, isDateInRange, now, sanitizeForMomentParsing, sinceNowInMinutes, utcDate } from '../utils/format';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { pushToWorkerForConnector } from '../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { findAllRssIngestions, patchRssIngestion } from '../modules/ingestion/ingestion-rss-domain';
import type { AuthContext, AuthUser } from '../types/user';
import type {
  BasicStoreEntityIngestionCsv,
  BasicStoreEntityIngestionJson,
  BasicStoreEntityIngestionRss,
  BasicStoreEntityIngestionTaxii,
  BasicStoreEntityIngestionTaxiiCollection,
  DataParam,
} from '../modules/ingestion/ingestion-types';
import { findAllTaxiiIngestions, patchTaxiiIngestion } from '../modules/ingestion/ingestion-taxii-domain';
import { ConnectorType, IngestionAuthType, IngestionCsvMapperType, TaxiiVersion } from '../generated/graphql';
import { fetchCsvFromUrl, findAllCsvIngestions, patchCsvIngestion } from '../modules/ingestion/ingestion-csv-domain';
import { findById as findCsvMapperById } from '../modules/internal/csvMapper/csvMapper-domain';
import { type CsvBundlerIngestionOpts, generateAndSendBundleProcess, removeHeaderFromFullFile } from '../parser/csv-bundler';
import { createWork, reportExpectation, updateExpectationsNumber } from '../domain/work';
import { parseCsvMapper } from '../modules/internal/csvMapper/csvMapper-utils';
import { findById as findUserById } from '../domain/user';
import { compareHashSHA256, hashSHA256 } from '../utils/hash';
import type { StixBundle, StixObject } from '../types/stix-2-1-common';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { connectorIdFromIngestId, queueDetails } from '../domain/connector';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import type { StixIndicator } from '../modules/indicator/indicator-types';
import type { CsvMapperParsed } from '../modules/internal/csvMapper/csvMapper-types';
import { executeJsonQuery, findAllJsonIngestions, patchJsonIngestion } from '../modules/ingestion/ingestion-json-domain';

// Ingestion manager responsible to cleanup old data
// Each API will start is ingestion manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 30000;
const INGESTION_MANAGER_KEY = conf.get('ingestion_manager:lock_key') || 'ingestion_manager_lock';
const INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST = conf.get('ingestion_manager:taxii_feed:limit_per_request') || 0;
const RSS_FEED_MIN_INTERVAL_MINUTES = conf.get('ingestion_manager:rss_feed:min_interval_minutes') || 5;
const RSS_FEED_USER_AGENT = conf.get('ingestion_manager:rss_feed:user_agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0';
const CSV_FEED_MIN_INTERVAL_MINUTES = conf.get('ingestion_manager:csv_feed:min_interval_minutes') || 5;

let running = false;

// region utils
const asArray = (data: unknown) => {
  if (data) {
    if (Array.isArray(data)) {
      return data;
    }
    return [data];
  }
  return [];
};

const isMustExecuteIteration = (last_execution_date: Date | undefined, scheduling_period: string) => {
  if (isNotEmptyField(scheduling_period) && scheduling_period !== 'auto' && last_execution_date) {
    const isInRange = isDateInRange(last_execution_date, scheduling_period, utcDate());
    return !isInRange;
  }
  return true;
};

const shouldExecuteIngestion = (ingestion: BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv, min_interval_minutes: number) => {
  const { last_execution_date } = ingestion;
  return !last_execution_date || sinceNowInMinutes(last_execution_date) >= min_interval_minutes;
};

interface UpdateInfo {
  state?: any
  buffering?: boolean
  messages_size?: number
}
const updateBuiltInConnectorInfo = async (context: AuthContext, user_id: string | undefined, id: string, opts: UpdateInfo = {}) => {
  // Patch the related connector
  const csvNow = utcDate();
  const connectorPatch: any = {
    updated_at: csvNow.toISOString(),
    connector_info: {
      last_run_datetime: csvNow.toISOString(),
      next_run_datetime: csvNow.add(SCHEDULE_TIME, 'milliseconds').toISOString(),
      run_and_terminate: false,
      buffering: opts.buffering ?? false,
      queue_threshold: 0,
      queue_messages_size: (opts.messages_size ?? 0) / 1000000 // In Mb
    },
    connector_user_id: user_id,
  };
  if (opts.state) {
    connectorPatch.connector_state = JSON.stringify(opts.state);
  }
  const connectorId = connectorIdFromIngestId(id);
  await patchAttribute(context, SYSTEM_USER, connectorId, ENTITY_TYPE_CONNECTOR, connectorPatch);
};

const createWorkForIngestion = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii
| BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionTaxiiCollection | BasicStoreEntityIngestionJson) => {
  const connector = { internal_id: connectorIdFromIngestId(ingestion.id), connector_type: ConnectorType.ExternalImport };
  const workName = `run @ ${now()}`;
  const work: any = await createWork(context, SYSTEM_USER, connector, workName, connector.internal_id, { receivedTime: now() });
  return work;
};

export const pushBundleToConnectorQueue = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii
| BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionTaxiiCollection | BasicStoreEntityIngestionJson, bundle: StixBundle) => {
  // Push the bundle to absorption queue
  const connectorId = connectorIdFromIngestId(ingestion.id);
  const work: any = await createWorkForIngestion(context, ingestion);
  const stixBundle = JSON.stringify(bundle);
  const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
  if (bundle.objects.length === 1) {
    // Only add explicit expectation if the worker will not split anything
    await updateExpectationsNumber(context, SYSTEM_USER, work.id, bundle.objects.length);
  }
  await pushToWorkerForConnector(connectorId, {
    type: 'bundle',
    applicant_id: ingestion.user_id ?? OPENCTI_SYSTEM_UUID,
    content,
    work_id: work.id,
    update: true
  });
  return work.id;
};
// endregion

// region Rss ingestion
type Getter = (uri: string) => Promise<object>;

interface RssElement {
  pubDate: { _: string }
  lastBuildDate: { _: string }
  updated: { _: string }
}

interface RssItem {
  title: { _: string }
  summary: { _: string }
  description: { _: string }
  link: { _: string, href?: string }
  content: { _: string }
  'content:encoded': { _: string }
  category: { _: string } | { _: string }[]
  pubDate: { _: string }
  lastBuildDate: { _: string }
  updated: { _: string }
}

interface DataItem {
  title: string
  description: string
  link: string | undefined
  content: string
  labels: string[]
  pubDate: Moment
}

const rssItemV1Convert = (turndownService: TurndownService, feed: RssElement, entry: RssItem): DataItem => {
  const { updated } = feed;
  return {
    title: entry.title._,
    description: turndownService.turndown(entry.summary?._ ?? ''),
    link: isNotEmptyField(entry.link) ? (entry.link as { href: string }).href?.trim() : '',
    content: turndownService.turndown(entry.content?._ ?? ''),
    labels: [], // No label in rss v1
    pubDate: utcDate(sanitizeForMomentParsing(entry.updated?._ ?? updated?._ ?? FROM_START_STR)),
  };
};

const rssItemV2Convert = (turndownService: TurndownService, channel: RssElement, item: RssItem): DataItem => {
  const { pubDate } = channel;
  return {
    title: item.title._ ?? '',
    description: turndownService.turndown(item.description?._ ?? ''),
    link: isNotEmptyField(item.link) ? ((item.link as { _: string })._ ?? '').trim() : '',
    content: turndownService.turndown(item['content:encoded']?._ ?? item.content?._ ?? ''),
    labels: R.uniq(asArray(item.category).filter((c) => isNotEmptyField(c)).map((c) => (c as { _: string })._.trim())),
    pubDate: utcDate(sanitizeForMomentParsing(item.pubDate?._ ?? pubDate?._ ?? FROM_START_STR)),
  };
};

const rssHttpGetter = (): Getter => {
  const httpClientOptions: GetHttpClient = {
    responseType: 'text',
    headers: { 'User-Agent': RSS_FEED_USER_AGENT }
  };
  const httpClient = getHttpClient(httpClientOptions);
  return async (uri: string) => {
    const { data } = await httpClient.get(uri);
    return data;
  };
};

// RSS Title is mandatory
// A valid date is required, and after the current_state_date
const rssDataFilter = (items: DataItem[], current_state_date: Date | undefined): DataItem[] => {
  return items.filter((e) => isNotEmptyField(e.title))
    .filter((e) => e.pubDate.isValid())
    .filter((e) => isEmptyField(current_state_date) || e.pubDate.isAfter(current_state_date))
    .sort((a, b) => a.pubDate.diff(b.pubDate));
};

export const rssDataParser = async (turndownService: TurndownService, data: convertableToString, current_state_date: Date | undefined): Promise<DataItem[]> => {
  const xmlData = await xmlParse(data, { explicitArray: false, trim: true, explicitCharkey: true, mergeAttrs: true });
  if (xmlData?.feed) { // Atom V1
    const entries = asArray(xmlData.feed.entry);
    const rssItems = entries.map((entry) => rssItemV1Convert(turndownService, xmlData.feed, entry));
    return rssDataFilter(rssItems, current_state_date);
  }
  if (xmlData?.rss) { // Atom V2
    const channels = asArray(xmlData?.rss?.channel);
    const rssItems = channels.map((channel) => asArray(channel.item).map((item) => rssItemV2Convert(turndownService, channel, item))).flat();
    return rssDataFilter(rssItems, current_state_date);
  }
  return [];
};

const rssDataHandler = async (context: AuthContext, httpRssGet: Getter, turndownService: TurndownService, ingestion: BasicStoreEntityIngestionRss) => {
  const data = await httpRssGet(ingestion.uri);
  const items = await rssDataParser(turndownService, data, ingestion.current_state_date);
  // Build Stix bundle from items
  let lastPubDate;
  if (items.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Rss ingestion execution for ${items.length} items`);
    const reports = items.map((item) => {
      const report: any = {
        type: 'report',
        name: item.title,
        labels: item.labels,
        description: item.description,
        created_by_ref: ingestion.created_by_ref,
        object_marking_refs: ingestion.object_marking_refs,
        report_types: ingestion.report_types,
        published: item.pubDate.toISOString(),
      };
      report.id = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, report);
      if (item.link) {
        report.external_references = [{
          source_name: item.title,
          description: `${ingestion.name} ${item.title}. Retrieved ${item.pubDate.toISOString()}.`,
          url: item.link
        }];
      }
      return report;
    });
    const bundle: StixBundle = { type: 'bundle', spec_version: '2.1', id: `bundle--${uuidv4()}`, objects: reports };
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

const rssExecutor = async (context: AuthContext, turndownService: TurndownService) => {
  const httpGet = rssHttpGetter();
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, noFiltersChecking: true };
  const ingestions = await findAllRssIngestions(context, SYSTEM_USER, opts);
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
        const ingestionPromise = rssDataHandler(context, httpGet, turndownService, ingestion)
          .catch((e) => {
            logApp.warn('[OPENCTI-MODULE] INGESTION - RSS ingestion execution', { cause: e, name: ingestion.name });
            if (e instanceof AxiosError) {
              if (e?.response?.headers) {
                if (e.response.headers['cf-mitigated']) {
                  logApp.warn(`[OPENCTI-MODULE] INGESTION Rss - Cloudflare challenge fail for ${ingestion.uri}`);
                }
              }
            }
            // In case of error we need also to take in account the min_interval_minutes with last_execution_date update.
            patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now() }).catch((reason) => logApp.error('ERROR', { cause: reason }));
          });
        ingestionPromises.push(ingestionPromise);
      }
    }
  }
  return Promise.all(ingestionPromises);
};
// endregion

// region Taxii ingestion
export interface TaxiiResponseData {
  data: { more: boolean | undefined, next: string | undefined, objects: StixObject[] },
  addedLastHeader: string | undefined | null
}

interface TaxiiGetParams {
  next: string | undefined,
  added_after: Date | undefined,
  limit?: string | undefined
}

/**
 *  Compute HTTP GET parameters to send to taxii server.
 *
 *  @see https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107519
 *   // If the more property is set to true and the next property is populated
 *   // then the client can paginate through the remaining records
 *   // using the next URL parameter along with the same original query options.
 *   // If the more property is set to true and the next property is empty
 *   // then the client may paginate through the remaining records by using the added_after URL parameter with the
 *   // date/time value from the X-TAXII-Date-Added-Last header along with the same original query options.
 * @param ingestion
 */
export const prepareTaxiiGetParam = (ingestion: BasicStoreEntityIngestionTaxii) => {
  const params: TaxiiGetParams = { next: ingestion.current_state_cursor, added_after: ingestion.added_after_start };
  if (INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST > 0) {
    params.limit = INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST;
  }
  return params;
};

const taxiiHttpGet = async (ingestion: BasicStoreEntityIngestionTaxii): Promise<TaxiiResponseData> => {
  const octiHeaders = new OpenCTIHeaders();
  octiHeaders.Accept = 'application/taxii+json;version=2.1';
  if (ingestion.authentication_type === IngestionAuthType.Basic) {
    const auth = Buffer.from(ingestion.authentication_value, 'utf-8').toString('base64');
    octiHeaders.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Bearer) {
    octiHeaders.Authorization = `Bearer ${ingestion.authentication_value}`;
  }
  let certificates;
  if (ingestion.authentication_type === IngestionAuthType.Certificate) {
    certificates = { cert: ingestion.authentication_value.split(':')[0], key: ingestion.authentication_value.split(':')[1], ca: ingestion.authentication_value.split(':')[2] };
  }

  const httpClientOptions: GetHttpClient = { headers: octiHeaders, rejectUnauthorized: false, responseType: 'json', certificates };
  const httpClient = getHttpClient(httpClientOptions);
  const preparedUri = ingestion.uri.endsWith('/') ? ingestion.uri : `${ingestion.uri}/`;
  const url = `${preparedUri}collections/${ingestion.collection}/objects/`;
  const params = prepareTaxiiGetParam(ingestion);

  logApp.info('[OPENCTI-MODULE] Taxii HTTP sending', {
    ingestion: ingestion.name,
    request: {
      params,
      url,
    }
  });
  const { data, headers, status } = await httpClient.get(url, { params });
  logApp.info('[OPENCTI-MODULE] Taxii HTTP Get done.', {
    ingestion: ingestion.name,
    response: {
      addedLastHeader: headers['x-taxii-date-added-last'],
      addedFirstHeader: headers['x-taxii-date-added-first'],
      more: data.more,
      next: data.next,
      status,
    },
  });
  return { data, addedLastHeader: headers['x-taxii-date-added-last'] };
};

type TaxiiHandlerFn = (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => Promise<void>;

export const handleConfidenceToScoreTransformation = (ingestion: BasicStoreEntityIngestionTaxii | BasicStoreEntityIngestionTaxiiCollection, objects: StixObject[]) => {
  if (ingestion.confidence_to_score === true) {
    return objects.map((o) => {
      if (o.type === 'indicator') {
        const indicator = o as StixIndicator;
        if (isNotEmptyField(indicator.confidence)) {
          if (indicator.extensions && indicator.extensions[STIX_EXT_OCTI]) {
            indicator.extensions[STIX_EXT_OCTI].score = indicator.confidence;
          } else if (indicator.extensions) {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            indicator.extensions[STIX_EXT_OCTI] = { score: indicator.confidence };
          } else {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            indicator.extensions = { [STIX_EXT_OCTI]: { score: indicator.confidence } };
          }
          return indicator;
        }
      }
      return o;
    });
  }
  return objects;
};

export const processTaxiiResponse = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii, taxiResponse:TaxiiResponseData) => {
  const { data, addedLastHeader } = taxiResponse;
  if (data.objects && data.objects.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Taxii ingestion execution for ${data.objects.length} items, sending stix bundle to workers.`, { ingestionId: ingestion.id });
    const objects = handleConfidenceToScoreTransformation(ingestion, data.objects);
    const bundle: StixBundle = { type: 'bundle', spec_version: '2.1', id: `bundle--${uuidv4()}`, objects };
    // Push the bundle to absorption queue
    await pushBundleToConnectorQueue(context, ingestion, bundle);
    const more = data.more || false;
    // Update the state
    if (more && isNotEmptyField(data.next)) {
      // Do not touch to added_after_start
      const state = { current_state_cursor: data.next, last_execution_date: now() };
      const ingestionUpdate = await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, state);
      const connectorState = { current_state_cursor: ingestionUpdate.current_state_cursor, added_after_start: ingestionUpdate.added_after_start };
      await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state: connectorState });
    } else {
      // Reset the pagination cursor, and update date
      const state = {
        current_state_cursor: undefined,
        added_after_start: addedLastHeader ? utcDate(addedLastHeader).toISOString() : now(),
        last_execution_date: now()
      };
      const ingestionUpdate = await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, state);
      const connectorState = { current_state_cursor: ingestionUpdate.current_state_cursor, added_after_start: ingestionUpdate.added_after_start };
      await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state: connectorState });
    }
  } else {
    const ingestionUpdate = await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now(), current_state_cursor: undefined });
    const connectorState = { current_state_cursor: ingestionUpdate.current_state_cursor, added_after_start: ingestionUpdate.added_after_start };
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state: connectorState });
    logApp.info('[OPENCTI-MODULE] Taxii ingestion - taxii server has not sent any object.', {
      next: data.next,
      more: data.more,
      addedLastHeader,
      ingestionId: ingestion.id,
      ingestionName: ingestion.name
    });
  }
};

const taxiiV21DataHandler: TaxiiHandlerFn = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => {
  const taxiResponse = await taxiiHttpGet(ingestion);
  await processTaxiiResponse(context, ingestion, taxiResponse);
};
const TAXII_HANDLERS: { [k: string]: TaxiiHandlerFn } = {
  [TaxiiVersion.V21]: taxiiV21DataHandler
};
const taxiiExecutor = async (context: AuthContext) => {
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, noFiltersChecking: true };
  const ingestions = await findAllTaxiiIngestions(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    // If ingestion have remaining messages in the queue, dont fetch any new data
    const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
    if (messages_number === 0) {
      const taxiiHandler = TAXII_HANDLERS[ingestion.version];
      if (!taxiiHandler) {
        throw UnsupportedError(`[OPENCTI-MODULE] Taxii version ${ingestion.version} is not yet supported`);
      }
      const ingestionPromise = taxiiHandler(context, ingestion)
        .catch((e) => {
          logApp.warn('[OPENCTI-MODULE] INGESTION - Taxii ingestion execution', { cause: e, name: ingestion.name });
        });
      ingestionPromises.push(ingestionPromise);
    } else {
      // Update the state
      const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
      ingestionPromises.push(ingestionPromise);
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
  addedLast: string | undefined | null
) => {
  const linesContent = csvLines.join('');
  const hashedIncomingData = hashSHA256(linesContent);
  const isUnchangedData = compareHashSHA256(linesContent, ingestion.current_state_hash ?? '');
  let objectsInBundleCount = 0;
  if (isUnchangedData) {
    logApp.info(`[OPENCTI-MODULE] INGESTION - Unchanged data for csv ingest: ${ingestion.name}`);
    await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id);
  } else {
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
  const csvMapper = ingestion.csv_mapper_type === IngestionCsvMapperType.Inline
    ? JSON.parse(ingestion.csv_mapper!) : await findCsvMapperById(context, user, ingestion.csv_mapper_id!);
  const csvMapperParsed = parseCsvMapper(csvMapper);
  csvMapperParsed.user_chosen_markings = ingestion.markings ?? [];
  try {
    const { csvLines, addedLast } = await fetchCsvFromUrl(csvMapperParsed, ingestion);
    await processCsvLines(context, ingestion, csvMapperParsed, csvLines, addedLast);
  } catch (e: any) {
    logApp.error(`[OPENCTI-MODULE] INGESTION Csv - Error trying to fetch csv feed for: ${ingestion.name}`);
    logApp.error(e, { ingestion });
    throw e;
  }
};

const csvExecutor = async (context: AuthContext) => {
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, noFiltersChecking: true };
  const ingestions = await findAllCsvIngestions(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    if (isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
      // If ingestion have remaining messages in the queue dont fetch any new data
      if (messages_number > 0) {
        logApp.info(`[OPENCTI-MODULE] INGESTION Csv, skipping ${ingestion.name} - queue already filled with messages (${messages_number})`);
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { buffering: true, messages_size });
        ingestionPromises.push(ingestionPromise);
        // If last execution was done before CSV_FEED_MIN_INTERVAL_MINUTES minutes, dont fetch any new data
      } else if (!shouldExecuteIngestion(ingestion, CSV_FEED_MIN_INTERVAL_MINUTES)) {
        logApp.info(`[OPENCTI-MODULE] INGESTION Csv, skipping ${ingestion.name} - last run is more recent than ${CSV_FEED_MIN_INTERVAL_MINUTES} minutes.`);
        const ingestionPromise = updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { messages_size });
        ingestionPromises.push(ingestionPromise);
        // If no message in queue and last execution is old enough, fetch new data
      } else {
        const ingestionPromise = csvDataHandler(context, ingestion)
          .catch((e) => {
            logApp.warn('[OPENCTI-MODULE] INGESTION - Csv ingestion execution', { cause: e, name: ingestion.name });
            // In case of error we need also to take in account the min_interval_minutes with last_execution_date update.
            patchCsvIngestion(context, SYSTEM_USER, ingestion.internal_id, { last_execution_date: now() }).catch((reason) => logApp.error('ERROR', { cause: reason }));
          });
        ingestionPromises.push(ingestionPromise);
      }
    }
  }
  return Promise.all(ingestionPromises);
};
// endregion

// region json ingestion
const mergeQueryState = (queryParamsAttributes: Array<DataParam> | undefined, previousState: Record<string, any>, newState: Record<string, any>) => {
  const state: Record<string, any> = {};
  const queryParams = queryParamsAttributes ?? [];
  for (let attrIndex = 0; attrIndex < queryParams.length; attrIndex += 1) {
    const queryParamsAttribute = queryParams[attrIndex];
    if (queryParamsAttribute.state_operation === 'sum') {
      state[queryParamsAttribute.to] = parseInt(previousState[queryParamsAttribute.to] ?? 0, 10) + parseInt(newState[queryParamsAttribute.to] ?? 0, 10);
    } else {
      state[queryParamsAttribute.to] = isNotEmptyField(newState[queryParamsAttribute.to]) ? newState[queryParamsAttribute.to] : previousState[queryParamsAttribute.to];
    }
  }
  return state;
};

export const jsonExecutor = async (context: AuthContext) => {
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, noFiltersChecking: true };
  const ingestions = await findAllJsonIngestions(context, SYSTEM_USER, opts);
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    if (isMustExecuteIteration(ingestion.last_execution_date, ingestion.scheduling_period)) {
      const { messages_number, messages_size } = await queueDetails(connectorIdFromIngestId(ingestion.id));
      if (messages_number === 0) { // If no more ingestion to do
        const { bundle, variables, nextExecutionState } = await executeJsonQuery(context, ingestion);
        logApp.info('pushBundleToConnectorQueue', bundle.objects.length);
        // Push the bundle to absorption queue if required
        if (bundle.objects.length > 0) {
          await pushBundleToConnectorQueue(context, ingestion, bundle);
        }
        // Save new state for next execution
        const ingestionState = mergeQueryState(ingestion.query_attributes, variables, nextExecutionState);
        const state = { ingestion_json_state: ingestionState, last_execution_date: now() };
        await patchJsonIngestion(context, SYSTEM_USER, ingestion.internal_id, state);
        await updateBuiltInConnectorInfo(context, ingestion.user_id, ingestion.id, { state: ingestionState });
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
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'INGESTION_MANAGER',
        enable: booleanConf('ingestion_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] INGESTION - Stopping ingestion manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const ingestionManager = initIngestionManager();

export default ingestionManager;
