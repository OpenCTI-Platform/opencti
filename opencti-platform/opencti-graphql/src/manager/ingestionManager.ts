import type { convertableToString } from 'xml2js';
import { parseStringPromise as xmlParse } from 'xml2js';
import TurndownService from 'turndown';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import type { SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { AxiosHeaders } from 'axios';
import type { Moment } from 'moment';
import { lockResource } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnknownError, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { FROM_START_STR, sanitizeForMomentParsing, utcDate } from '../utils/format';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { pushToSync } from '../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { findAllRssIngestions, patchRssIngestion } from '../modules/ingestion/ingestion-rss-domain';
import type { AuthContext } from '../types/user';
import type { BasicStoreEntityIngestionRss, BasicStoreEntityIngestionTaxii } from '../modules/ingestion/ingestion-types';
import { findAllTaxiiIngestions, patchTaxiiIngestion } from '../modules/ingestion/ingestion-taxii-domain';
import { TaxiiVersion } from '../generated/graphql';

// Ingestion manager responsible to cleanup old data
// Each API will start is ingestion manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 300000;
const INGESTION_MANAGER_KEY = conf.get('ingestion_manager:lock_key') || 'ingestion_manager_lock';

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
    title: turndownService.turndown(entry.title._),
    description: turndownService.turndown(entry.summary?._ ?? ''),
    link: isNotEmptyField(entry.link) ? entry.link.href?.trim() : '',
    content: turndownService.turndown(entry.content?._ ?? ''),
    labels: [], // No label in rss v1
    pubDate: utcDate(sanitizeForMomentParsing(entry.updated?._ ?? updated?._ ?? FROM_START_STR)),
  };
};

const rssItemV2Convert = (turndownService: TurndownService, channel: RssElement, item: RssItem): DataItem => {
  const { pubDate } = channel;
  return {
    title: turndownService.turndown(item.title._ ?? ''),
    description: turndownService.turndown(item.description?._ ?? ''),
    link: isNotEmptyField(item.link) ? (item.link._ ?? '').trim() : '',
    content: turndownService.turndown(item['content:encoded']?._ ?? item.content?._ ?? ''),
    labels: R.uniq(asArray(item.category).filter((c) => isNotEmptyField(c)).map((c) => c._.trim())),
    pubDate: utcDate(sanitizeForMomentParsing(item.pubDate?._ ?? pubDate?._ ?? FROM_START_STR)),
  };
};

const rssHttpGetter = (): Getter => {
  const httpClient = getHttpClient({
    responseType: 'text',
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0' }
  });
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
    const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: reports };
    // Push the bundle to absorption queue
    const stixBundle = JSON.stringify(bundle);
    const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
    await pushToSync({ type: 'bundle', applicant_id: ingestion.user_id ?? OPENCTI_SYSTEM_UUID, content, update: true });
    // Update the state
    const lastPubDate = R.last(items)?.pubDate;
    await patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { current_state_date: lastPubDate });
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
    const ingestionPromise = rssDataHandler(context, httpGet, turndownService, ingestion)
      .catch((e) => {
        logApp.error(e, { name: ingestion.name, context: 'Rss execution' });
      });
    ingestionPromises.push(ingestionPromise);
  }
  return Promise.all(ingestionPromises);
};
// endregion

// region Taxii ingestion
interface TaxiiResponseData {
  data: { more: boolean, next: string, objects: object[] },
  addedLast: string | undefined | null
}

const taxiiHttpGet = async (ingestion: BasicStoreEntityIngestionTaxii): Promise<TaxiiResponseData> => {
  const headers = new AxiosHeaders();
  headers.Accept = 'application/taxii+json;version=2.1';
  if (ingestion.authentication_type === 'basic') {
    const auth = Buffer.from(ingestion.authentication_value, 'utf-8').toString('base64');
    headers.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === 'bearer') {
    headers.Authorization = `Bearer ${ingestion.authentication_value}`;
  }
  let certificates;
  if (ingestion.authentication_type === 'certificate') {
    certificates = { cert: ingestion.authentication_value.split(':')[0], key: ingestion.authentication_value.split(':')[1], ca: ingestion.authentication_value.split(':')[0] };
  }
  const httpClientOptions: GetHttpClient = { headers, rejectUnauthorized: false, responseType: 'json', certificates };
  const httpClient = getHttpClient(httpClientOptions);
  const preparedUri = ingestion.uri.endsWith('/') ? ingestion.uri : `${ingestion.uri}/`;
  const url = `${preparedUri}collections/${ingestion.collection}/objects/`;
  const next = ingestion.added_after_start ? ingestion.current_state_cursor : null;
  const params = { next, added_after: ingestion.added_after_start };
  const { data, headers: resultHeaders } = await httpClient.get(url, { params });
  return { data, addedLast: resultHeaders['x-taxii-date-added-last'] };
};
type TaxiiHandlerFn = (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => Promise<void>;
const taxiiV21DataHandler: TaxiiHandlerFn = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => {
  const { data, addedLast } = await taxiiHttpGet(ingestion);
  if (data.objects && data.objects.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Taxii ingestion execution for ${data.objects.length} items`);
    const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: data.objects };
    // Push the bundle to absorption queue
    const stixBundle = JSON.stringify(bundle);
    const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
    await pushToSync({ type: 'bundle', applicant_id: ingestion.user_id ?? OPENCTI_SYSTEM_UUID, content, update: true });
    // Update the state
    await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, {
      current_state_cursor: data.next ? String(data.next) : undefined,
      added_after_start: utcDate(addedLast)
    });
  } else if (data.objects === undefined) {
    const error = UnknownError('Undefined taxii objects', data);
    logApp.error(error, { name: ingestion.name, context: 'Taxii 2.1 transform' });
  }
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
    const taxiiHandler = TAXII_HANDLERS[ingestion.version];
    if (!taxiiHandler) {
      throw UnsupportedError(`[OPENCTI-MODULE] Taxii version ${ingestion.version} is not yet supported`);
    }
    const ingestionPromise = taxiiHandler(context, ingestion)
      .catch((e) => {
        logApp.error(e, { name: ingestion.name, context: 'Taxii ingestion execution' });
      });
    ingestionPromises.push(ingestionPromise);
  }
  return Promise.all(ingestionPromises);
};
// endregion

const ingestionHandler = async () => {
  logApp.debug('[OPENCTI-MODULE] Running ingestion manager');
  let lock;
  try {
    // Lock the manager
    const turndownService = new TurndownService();
    lock = await lockResource([INGESTION_MANAGER_KEY], { retryCount: 0 });
    running = true;
    // noinspection JSUnusedLocalSymbols
    const context = executionContext('ingestion_manager');
    const ingestionPromises = [];
    ingestionPromises.push(rssExecutor(context, turndownService));
    ingestionPromises.push(taxiiExecutor(context));
    await Promise.all(ingestionPromises);
  } catch (e: any) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Ingestion manager already in progress by another API');
    } else {
      logApp.error(e, { manager: 'INGESTION_MANAGER' });
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
      logApp.info('[OPENCTI-MODULE] Running ingestion manager');
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
      logApp.info('[OPENCTI-MODULE] Stopping ingestion manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const ingestionManager = initIngestionManager();

export default ingestionManager;
