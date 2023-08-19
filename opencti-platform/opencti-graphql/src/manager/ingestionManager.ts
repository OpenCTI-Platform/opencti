import { parseStringPromise as xmlParse } from 'xml2js';
import TurndownService from 'turndown';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import type { SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { AxiosHeaders } from 'axios';
import { lockResource } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { GetHttpClient, getHttpClient } from '../utils/http-client';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { utcDate } from '../utils/format';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { pushToSync } from '../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { findAllRssIngestions, patchRssIngestion } from '../modules/ingestion/ingestion-rss-domain';
import type { AuthContext } from '../types/user';
import type { BasicStoreEntityIngestionRss, BasicStoreEntityIngestionTaxii } from '../modules/ingestion/ingestion-types';
import type { Filter } from '../database/middleware-loader';
import { findAllTaxiiIngestions, patchTaxiiIngestion } from '../modules/ingestion/ingestion-taxii-domain';
import { TaxiiVersion } from '../generated/graphql';

// Retention manager responsible to cleanup old data
// Each API will start is retention manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 60000;
const INGESTION_MANAGER_KEY = conf.get('ingestion_manager:lock_key') || 'ingestion_manager_lock';

let running = false;

// const rssFeed: Partial<BasicStoreEntityIngestion> = {
//   name: 'malwarebytes',
//   description: '',
//   uri: 'https://www.malwarebytes.com/blog/feed/index.xml',
//   user_id: SYSTEM_USER.id,
//   created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
//   object_marking_refs: [MARKING_TLP_CLEAR],
//   report_types: ['threat-report'],
//   current_state_date: undefined,
//   ingestion_running: true,
// };

// const taxiiFeed: Partial<BasicStoreEntityIngestionTaxii> = {
//   name: 'filigran',
//   description: '',
//   uri: 'https://filigran.opencti.io/taxii2',
//   collection: '85b6a0cf-98cf-4676-ba89-eb14b2da0fc3',
//   authentication_type: 'bearer',
//   authentication_value: '0fea3ad5-da38-4c0a-b0c4-f2bc38434ba7',
//   user_id: SYSTEM_USER.id,
//   created_by_ref: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024',
//   object_marking_refs: [MARKING_TLP_CLEAR],
//   report_types: ['threat-report'],
//   added_after_start: undefined,
//   current_state_cursor: undefined,
//   ingestion_running: true,
// };

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
  pubDate: string
  lastBuildDate: string
}
interface RssItem {
  title: string
  description: string
  link: string
  content: string
  'content:encoded': string
  category: string | string[]
  pubDate: string
  lastBuildDate: string
}
const rssItemConvert = (turndownService: TurndownService, element: RssElement, item: RssItem) => {
  const { pubDate, lastBuildDate } = element;
  return {
    title: turndownService.turndown(item.title),
    description: turndownService.turndown(item.description),
    link: item.link,
    content: turndownService.turndown(item['content:encoded'] ?? item.content ?? ''),
    labels: R.uniq(asArray(item.category).map((c) => c.trim())),
    pubDate: utcDate(item.pubDate ?? pubDate),
    lastBuildDate: utcDate(item.lastBuildDate ?? lastBuildDate)
  };
};
const rssHttpGetter = () : Getter => {
  const httpClient = getHttpClient({ responseType: 'text' });
  return async (uri: string) => {
    const { data } = await httpClient.get(uri);
    return data;
  };
};
const rssDataHandler = async (context: AuthContext, httpRssGet: Getter, turndownService: TurndownService, ingestion: BasicStoreEntityIngestionRss) => {
  const data = await httpRssGet(ingestion.uri);
  // Build items from XML
  const xmlData = await xmlParse(data, { explicitArray: false });
  const elements = asArray(xmlData?.rss?.channel);
  const items = elements
    .map((e) => asArray(e.item).map((item) => rssItemConvert(turndownService, e, item)))
    .flat()
    .filter((e) => isNotEmptyField(e.pubDate) && (isEmptyField(ingestion.current_state_date) || e.lastBuildDate.isAfter(ingestion.current_state_date)))
    .sort((a, b) => a.lastBuildDate.diff(b.lastBuildDate));
  // Build Stix bundle from items
  if (items.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Rss ingestion execution for ${items.length} items`);
    const reports = items.map((item) => {
      const report: any = {
        type: 'report',
        spec_version: '2.1',
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
          description: `${ingestion.name} ${item.title}. Retrieved ${item.lastBuildDate.toISOString()}.`,
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
    await patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { current_state_date: utcDate() });
  }
};
const rssExecutor = async (context: AuthContext, turndownService: TurndownService) => {
  const httpGet = rssHttpGetter();
  const filters: Array<Filter> = [{ key: 'ingestion_running', values: [true] }];
  const ingestions = await findAllRssIngestions(context, SYSTEM_USER, { filters, connectionFormat: false });
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    const ingestionPromise = rssDataHandler(context, httpGet, turndownService, ingestion)
      .catch((e) => {
        logApp.error(`[OPENCTI-MODULE] Rss ingestion execution error for ${ingestion}`, { error: e });
      });
    ingestionPromises.push(ingestionPromise);
  }
  return ingestionPromises;
};
// endregion

// region Taxii ingestion
interface TaxiiResponseData { more: boolean, next: string, objects: object[] }
const taxiiHttpGet = async (ingestion: BasicStoreEntityIngestionTaxii) : Promise<TaxiiResponseData> => {
  const headers = new AxiosHeaders();
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
  const url = `${preparedUri}root/collections/${ingestion.collection}/objects`;
  const { data } = await httpClient.get(url, { params: { added_after: ingestion.added_after_start, next: ingestion.current_state_cursor } });
  return data;
};
type TaxiiHandlerFn = (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => Promise<void>;
const taxiiV21DataHandler: TaxiiHandlerFn = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => {
  const data = await taxiiHttpGet(ingestion);
  if (data.objects.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Taxii ingestion execution for ${data.objects.length} items`);
    const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: data.objects };
    // Push the bundle to absorption queue
    const stixBundle = JSON.stringify(bundle);
    const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
    await pushToSync({ type: 'bundle', applicant_id: ingestion.user_id ?? OPENCTI_SYSTEM_UUID, content, update: true });
  }
  // Update the state
  if (isNotEmptyField(data.next)) {
    await patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, { current_state_cursor: data.next });
  }
};
const TAXII_HANDLERS: { [k: string]: TaxiiHandlerFn } = {
  [TaxiiVersion.V21]: taxiiV21DataHandler
};
const taxiiExecutor = async (context: AuthContext) => {
  const filters: Array<Filter> = [{ key: 'ingestion_running', values: [true] }];
  const ingestions = await findAllTaxiiIngestions(context, SYSTEM_USER, { filters, connectionFormat: false });
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    const taxiiHandler = TAXII_HANDLERS[ingestion.version];
    if (!taxiiHandler) {
      throw UnsupportedError(`[OPENCTI-MODULE] Taxii version ${ingestion.version} is not yet supported`);
    }
    const ingestionPromise = taxiiHandler(context, ingestion)
      .catch((e) => {
        logApp.error(`[OPENCTI-MODULE] Taxii ingestion execution error for ${ingestion}`, { error: e });
      });
    ingestionPromises.push(ingestionPromise);
  }
  return ingestionPromises;
};
// endregion

const ingestionHandler = async () => {
  logApp.debug('[OPENCTI-MODULE] Running retention manager');
  let lock;
  try {
    // Lock the manager
    const turndownService = new TurndownService();
    lock = await lockResource([INGESTION_MANAGER_KEY], { retryCount: 0 });
    running = true;
    // noinspection JSUnusedLocalSymbols
    const context = executionContext('ingestion_manager');
    const ingestionPromises = [];
    ingestionPromises.push(await rssExecutor(context, turndownService));
    ingestionPromises.push(await taxiiExecutor(context));
    await Promise.all(ingestionPromises);
  } catch (e: any) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Retention manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Retention manager fail to execute', { error: e });
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
