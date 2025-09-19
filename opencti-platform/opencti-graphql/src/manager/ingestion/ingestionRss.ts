import type { Moment } from 'moment/moment';
import TurndownService from 'turndown';
import * as R from 'ramda';
import { type convertableToString, parseStringPromise as xmlParse } from 'xml2js';
import { v4 as uuidv4 } from 'uuid';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { FROM_START_STR, now, sanitizeForMomentParsing, utcDate } from '../../utils/format';
import { getHttpClient, type GetHttpClient } from '../../utils/http-client';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntityIngestionRss } from '../../modules/ingestion/ingestion-types';
import conf, { logApp } from '../../config/conf';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { StixBundle } from '../../types/stix-2-1-common';
import { findAllRssIngestion } from '../../modules/ingestion/ingestion-rss-domain';
import { SYSTEM_USER } from '../../utils/access';
import { asArray, pushBundleToConnectorQueue } from './ingestionUtils';
import { ingestionQueueExecution } from './ingestionExecutor';

const RSS_FEED_USER_AGENT = conf.get('ingestion_manager:rss_feed:user_agent')
    || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0';

const turndownService = new TurndownService();

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

const rssItemV1Convert = (feed: RssElement, entry: RssItem): DataItem => {
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

const rssItemV2Convert = (channel: RssElement, item: RssItem): DataItem => {
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

const rssDataParser = async (data: convertableToString, current_state_date: Date | undefined): Promise<DataItem[]> => {
  const xmlData = await xmlParse(data, { explicitArray: false, trim: true, explicitCharkey: true, mergeAttrs: true });
  if (xmlData?.feed) { // Atom V1
    const entries = asArray(xmlData.feed.entry);
    const rssItems = entries.map((entry) => rssItemV1Convert(xmlData.feed, entry));
    return rssDataFilter(rssItems, current_state_date);
  }
  if (xmlData?.rss) { // Atom V2
    const channels = asArray(xmlData?.rss?.channel);
    const rssItems = channels.map((channel) => asArray(channel.item).map((item) => rssItemV2Convert(channel, item))).flat();
    return rssDataFilter(rssItems, current_state_date);
  }
  return [];
};

const rssDataHandler = async (context: AuthContext, httpRssGet: Getter, ingestion: BasicStoreEntityIngestionRss) => {
  const data = await httpRssGet(ingestion.uri);
  const items = await rssDataParser(data, ingestion.current_state_date);
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
    await pushBundleToConnectorQueue(context, ingestion, bundle); // Push the bundle to absorption queue
    lastPubDate = R.last(items)?.pubDate.toISOString();
    const ingestionPatch = { current_state_date: lastPubDate, last_execution_date: now() };
    const connectorInfo = { current_state_date: lastPubDate };
    return { size: items.length, ingestionPatch, connectorInfo };
  }
  logApp.info('[OPENCTI-MODULE] Rss ingestion execution done, but no new item to ingest.');
  return { size: 0, ingestionPatch: { last_execution_date: now() }, connectorInfo: {} };
};

export const rssExecutor = async (context: AuthContext) => {
  const httpGet = rssHttpGetter();
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, noFiltersChecking: true };
  const ingestions = await findAllRssIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    const dataHandlerFn = () => {
      return rssDataHandler(context, httpGet, ingestion);
    };
    ingestionPromises.push(ingestionQueueExecution(context, ingestion, dataHandlerFn));
  }
  return Promise.all(ingestionPromises);
};
