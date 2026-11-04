import type { convertableToString } from 'xml2js';
import { parseStringPromise as xmlParse } from 'xml2js';
import type TurndownService from 'turndown';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import type { Moment } from 'moment';
import conf from '../../config/conf';
import { type GetHttpClient, getHttpClient } from '../../utils/http-client';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { FROM_START_STR, sanitizeForMomentParsing, utcDate } from '../../utils/format';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { StixBundle } from '../../types/stix-2-1-common';
import type { BasicStoreEntityIngestionRss } from './ingestion-types';
import { FEED_REQUEST_TIMEOUT } from './ingestion-common';
import { asArray } from '../../utils/arrayUtil';

// User-Agent sent to RSS sources: a browser one by default, as some hosts reject requests from unknown clients
const RSS_FEED_USER_AGENT = conf.get('ingestion_manager:rss_feed:user_agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0';

export type RssGetter = (uri: string) => Promise<object>;

interface RssElement {
  pubDate: { _: string };
  lastBuildDate: { _: string };
  updated: { _: string };
}

interface RssItem {
  title: { _: string };
  summary: { _: string };
  description: { _: string };
  link: { _: string; href?: string };
  content: { _: string };
  'content:encoded': { _: string };
  category: { _: string } | { _: string }[];
  pubDate: { _: string };
  lastBuildDate: { _: string };
  updated: { _: string };
}

export interface DataItem {
  title: string;
  description: string;
  link: string | undefined;
  content: string;
  labels: string[];
  pubDate: Moment;
}

/**
 * Converts an Atom 1.0 entry (`<feed><entry>`) to an item: link from its `href` attribute,
 * summary and content as markdown, no labels, date from the entry or else the feed `updated`.
 */
const rssItemV1Convert = (turndownService: TurndownService, feed: RssElement, entry: RssItem): DataItem => {
  const { updated } = feed;
  // Safe access to link with fallback to empty string
  const link = entry.link?.href?.trim() ?? '';
  // Use link as fallback if title is missing, or 'Untitled' as last resort
  const title = entry.title?._ || link || 'Untitled';

  return {
    title,
    description: turndownService.turndown(entry.summary?._ ?? ''),
    link: link || undefined,
    content: turndownService.turndown(entry.content?._ ?? ''),
    labels: [], // No label in rss v1
    pubDate: utcDate(sanitizeForMomentParsing(entry.updated?._ ?? updated?._ ?? FROM_START_STR)),
  };
};

/**
 * Converts an RSS 2.0 item (`<rss><channel><item>`) to an item: description and content
 * (`content:encoded` first) as markdown, categories as labels, date from the item or else the channel `pubDate`.
 */
const rssItemV2Convert = (turndownService: TurndownService, channel: RssElement, item: RssItem): DataItem => {
  const { pubDate } = channel;
  // Safe access to link with fallback to empty string
  const link = item.link?._?.trim() ?? '';
  // Use link as fallback if title is missing, or 'Untitled' as last resort
  const title = item.title?._ || link || 'Untitled';

  return {
    title,
    description: turndownService.turndown(item.description?._ ?? ''),
    link: link || undefined,
    content: turndownService.turndown(item['content:encoded']?._ ?? item.content?._ ?? ''),
    labels: R.uniq(asArray(item.category, { falsyAsEmpty: true }).filter((c) => isNotEmptyField(c)).map((c) => (c as { _: string })._.trim())),
    pubDate: utcDate(sanitizeForMomentParsing(item.pubDate?._ ?? pubDate?._ ?? FROM_START_STR)),
  };
};

export const rssHttpClientOptions = (ingestion: BasicStoreEntityIngestionRss) => {
  const httpClientOptions: GetHttpClient = {
    responseType: 'text',
    headers: { 'User-Agent': RSS_FEED_USER_AGENT },
    timeout: FEED_REQUEST_TIMEOUT,
    rejectUnauthorized: ingestion.ssl_verify,
  };
  return httpClientOptions;
};

export const rssHttpGetter = (ingestion: BasicStoreEntityIngestionRss): RssGetter => {
  const httpClient = getHttpClient(rssHttpClientOptions(ingestion));
  return async (uri: string) => {
    const { data } = await httpClient.get(uri);
    return data;
  };
};

/**
 * Keeps the items to ingest (a title, a valid date after current_state_date), oldest first.
 */
const rssDataFilter = (items: DataItem[], current_state_date: Date | undefined): DataItem[] => {
  return items.filter((e) => isNotEmptyField(e.title))
    .filter((e) => e.pubDate.isValid())
    .filter((e) => isEmptyField(current_state_date) || e.pubDate.isAfter(current_state_date))
    .sort((a, b) => a.pubDate.diff(b.pubDate));
};

export const rssDataParser = async (turndownService: TurndownService, data: convertableToString, current_state_date: Date | undefined): Promise<DataItem[]> => {
  const xmlData = await xmlParse(data, { explicitArray: false, trim: true, explicitCharkey: true, mergeAttrs: true });
  if (xmlData?.feed) { // Atom V1
    const entries = asArray(xmlData.feed.entry, { falsyAsEmpty: true });
    const rssItems = entries.map((entry) => rssItemV1Convert(turndownService, xmlData.feed, entry));
    return rssDataFilter(rssItems, current_state_date);
  }
  if (xmlData?.rss) { // Atom V2
    const channels = asArray(xmlData?.rss?.channel, { falsyAsEmpty: true });
    const rssItems = channels.map((channel) => asArray(channel.item, { falsyAsEmpty: true }).map((item) => rssItemV2Convert(turndownService, channel, item))).flat();
    return rssDataFilter(rssItems, current_state_date);
  }
  return [];
};

// One STIX report per RSS item, carrying the feed's author, markings and report types
export const buildRssReportsBundle = (ingestion: BasicStoreEntityIngestionRss, items: DataItem[]): StixBundle => {
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
        url: item.link,
      }];
    }
    return report;
  });
  return { type: 'bundle', spec_version: '2.1', id: `bundle--${uuidv4()}`, objects: reports };
};
