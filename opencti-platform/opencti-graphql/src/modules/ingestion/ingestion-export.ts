import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreEntityMarkingDefinition } from '../../types/store';
import { getEntitiesMapFromCache } from '../../database/cache';
import { internalLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { SYSTEM_USER } from '../../utils/access';
import { IngestionCsvMapperType } from '../../generated/graphql';
import { convertRepresentationsIds } from '../internal/mapper-utils';
import type { CsvMapperRepresentation } from '../internal/csvMapper/csvMapper-types';
import type { JsonMapperRepresentation } from '../internal/jsonMapper/jsonMapper-types';
import { findById as findJsonMapperById } from '../internal/jsonMapper/jsonMapper-domain';
import { findCsvMapperForIngestionById } from './ingestion-csv-domain';
import { sanitizeExportedHeaders, sanitizeExportedQueryAttributes } from './ingestion-json-domain';
import type { BasicStoreEntityIngestionCsv, BasicStoreEntityIngestionJson, BasicStoreEntityIngestionRss, BasicStoreEntityIngestionTaxii } from './ingestion-types';
import type {
  CsvFeedImportConfiguration,
  FeedMarkingReference,
  JsonFeedImportConfiguration,
  RssFeedImportConfiguration,
  TaxiiFeedImportConfiguration,
} from './ingestion-import-schema';

export const exportFeedMarkings = async (context: AuthContext, ids: string[] | undefined | null): Promise<FeedMarkingReference[]> => {
  const markings = await getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return (ids ?? [])
    .map((id) => markings.get(id))
    .filter((marking): marking is BasicStoreEntityMarkingDefinition => !!marking)
    .map(({ standard_id, definition_type, definition }) => ({ standard_id, definition_type, definition }));
};

const feedConfidenceLevel = async (context: AuthContext, userId: string | undefined) => {
  if (!userId) {
    return null;
  }
  const users = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return users.get(userId)?.user_confidence_level?.max_confidence ?? null;
};

type StoredFeed = BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionJson | BasicStoreEntityIngestionTaxii;

const commonFields = async (context: AuthContext, feed: StoredFeed) => ({
  name: feed.name,
  description: feed.description ?? null,
  scheduling_period: feed.scheduling_period ?? null,
  uri: feed.uri,
  ssl_verify: feed.ssl_verify ?? null,
  confidence_level: await feedConfidenceLevel(context, feed.user_id),
});

export const exportRssFeed = async (context: AuthContext, user: AuthUser, feed: BasicStoreEntityIngestionRss): Promise<RssFeedImportConfiguration> => {
  const author = feed.created_by_ref ? await internalLoadById<BasicStoreEntity>(context, user, feed.created_by_ref) : undefined;
  return {
    ...(await commonFields(context, feed)),
    report_types: feed.report_types ?? [],
    markings: await exportFeedMarkings(context, feed.object_marking_refs),
    author: author ? { standard_id: author.standard_id, name: author.name } : null,
  };
};

const csvMapperOf = async (context: AuthContext, user: AuthUser, feed: BasicStoreEntityIngestionCsv) => {
  if (feed.csv_mapper_type === IngestionCsvMapperType.Inline) {
    const mapper = JSON.parse(feed.csv_mapper ?? '{}');
    return {
      name: mapper.name ?? null,
      has_header: !!mapper.has_header,
      separator: mapper.separator ?? ',',
      skipLineChar: mapper.skipLineChar ?? null,
      representations: mapper.representations ?? [],
    };
  }
  const mapper = await findCsvMapperForIngestionById(context, user, feed.csv_mapper_id ?? '');
  return {
    name: mapper.name,
    has_header: mapper.has_header,
    separator: mapper.separator,
    skipLineChar: mapper.skipLineChar ?? null,
    representations: JSON.parse(mapper.representations),
  };
};

export const exportCsvFeed = async (context: AuthContext, user: AuthUser, feed: BasicStoreEntityIngestionCsv): Promise<CsvFeedImportConfiguration> => {
  const csvMapper = await csvMapperOf(context, user, feed);
  await convertRepresentationsIds(context, user, csvMapper.representations as CsvMapperRepresentation[], 'internal');
  return {
    ...(await commonFields(context, feed)),
    authentication_type: feed.authentication_type,
    markings: await exportFeedMarkings(context, feed.markings),
    csv_mapper: csvMapper,
  };
};

export const exportJsonFeed = async (context: AuthContext, user: AuthUser, feed: BasicStoreEntityIngestionJson): Promise<JsonFeedImportConfiguration> => {
  const jsonMapper = await findJsonMapperById(context, user, feed.json_mapper_id);
  const representations: JsonMapperRepresentation[] = JSON.parse(jsonMapper.representations);
  await convertRepresentationsIds(context, user, representations, 'internal');
  return {
    ...(await commonFields(context, feed)),
    authentication_type: feed.authentication_type,
    markings: await exportFeedMarkings(context, (feed as { markings?: string[] }).markings),
    verb: feed.verb,
    body: feed.body ?? null,
    headers: sanitizeExportedHeaders(feed.headers) ?? [],
    query_attributes: (sanitizeExportedQueryAttributes(feed.query_attributes) ?? []) as unknown as JsonFeedImportConfiguration['query_attributes'],
    pagination_with_sub_page: feed.pagination_with_sub_page ?? null,
    pagination_with_sub_page_attribute_path: feed.pagination_with_sub_page_attribute_path ?? null,
    pagination_with_sub_page_query_verb: feed.pagination_with_sub_page_query_verb || null,
    json_mapper: {
      name: jsonMapper.name,
      variables: jsonMapper.variables ? JSON.parse(jsonMapper.variables) : [],
      representations: representations as unknown as JsonFeedImportConfiguration['json_mapper']['representations'],
    },
  };
};

type StoredRepresentations = { attributes?: { default_values?: unknown }[] }[];

const feedMapperRepresentations = async (context: AuthContext, user: AuthUser, feed: StoredFeed): Promise<StoredRepresentations> => {
  if ('json_mapper_id' in feed && feed.json_mapper_id) {
    const jsonMapper = await findJsonMapperById(context, user, feed.json_mapper_id);
    return jsonMapper?.representations ? JSON.parse(jsonMapper.representations) : [];
  }
  if ('csv_mapper_type' in feed || 'csv_mapper_id' in feed) {
    return (await csvMapperOf(context, user, feed as BasicStoreEntityIngestionCsv)).representations;
  }
  return [];
};

export const exportFeedMarkingIds = async (context: AuthContext, user: AuthUser, feed: StoredFeed): Promise<string[]> => {
  const markings = await getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const feedMarkings = 'object_marking_refs' in feed ? feed.object_marking_refs : (feed as { markings?: string[] }).markings;
  const defaultValues = (await feedMapperRepresentations(context, user, feed))
    .flatMap(({ attributes }) => (attributes ?? []).flatMap(({ default_values: values }) => (Array.isArray(values) ? values : [])));
  const standardIds = [...(feedMarkings ?? []), ...defaultValues]
    .map((id): string | undefined => (typeof id === 'string' ? markings.get(id)?.standard_id : undefined))
    .filter((standardId): standardId is string => !!standardId);
  return [...new Set(standardIds)];
};

export const exportTaxiiFeed = async (context: AuthContext, feed: BasicStoreEntityIngestionTaxii): Promise<TaxiiFeedImportConfiguration> => ({
  ...(await commonFields(context, feed)),
  authentication_type: feed.authentication_type,
  version: feed.version as TaxiiFeedImportConfiguration['version'],
  collection: feed.collection,
  added_after_start: feed.added_after_start ? new Date(feed.added_after_start).toISOString() : null,
  confidence_to_score: feed.confidence_to_score ?? null,
});
