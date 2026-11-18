import * as R from 'ramda';
import type { ZodType } from 'zod';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreEntityMarkingDefinition } from '../../types/store';
import { type EditInput, FilterMode, IngestionAuthType, IngestionCsvMapperType } from '../../generated/graphql';
import { getEntitiesMapFromCache } from '../../database/cache';
import { fullEntitiesList, internalFindByIds, internalLoadById, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { SYSTEM_USER } from '../../utils/access';
import { isStixId } from '../../schema/schemaUtils';
import { findDefaultIngestionGroups } from '../../domain/group';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportValidationReason,
  freeConfigImportName,
  joinConfigImportReasons,
} from '../configImport/configImport-utils';
import { userAlreadyExists, userDelete } from '../user/user-domain';
import type { BasicStoreEntityUser } from '../user/user-types';
import { convertRepresentationsIds } from '../internal/mapper-utils';
import type { CsvMapperRepresentation } from '../internal/csvMapper/csvMapper-types';
import { ENTITY_TYPE_JSON_MAPPER, type BasicStoreEntityJsonMapper, type JsonMapperRepresentation } from '../internal/jsonMapper/jsonMapper-types';
import { createJsonMapperFromConfiguration, deleteJsonMapper } from '../internal/jsonMapper/jsonMapper-domain';
import { CONFIDENCE_NOT_CHANGED_REASON, NO_INGESTION_GROUP_REASON } from '../connector/connector-import';
import type { ConfigPresetImportCredential } from '../configPreset/import/configPreset-import-types';
import { decryptIngestionCredential, verifyIngestionAuthenticationContent, verifyIngestionUri } from './ingestion-common';
import { createIngestionAutomaticUser } from './ingestion-execution-identity';
import { addIngestion as addRssFeed, findAllRssIngestion, ingestionEditField as editRssFeed } from './ingestion-rss-domain';
import { addIngestionCsv, findAllCsvIngestion, ingestionCsvEditField } from './ingestion-csv-domain';
import { addIngestionJson, findAllJsonIngestion, ingestionJsonEditField, isSensitiveHeaderName, isSensitiveQueryAttribute } from './ingestion-json-domain';
import { findAllTaxiiIngestion, ingestionTaxiiAdd, ingestionTaxiiEditField } from './ingestion-taxii-domain';
import { exportCsvFeed, exportJsonFeed, exportRssFeed, exportTaxiiFeed } from './ingestion-export';
import { encodeUriCredential, isSameUriDestination, uriCredentials, uriWithCredentials } from './ingestion-uri-credentials';
import {
  type CsvFeedImportConfiguration,
  csvFeedImportSchema,
  type FeedImportConfiguration,
  type FeedMarkingReference,
  type JsonFeedImportConfiguration,
  jsonFeedImportSchema,
  type RssFeedImportConfiguration,
  rssFeedImportSchema,
  type TaxiiFeedImportConfiguration,
  taxiiFeedImportSchema,
} from './ingestion-import-schema';
import type { BasicStoreEntityIngestionCsv, BasicStoreEntityIngestionJson, BasicStoreEntityIngestionRss, BasicStoreEntityIngestionTaxii } from './ingestion-types';

export type StoredFeed = BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionJson | BasicStoreEntityIngestionTaxii;
type FeedFields = Record<string, unknown>;

export interface FeedImportOptions extends ConfigImportOptions {
  reservedNames?: Set<string>;
  credentials?: Record<string, string>;
  ingestionGroupPlanned?: boolean;
  serviceAccountId?: string;
  // In a dry run, the markings the same import creates, by standard id
  plannedMarkings?: Map<string, unknown>;
}

export type FeedImportCode = 'invalid' | 'exists' | 'ambiguous' | 'name_conflict' | 'markings_not_found' | 'credentials_required'
  | 'no_ingestion_group' | 'service_account_missing' | 'unchanged';

export type FeedImportResult = ConfigImportResult<FeedImportConfiguration, FeedImportCode> & {
  name?: string;
  credentials?: ConfigPresetImportCredential[];
  feed?: BasicStoreEntity;
};

export const AMBIGUOUS_FEED_REASON = 'Several feeds have this name: import it as a copy';

// Without a default group for the service accounts, a feed created writes with a service account the user chooses
export const isIngestionGroupMissing = async (context: AuthContext, user: AuthUser) => (await findDefaultIngestionGroups(context, user)).length === 0;

interface WriteContext {
  dryRun: boolean;
  markingIds: string[];
  authenticationValue?: string;
  headerValues: Record<string, string>;
  queryDefaults: Record<string, string>;
  plannedMarkings?: Map<string, unknown>;
}

interface FeedWrite {
  fields: FeedFields;
  reasons: string[];
  missingMarkings?: string[];
  // Undoes what was written before the feed (the mapper it creates), when the feed itself cannot be written
  rollback?: () => Promise<void>;
}

interface FeedAdapter<C extends FeedImportConfiguration, F extends StoredFeed> {
  schema: ZodType<C>;
  list: (context: AuthContext, user: AuthUser) => Promise<F[]>;
  exportFeed: (context: AuthContext, user: AuthUser, feed: F) => Promise<C>;
  fields: (context: AuthContext, user: AuthUser, configuration: C, write: WriteContext, target?: F) => Promise<FeedWrite>;
  add: (context: AuthContext, user: AuthUser, input: FeedFields) => Promise<BasicStoreEntity>;
  edit: (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => Promise<unknown>;
  supportsAutomaticUser: boolean;
}

const AUTHENTICATION_PARTS: Record<string, { key: string; description: string; secret: boolean; required: boolean }[]> = {
  [IngestionAuthType.Basic]: [
    { key: 'username', description: 'Username of the basic authentication', secret: false, required: true },
    { key: 'password', description: 'Password of the basic authentication', secret: true, required: true },
  ],
  [IngestionAuthType.Bearer]: [
    { key: 'token', description: 'Bearer token', secret: true, required: true },
  ],
  [IngestionAuthType.Certificate]: [
    { key: 'certificate', description: 'Client certificate', secret: false, required: true },
    { key: 'key', description: 'Private key of the client certificate', secret: true, required: true },
    { key: 'ca', description: 'Certificate authority', secret: false, required: false },
  ],
};

export const feedHeaderCredentialKey = (name: string) => `header:${name}`;
const queryAttributeCredentialKey = (attribute: { exposed?: string | null; to?: string | null }) => {
  return attribute.exposed === 'header' ? feedHeaderCredentialKey(attribute.to as string) : `${attribute.exposed ?? 'attribute'}:${attribute.to}`;
};

export const DESTINATION_CHANGED_REASON = 'The URI points to another server: the stored credentials are not kept';
export const SSL_VERIFY_DISABLED_REASON = 'The verification of the SSL certificate is disabled';

const MAX_CONFIGURATION_DEPTH = 32;

const isTooDeep = (value: unknown) => {
  const stack: { node: unknown; depth: number }[] = [{ node: value, depth: 0 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    if (node && typeof node === 'object') {
      if (depth > MAX_CONFIGURATION_DEPTH) {
        return true;
      }
      Object.values(node).forEach((child) => stack.push({ node: child, depth: depth + 1 }));
    }
  }
  return false;
};

const withoutNil = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(withoutNil);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => [k, withoutNil(v)]));
  }
  return value;
};

const sameConfiguration = (current: FeedImportConfiguration, bundle: FeedImportConfiguration) => {
  const { confidence_level: _current, ...currentRest } = current;
  const { confidence_level: _bundle, ...bundleRest } = bundle;
  return R.equals(withoutNil(currentRest), withoutNil(bundleRest));
};

const resolveMarkings = async (context: AuthContext, user: AuthUser, references: FeedMarkingReference[], plannedMarkings?: Map<string, unknown>) => {
  const cached = await getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const markingIds: string[] = [];
  const missing: string[] = [];
  for (let i = 0; i < references.length; i += 1) {
    const reference = references[i];
    const marking = cached.get(reference.standard_id)
      ?? await internalLoadById<BasicStoreEntityMarkingDefinition>(context, user, reference.standard_id, { type: ENTITY_TYPE_MARKING_DEFINITION });
    if (marking) {
      markingIds.push(marking.id);
    } else if (!plannedMarkings?.has(reference.standard_id)) {
      missing.push(reference.definition);
    }
  }
  return { markingIds, missing };
};

type MapperRepresentations = { attributes: { key?: unknown; default_values?: unknown }[] }[];

const MARKING_ID_PREFIX = 'marking-definition--';

// A default value of the mapper that is not on the platform is removed when the mapper is written: a missing marking stops the feed,
// the attributes that lose another value are reported
const missingDefaultValues = async (context: AuthContext, user: AuthUser, representations: MapperRepresentations, plannedMarkings?: Map<string, unknown>) => {
  const references = representations.flatMap(({ attributes }) => attributes.flatMap((attribute) => {
    const values = Array.isArray(attribute.default_values) ? attribute.default_values : [];
    return values
      .filter((value): value is string => typeof value === 'string' && !!isStixId(value) && !plannedMarkings?.has(value))
      .map((id) => ({ key: String(attribute.key), id }));
  }));
  if (references.length === 0) {
    return { markings: [], attributes: [] };
  }
  const ids = [...new Set(references.map(({ id }) => id))];
  const found = await internalFindByIds(context, user, ids, { baseData: true, toMap: true, mapWithAllIds: true }) as unknown as Record<string, unknown>;
  const missing = references.filter(({ id }) => !found[id]);
  return {
    markings: [...new Set(missing.filter(({ id }) => id.startsWith(MARKING_ID_PREFIX)).map(({ id }) => id))],
    attributes: [...new Set(missing.filter(({ id }) => !id.startsWith(MARKING_ID_PREFIX)).map(({ key }) => key))],
  };
};

const missingDefaultValuesReasons = (keys: string[]) => (keys.length > 0 ? [`Mapper default values not found: ${configImportReasonValue(keys.join(', '))}`] : []);

// A null clears the field: [null] would be written as a value (false for a boolean)
const toInputValue = (value: unknown) => (Array.isArray(value) ? value : (value == null ? [] : [value]));

const commonFields = (configuration: FeedImportConfiguration, name: string): FeedFields => ({
  name,
  description: configuration.description ?? null,
  scheduling_period: configuration.scheduling_period ?? null,
  uri: configuration.uri,
  ssl_verify: configuration.ssl_verify ?? null,
});

const authenticationFields = (configuration: { authentication_type: IngestionAuthType }, write: WriteContext): FeedFields => ({
  authentication_type: configuration.authentication_type,
  ...(write.authenticationValue !== undefined ? { authentication_value: write.authenticationValue } : {}),
});

const rssAdapter: FeedAdapter<RssFeedImportConfiguration, BasicStoreEntityIngestionRss> = {
  schema: rssFeedImportSchema,
  list: findAllRssIngestion,
  exportFeed: exportRssFeed,
  fields: async (context, user, configuration, write) => {
    const author = configuration.author ? await internalLoadById<BasicStoreEntity>(context, user, configuration.author.standard_id) : undefined;
    const reasons = configuration.author && !author ? [`Author not found: ${configImportReasonValue(configuration.author.name)}`] : [];
    return {
      fields: {
        report_types: configuration.report_types,
        object_marking_refs: write.markingIds,
        created_by_ref: author?.id ?? null,
      },
      reasons,
    };
  },
  add: (context, user, input) => addRssFeed(context, user, input as never),
  edit: editRssFeed,
  supportsAutomaticUser: true,
};

const csvAdapter: FeedAdapter<CsvFeedImportConfiguration, BasicStoreEntityIngestionCsv> = {
  schema: csvFeedImportSchema,
  list: findAllCsvIngestion,
  exportFeed: exportCsvFeed,
  fields: async (context, user, configuration, write) => {
    const missing = await missingDefaultValues(context, user, configuration.csv_mapper.representations, write.plannedMarkings);
    const representations = structuredClone(configuration.csv_mapper.representations) as unknown as CsvMapperRepresentation[];
    if (!write.dryRun && missing.markings.length === 0) {
      await convertRepresentationsIds(context, user, representations, 'stix');
    }
    return {
      fields: {
        ...authenticationFields(configuration, write),
        markings: write.markingIds,
        csv_mapper_type: IngestionCsvMapperType.Inline,
        csv_mapper: JSON.stringify({ ...configuration.csv_mapper, representations }),
      },
      reasons: missingDefaultValuesReasons(missing.attributes),
      missingMarkings: missing.markings,
    };
  },
  add: (context, user, input) => addIngestionCsv(context, user, input as never),
  edit: ingestionCsvEditField,
  supportsAutomaticUser: true,
};

const findJsonMappersByName = async (context: AuthContext, user: AuthUser, name: string) => {
  const filters = { mode: FilterMode.And, filterGroups: [], filters: [{ key: ['name'], values: [name] }] };
  const mappers = await fullEntitiesList<BasicStoreEntityJsonMapper>(context, user, [ENTITY_TYPE_JSON_MAPPER], { filters });
  return mappers.filter((mapper) => mapper.name === name);
};

// Compared as the export writes it: representations with standard ids
const isSameJsonMapper = async (context: AuthContext, user: AuthUser, mapper: BasicStoreEntityJsonMapper, configuration: JsonFeedImportConfiguration) => {
  const representations = JSON.parse(mapper.representations ?? '[]') as JsonMapperRepresentation[];
  await convertRepresentationsIds(context, user, representations, 'internal');
  const variables = mapper.variables ? JSON.parse(mapper.variables) : [];
  const { variables: bundleVariables, representations: bundleRepresentations } = configuration.json_mapper;
  return R.equals(withoutNil({ variables, representations }), withoutNil({ variables: bundleVariables, representations: bundleRepresentations }));
};

const findJsonMapper = async (context: AuthContext, user: AuthUser, configuration: JsonFeedImportConfiguration) => {
  const mappers = await findJsonMappersByName(context, user, configuration.json_mapper.name);
  for (let i = 0; i < mappers.length; i += 1) {
    if (await isSameJsonMapper(context, user, mappers[i], configuration)) {
      return { mapper: mappers[i], sameContent: true };
    }
  }
  return { mapper: mappers[0], sameContent: false };
};

const jsonAdapter: FeedAdapter<JsonFeedImportConfiguration, BasicStoreEntityIngestionJson> = {
  schema: jsonFeedImportSchema,
  list: findAllJsonIngestion,
  exportFeed: exportJsonFeed,
  fields: async (context, user, configuration, write) => {
    let jsonMapperId: string | undefined;
    let rollback: (() => Promise<void>) | undefined;
    const { mapper: existingMapper, sameContent } = await findJsonMapper(context, user, configuration);
    const missing = existingMapper
      ? { markings: [], attributes: [] }
      : await missingDefaultValues(context, user, configuration.json_mapper.representations, write.plannedMarkings);
    if (existingMapper) {
      jsonMapperId = existingMapper.id;
    } else if (!write.dryRun && missing.markings.length === 0) {
      const { json_mapper: { name, variables, representations } } = configuration;
      const mapperRepresentations = structuredClone(representations) as unknown as JsonMapperRepresentation[];
      const created = await createJsonMapperFromConfiguration(context, user, { name, variables, representations: mapperRepresentations });
      jsonMapperId = created.id;
      rollback = async () => {
        await deleteJsonMapper(context, user, created.id);
      };
    }
    return {
      fields: {
        ...authenticationFields(configuration, write),
        markings: write.markingIds,
        verb: configuration.verb,
        body: configuration.body ?? null,
        headers: configuration.headers.map((header) => ({ ...header, value: write.headerValues[header.name] ?? header.value })),
        query_attributes: configuration.query_attributes.map((attribute) => (isSensitiveQueryAttribute(attribute) && queryAttributeCredentialKey(attribute) in write.queryDefaults
          ? { ...attribute, default: write.queryDefaults[queryAttributeCredentialKey(attribute)] }
          : attribute)),
        pagination_with_sub_page: configuration.pagination_with_sub_page ?? null,
        pagination_with_sub_page_attribute_path: configuration.pagination_with_sub_page_attribute_path ?? null,
        pagination_with_sub_page_query_verb: configuration.pagination_with_sub_page_query_verb ?? null,
        json_mapper_id: jsonMapperId,
      },
      reasons: existingMapper
        ? (sameContent ? [] : [`JSON mapper ${configImportReasonValue(configuration.json_mapper.name)} already exists with another content: the feed uses it`])
        : [`JSON mapper created: ${configImportReasonValue(configuration.json_mapper.name)}`, ...missingDefaultValuesReasons(missing.attributes)],
      missingMarkings: missing.markings,
      rollback,
    };
  },
  add: (context, user, input) => addIngestionJson(context, user, input as never),
  edit: ingestionJsonEditField,
  supportsAutomaticUser: false,
};

const taxiiAdapter: FeedAdapter<TaxiiFeedImportConfiguration, BasicStoreEntityIngestionTaxii> = {
  schema: taxiiFeedImportSchema,
  list: findAllTaxiiIngestion,
  exportFeed: (context, _user, feed) => exportTaxiiFeed(context, feed),
  fields: async (_context, _user, configuration, write) => ({
    fields: {
      ...authenticationFields(configuration, write),
      version: configuration.version,
      collection: configuration.collection,
      added_after_start: configuration.added_after_start ?? null,
      confidence_to_score: configuration.confidence_to_score ?? null,
    },
    reasons: [],
  }),
  add: (context, user, input) => ingestionTaxiiAdd(context, user, input as never),
  edit: ingestionTaxiiEditField,
  supportsAutomaticUser: true,
};

const FEED_ADAPTERS = { rss: rssAdapter, csv: csvAdapter, json: jsonAdapter, taxii: taxiiAdapter };
export type FeedKind = keyof typeof FEED_ADAPTERS;
export const feedAdapterOf = (kind: FeedKind) => FEED_ADAPTERS[kind] as unknown as FeedAdapter<FeedImportConfiguration, StoredFeed>;

const refused = (
  code: FeedImportCode,
  reason: string,
  exists: boolean,
  configuration?: FeedImportConfiguration,
  credentials?: ConfigPresetImportCredential[],
): FeedImportResult => ({ status: 'failed', code, reason, exists, configuration, credentials });

const freeServiceAccountName = (context: AuthContext, name: string) => {
  return freeConfigImportName(`[F] ${name}`, (candidate) => userAlreadyExists(context, candidate));
};

const authenticationTypeOf = (configuration: FeedImportConfiguration) => {
  return 'authentication_type' in configuration ? configuration.authentication_type : IngestionAuthType.None;
};

// Credentials are never in the bundle: the parts the authentication type needs, the secrets of the URI, the values of the sensitive headers
// and query attribute defaults of a JSON feed. A credential is stored when the overwritten feed holds it for the same server: it is then kept
// unless a new value is given. A feed moved to another server keeps none of them
const keptTarget = <F extends StoredFeed>(configuration: FeedImportConfiguration, target?: F) => {
  return target && isSameUriDestination(target.uri, configuration.uri) ? target : undefined;
};

const feedCredentials = (configuration: FeedImportConfiguration, target?: StoredFeed): ConfigPresetImportCredential[] => {
  const kept = keptTarget(configuration, target);
  const authenticationType = authenticationTypeOf(configuration);
  const storedAuthentication = !!kept && 'authentication_type' in kept && kept.authentication_type === authenticationType && !!kept.authentication_value;
  const authentication = (AUTHENTICATION_PARTS[authenticationType] ?? []).map(({ key, description, secret, required }) => ({
    key,
    description,
    required,
    stored: storedAuthentication,
    secret,
    type: 'string',
  }));
  // A blank URI value can be empty on purpose (a paging parameter, a token as user name): it is required only when the feed held one
  const uri = uriCredentials(configuration.uri, kept?.uri).map(({ key, description, stored }) => ({
    key,
    description,
    required: stored !== '',
    stored: stored !== '',
    secret: true,
    type: 'string',
  }));
  const keptHeaders = kept && 'headers' in kept ? kept.headers ?? [] : [];
  const headers = ('headers' in configuration ? configuration.headers : [])
    .filter(({ name, value }) => value === '' && isSensitiveHeaderName(name))
    .map(({ name }) => ({
      key: feedHeaderCredentialKey(name),
      description: `Value of the header ${name}`,
      required: true,
      stored: keptHeaders.some((header) => header.name === name && header.value !== ''),
      secret: true,
      type: 'string',
    }));
  // The default of a sensitive query attribute is blanked too; it can be empty on purpose (a paging token), so it is optional
  const keptAttributes = kept && 'query_attributes' in kept ? kept.query_attributes ?? [] : [];
  const queryAttributes = ('query_attributes' in configuration ? configuration.query_attributes : [])
    .filter((attribute) => isSensitiveQueryAttribute(attribute) && !attribute.default)
    .filter((attribute, index, all) => all.findIndex((other) => queryAttributeCredentialKey(other) === queryAttributeCredentialKey(attribute)) === index)
    .filter((attribute) => !headers.some(({ key }) => key === queryAttributeCredentialKey(attribute)))
    .map((attribute) => ({
      key: queryAttributeCredentialKey(attribute),
      description: `Default value of ${attribute.to}`,
      required: false,
      stored: keptAttributes.some((stored) => queryAttributeCredentialKey(stored) === queryAttributeCredentialKey(attribute) && !!stored.default),
      secret: true,
      type: 'string',
    }));
  return [...authentication, ...uri, ...headers, ...queryAttributes];
};

const sameFieldValue = (key: string, current: unknown, next: unknown) => {
  if (key === 'added_after_start') {
    const time = (value: unknown) => (value ? new Date(value as string).getTime() : null);
    return time(current) === time(next);
  }
  // An empty list and an absent field are the same: a feed without markings may have none stored
  const normalized = (value: unknown) => (Array.isArray(value) && value.length === 0 ? null : withoutNil(value ?? null));
  return R.equals(normalized(current), normalized(next));
};

const authenticationValueOf = async (
  configuration: FeedImportConfiguration,
  credentials: ConfigPresetImportCredential[],
  given: Record<string, string>,
  target?: StoredFeed,
) => {
  const parts = AUTHENTICATION_PARTS[authenticationTypeOf(configuration)] ?? [];
  if (!parts.some(({ key }) => (given[key] ?? '') !== '')) {
    return undefined;
  }
  const isStored = credentials.some(({ key, stored }) => parts[0].key === key && stored);
  const current = isStored && target && 'authentication_value' in target ? ((await decryptIngestionCredential(target.authentication_value)) ?? '').split(':') : [];
  return parts.map(({ key }, index) => given[key] || current[index] || '').join(':');
};

const feedChanges = (fields: FeedFields, target: StoredFeed): EditInput[] => {
  const { authentication_type: authenticationType, authentication_value: _value, ...others } = fields;
  const current = target as unknown as Record<string, unknown>;
  const input: EditInput[] = Object.entries(others)
    .filter(([key, value]) => !sameFieldValue(key, current[key], value))
    .map(([key, value]) => ({ key, value: toInputValue(value) }));
  if ('authentication_type' in fields && current.authentication_type !== authenticationType) {
    input.push({ key: 'authentication_type', value: [authenticationType] });
  }
  return input;
};

export const importConfigPresetFeed = async <C extends FeedImportConfiguration, F extends StoredFeed>(
  context: AuthContext,
  user: AuthUser,
  adapter: FeedAdapter<C, F>,
  configuration: unknown,
  options: FeedImportOptions,
): Promise<FeedImportResult> => {
  const { mode, dryRun = false, reservedNames, credentials = {}, ingestionGroupPlanned = false, serviceAccountId, plannedMarkings } = options;
  if (isTooDeep(configuration)) {
    return refused('invalid', 'configuration: too deeply nested', false);
  }
  const parsed = adapter.schema.safeParse(configuration);
  if (!parsed.success) {
    return refused('invalid', configImportValidationReason(parsed.error), false);
  }
  const bundleFeed = parsed.data;
  const feeds = await adapter.list(context, user);
  const sameName = feeds.filter(({ name }) => name === bundleFeed.name);
  const exists = sameName.length > 0;
  // The credentials told back, whatever the mode and even on a refusal: stored is what the feed an overwrite targets holds,
  // so that the preview knows what each mode needs (a copy never keeps a stored one)
  const shownCredentials = feedCredentials(bundleFeed, sameName.length === 1 ? sameName[0] : undefined);
  try {
    verifyIngestionUri(bundleFeed.uri);
  } catch (error) {
    return refused('invalid', error instanceof Error ? error.message : String(error), exists, bundleFeed, shownCredentials);
  }
  if (exists && mode === ConfigImportMode.Add) {
    return refused('exists', 'Feed already exists', true, bundleFeed, shownCredentials);
  }
  const isCopy = mode === ConfigImportMode.Copy;
  if (!isCopy && (sameName.length > 1 || reservedNames?.has(bundleFeed.name))) {
    return refused('ambiguous', AMBIGUOUS_FEED_REASON, exists, bundleFeed, shownCredentials);
  }
  const target = isCopy ? undefined : sameName[0];
  const isNameTaken = async (candidate: string) => !!reservedNames?.has(candidate) || feeds.some(({ name }) => name === candidate);
  const name = isCopy ? await freeConfigImportName(bundleFeed.name, isNameTaken) : bundleFeed.name;
  if (!name) {
    return refused('name_conflict', 'Feed name already exists', exists, bundleFeed, shownCredentials);
  }
  const { markingIds, missing } = await resolveMarkings(context, user, 'markings' in bundleFeed ? bundleFeed.markings : [], plannedMarkings);
  if (missing.length > 0) {
    return refused('markings_not_found', `Markings not found: ${configImportReasonValue(missing.join(', '))}`, exists, bundleFeed, shownCredentials);
  }
  const feedCredentialsList = feedCredentials(bundleFeed, target);
  const given = Object.fromEntries(Object.entries(credentials).filter(([key, value]) => value !== '' && feedCredentialsList.some((credential) => credential.key === key)));
  // The platform's own export of the feed, nothing given: up to date, whatever the export blanked
  const { confidence_level: confidence } = bundleFeed;
  const feedUser = target?.user_id && confidence !== null && confidence !== undefined
    ? await storeLoadById<BasicStoreEntityUser>(context, user, target.user_id, ENTITY_TYPE_USER)
    : undefined;
  const confidenceReason = feedUser && feedUser.user_confidence_level?.max_confidence !== confidence ? CONFIDENCE_NOT_CHANGED_REASON : undefined;
  if (target && Object.keys(given).length === 0 && sameConfiguration(await adapter.exportFeed(context, user, target), bundleFeed)) {
    const reason = joinConfigImportReasons([CONFIG_IMPORT_UNCHANGED_REASON, confidenceReason]);
    return { status: 'skipped', code: 'unchanged', reason, exists: true, name, configuration: bundleFeed, credentials: shownCredentials };
  }
  const destinationReason = target && !isSameUriDestination(target.uri, bundleFeed.uri) ? DESTINATION_CHANGED_REASON : undefined;
  const missingCredentials = feedCredentialsList.filter(({ key, required, stored }) => required && !stored && !given[key]);
  if (missingCredentials.length > 0) {
    const missingReason = `Configuration to provide: ${missingCredentials.map(({ key }) => key).join(', ')}`;
    return refused('credentials_required', joinConfigImportReasons([destinationReason, missingReason]) ?? missingReason, exists, bundleFeed, shownCredentials);
  }
  const authenticationValue = await authenticationValueOf(bundleFeed, feedCredentialsList, given, target);
  if (authenticationValue !== undefined) {
    try {
      verifyIngestionAuthenticationContent(authenticationTypeOf(bundleFeed), authenticationValue);
    } catch (error) {
      return refused('invalid', error instanceof Error ? error.message : String(error), exists, bundleFeed, shownCredentials);
    }
  }
  if (!target && serviceAccountId && !(await storeLoadById(context, user, serviceAccountId, ENTITY_TYPE_USER))) {
    return refused('service_account_missing', 'Service account not found', exists, bundleFeed, shownCredentials);
  }
  if (!target && !serviceAccountId && !ingestionGroupPlanned && await isIngestionGroupMissing(context, user)) {
    return refused('no_ingestion_group', NO_INGESTION_GROUP_REASON, exists, bundleFeed, shownCredentials);
  }
  const kept = keptTarget(bundleFeed, target);
  const keptHeaders = kept && 'headers' in kept ? kept.headers ?? [] : [];
  const headerValues = Object.fromEntries(('headers' in bundleFeed ? bundleFeed.headers : [])
    .filter(({ name: headerName, value }) => value === '' && isSensitiveHeaderName(headerName))
    .map(({ name: headerName }) => [headerName, given[feedHeaderCredentialKey(headerName)] || keptHeaders.find((header) => header.name === headerName)?.value || '']));
  const keptAttributes = kept && 'query_attributes' in kept ? kept.query_attributes ?? [] : [];
  const queryDefaults = Object.fromEntries(('query_attributes' in bundleFeed ? bundleFeed.query_attributes : [])
    .filter((attribute) => isSensitiveQueryAttribute(attribute) && !attribute.default)
    .map((attribute) => {
      const key = queryAttributeCredentialKey(attribute);
      return [key, given[key] || keptAttributes.find((stored) => queryAttributeCredentialKey(stored) === key)?.default || ''];
    }));
  const uri = uriWithCredentials(bundleFeed.uri, Object.fromEntries(uriCredentials(bundleFeed.uri, kept?.uri)
    .map(({ key, stored }) => [key, given[key] ? encodeUriCredential(given[key]) : stored])));
  const write: WriteContext = { dryRun, markingIds, authenticationValue, headerValues, queryDefaults, plannedMarkings };
  const { fields: specificFields, reasons, missingMarkings = [], rollback } = await adapter.fields(context, user, bundleFeed, write, target);
  if (missingMarkings.length > 0) {
    return refused('markings_not_found', `Markings not found: ${configImportReasonValue(missingMarkings.join(', '))}`, exists, bundleFeed, shownCredentials);
  }
  const sslReason = target && bundleFeed.ssl_verify === false && target.ssl_verify !== false ? SSL_VERIFY_DISABLED_REASON : undefined;
  const fields = { ...commonFields(bundleFeed, name), uri, ...specificFields };
  // Nothing to write (a JSON mapper reused by its name, whatever the one of the bundle): up to date, not overwritten
  if (target && authenticationValue === undefined && feedChanges(fields, target).length === 0) {
    const reason = joinConfigImportReasons([CONFIG_IMPORT_UNCHANGED_REASON, confidenceReason, ...reasons]);
    return { status: 'skipped', code: 'unchanged', reason, exists: true, name, configuration: bundleFeed, credentials: shownCredentials };
  }
  const reason = joinConfigImportReasons([name !== bundleFeed.name ? `Added as "${name}"` : undefined, destinationReason, sslReason, confidenceReason, ...reasons]);
  const result: FeedImportResult = { status: target ? 'overwritten' : 'created', exists, name, configuration: bundleFeed, reason, credentials: shownCredentials };
  if (dryRun) {
    return result;
  }
  try {
    return await writeFeed(context, user, adapter, { fields, result, target, authenticationValue, serviceAccountId, confidence });
  } catch (error) {
    try {
      await rollback?.();
    } catch (rollbackError) {
      logApp.warn('[CONFIG PRESET] Feed import rollback failed', { cause: rollbackError, name });
    }
    throw error;
  }
};

const writeFeed = async <C extends FeedImportConfiguration, F extends StoredFeed>(
  context: AuthContext,
  user: AuthUser,
  adapter: FeedAdapter<C, F>,
  { fields, result, target, authenticationValue, serviceAccountId, confidence }: {
    fields: FeedFields;
    result: FeedImportResult;
    target?: F;
    authenticationValue?: string;
    serviceAccountId?: string;
    confidence?: number | null;
  },
): Promise<FeedImportResult> => {
  const name = fields.name as string;
  if (target) {
    const input = feedChanges(fields, target);
    if (input.length > 0) {
      await adapter.edit(context, user, target.id, input);
    }
    if (authenticationValue !== undefined) {
      await adapter.edit(context, user, target.id, [{ key: 'authentication_value', value: [authenticationValue] }]);
    }
    return { ...result, feed: target };
  }
  // A feed created without a value keeps the default of its type: a null would be indexed as false (ssl_verify off)
  const { ssl_verify: sslVerify, ...withoutSslVerify } = fields;
  const createdFields = { ...withoutSslVerify, ...(sslVerify != null ? { ssl_verify: sslVerify } : {}), ingestion_running: false };
  if (serviceAccountId) {
    return { ...result, feed: await adapter.add(context, user, { ...createdFields, user_id: serviceAccountId }) };
  }
  const serviceAccountName = (await freeServiceAccountName(context, name)) ?? `[F] ${name}`;
  const confidenceLevel = confidence ?? undefined;
  if (adapter.supportsAutomaticUser) {
    return { ...result, feed: await adapter.add(context, user, { ...createdFields, user_id: serviceAccountName, automatic_user: true, confidence_level: confidenceLevel }) };
  }
  const serviceAccount = await createIngestionAutomaticUser(context, user, { userName: serviceAccountName, serviceAccount: true, confidenceLevel });
  try {
    return { ...result, feed: await adapter.add(context, user, { ...createdFields, user_id: serviceAccount.id }) };
  } catch (error) {
    // Only when the feed was not written: a feed that exists keeps its service account
    try {
      const feeds = await adapter.list(context, user);
      if (!feeds.some((feed) => feed.user_id === serviceAccount.id)) {
        await userDelete(context, SYSTEM_USER, serviceAccount.id);
      }
    } catch (cleanupError) {
      logApp.warn('[CONFIG PRESET] Feed import service account cleanup failed', { cause: cleanupError, name });
    }
    throw error;
  }
};
