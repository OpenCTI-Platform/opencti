import type { GraphQLError } from 'graphql';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
import { AwsSigv4Signer } from '@opensearch-project/opensearch/aws';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import semver from 'semver';
import { ATTR_DB_QUERY_TEXT, ATTR_DB_NAMESPACE, ATTR_DB_OPERATION_NAME, SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION, SEMATTRS_DB_STATEMENT } from '@opentelemetry/semantic-conventions';
import * as jsonpatch from 'fast-json-patch';
import {
  buildPagination,
  buildPaginationFromEdges,
  ES_INDEX_PREFIX,
  getIndicesToQuery,
  INDEX_DELETED_OBJECTS,
  INDEX_DRAFT_OBJECTS,
  INDEX_INTERNAL_OBJECTS,
  isDraftIndex,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  offsetToCursor,
  pascalize,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_PLATFORM_INDICES,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  wait,
  waitInSec,
  WRITE_PLATFORM_INDICES,
} from './utils';
import conf, { booleanConf, extendedErrors, loadCert, logApp, logMigration } from '../config/conf';
import {
  ClientAbortError,
  ComplexSearchError,
  ConfigurationError,
  DatabaseError,
  EngineShardsError,
  FunctionalError,
  LockTimeoutError,
  TYPE_LOCK_ERROR,
  UnsupportedError,
} from '../config/errors';
import {
  isStixRefRelationship,
  isStixRefUnidirectionalRelationship,
  RELATION_CREATED_BY,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  RELATION_OBJECT_PARTICIPANT,
} from '../schema/stixRefRelationship';
import { ABSTRACT_BASIC_RELATIONSHIP, BASE_TYPE_RELATION, buildRefRelationKey, ID_INFERRED, ID_INTERNAL, isAbstract, REL_INDEX_PREFIX } from '../schema/general';
import { isModifiedObject, isUpdatedAtObject } from '../schema/fieldDataAdapter';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship } from '../schema/stixRelationship';
import { isStixCoreRelationship, RELATION_INDICATES, RELATION_LOCATED_AT, RELATION_PUBLISHES, RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { generateInternalId, INTERNAL_FROM_FIELD, INTERNAL_TO_FIELD } from '../schema/identifier';
import { controlUserRestrictDeleteAgainstElement, executionContext, INTERNAL_USERS, SYSTEM_USER, userFilterStoreElements } from '../utils/access';
import { now } from '../utils/format';
import { ENTITY_TYPE_MIGRATION_STATUS } from '../schema/internalObject';
import { meterManager, telemetry } from '../config/tracing';
import { isBooleanAttribute, isDateAttribute, isNumericAttribute, validateDataBeforeIndexing } from '../schema/schema-attributes';
import { extractEntityRepresentativeName, extractRepresentative } from './entity-representative';
import { extractFiltersFromGroup } from '../utils/filtering/filtering-utils';
import {
  ID_SUBFILTER,
  INSTANCE_DYNAMIC_REGARDING_OF,
  INSTANCE_REGARDING_OF,
  INSTANCE_REGARDING_OF_DIRECTION_FORCED,
  INSTANCE_REGARDING_OF_DIRECTION_REVERSE,
  RELATION_INFERRED_SUBFILTER,
  RELATION_TYPE_SUBFILTER,
} from '../utils/filtering/filtering-constants';
import { type Filter, type FilterGroup, FilterMode } from '../generated/graphql';
import { RELATION_IN_PIR } from '../schema/internalRelationship';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { buildEntityData } from './data-builder';
import { buildDraftFilter, isDraftSupportedEntity } from './draft-utils';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { getDraftContext } from '../utils/draftContext';
import { enrichWithRemoteCredentials } from '../config/credentials';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, isStixCyberObservable } from '../schema/stixCyberObservable';
import { lockResources } from '../lock/master-lock';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE, DRAFT_OPERATION_DELETE_LINKED, DRAFT_OPERATION_UPDATE_LINKED } from '../modules/draftWorkspace/draftOperations';
import { asyncMap } from '../utils/data-processing';
import { doYield } from '../utils/eventloop-utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicConnection, BasicNodeEdge, BasicStoreBase, BasicStoreEntity, BasicStoreRelation, StoreObject, StoreRelation } from '../types/store';
import { IDS_ATTRIBUTES } from '../domain/attribute-utils';
import { pushAll, unshiftAll } from '../utils/arrayUtil';
import { getRoleAssumerWithWebIdentity } from '../utils/awsSdk';
import { elConvertHits, elConvertHitsToMap } from './engine-data-converter';
import { engineMappingGenerator, getRetroCompatibleMappings } from './engine-mapping-generator';
import {
  BASE_FIELDS,
  buildDataRestrictions,
  buildFieldForQuery,
  computeQueryIndices,
  elGenerateFullTextSearchShould,
  elQueryBodyBuilder,
  findElementsDuplicateIds,
  NAMED_QUERIES_UNIQUENESS_SEPARATOR,
  POST_FILTER_TAG_SEPARATOR,
  type QueryBodyBuilderOpts,
  REL_COUNT_SCRIPT_FIELD,
  REL_DEFAULT_FETCH,
} from './engine-query-builder';
import { AbortError } from 'node-fetch';

const ELK_ENGINE = 'elk';
const OPENSEARCH_ENGINE = 'opensearch';
export const ES_MAX_CONCURRENCY: number = conf.get('elasticsearch:max_concurrency');
export const ES_INIT_MAPPING_MIGRATION: string = conf.get('elasticsearch:internal_init_mapping_migration') || 'off'; // off / old / standard
export const ES_IS_OLD_MAPPING: boolean = ES_INIT_MAPPING_MIGRATION === 'old';
export const ES_IS_INIT_MIGRATION: boolean = ES_INIT_MAPPING_MIGRATION === 'standard' || ES_IS_OLD_MAPPING;
export const ES_MINIMUM_FIXED_PAGINATION: number = 20; // When really low pagination is better by default
export const ES_DEFAULT_PAGINATION: number = conf.get('elasticsearch:default_pagination_result') || 500;
export const ES_MAX_PAGINATION: number = conf.get('elasticsearch:max_pagination_result') || 5000;
export const MAX_BULK_OPERATIONS: number = conf.get('elasticsearch:max_bulk_operations') || 5000;
export const MAX_RUNTIME_RESOLUTION_SIZE: number = conf.get('elasticsearch:max_runtime_resolutions') || 5000;
export const MAX_RELATED_CONTAINER_RESOLUTION: number = conf.get('elasticsearch:max_container_resolutions') || 1000;
export const MAX_RELATED_CONTAINER_OBJECT_RESOLUTION: number = conf.get('elasticsearch:max_container_object_resolutions') || 100000;
export const ES_INDEX_PATTERN_SUFFIX: string = conf.get('elasticsearch:index_creation_pattern');
const ES_MAX_RESULT_WINDOW: number = conf.get('elasticsearch:max_result_window') || 100000;
const ES_INDEX_SHARD_NUMBER: number = conf.get('elasticsearch:number_of_shards');
const ES_INDEX_REPLICA_NUMBER: number = conf.get('elasticsearch:number_of_replicas');

const ES_PRIMARY_SHARD_SIZE: string = conf.get('elasticsearch:max_primary_shard_size') || '50gb';
const ES_MAX_DOCS: number = conf.get('elasticsearch:max_docs') || 75000000;
const ES_CARDINALITY_THRESHOLD = 40000;

const TOO_MANY_CLAUSES = 'too_many_nested_clauses';
const DOCUMENT_MISSING_EXCEPTION = 'document_missing_exception';
export const ES_RETRY_ON_CONFLICT = 30;
export const BULK_TIMEOUT = '1h';
const ES_MAX_MAPPINGS = 3000;
const MAX_AGGREGATION_SIZE = 100;

export const ROLE_FROM = 'from';
export const ROLE_TO = 'to';
export const UNIMPACTED_ENTITIES_ROLE = [
  `${RELATION_CREATED_BY}_${ROLE_TO}`,
  `${RELATION_OBJECT_MARKING}_${ROLE_TO}`,
  `${RELATION_OBJECT_ASSIGNEE}_${ROLE_TO}`,
  `${RELATION_OBJECT_PARTICIPANT}_${ROLE_TO}`,
  `${RELATION_GRANTED_TO}_${ROLE_TO}`,
  `${RELATION_OBJECT_LABEL}_${ROLE_TO}`,
  `${RELATION_KILL_CHAIN_PHASE}_${ROLE_TO}`,
  `${RELATION_PUBLISHES}_${ROLE_FROM}`,
  `${RELATION_IN_PIR}_${ROLE_TO}`,
  // RELATION_OBJECT
  // RELATION_EXTERNAL_REFERENCE
  `${RELATION_INDICATES}_${ROLE_TO}`,
];
const LOCATED_AT_CLEANED = [ENTITY_TYPE_LOCATION_REGION, ENTITY_TYPE_LOCATION_COUNTRY];
const UNSUPPORTED_LOCATED_AT = [ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_TYPE_LOCATION_CITY];
export const isSpecialNonImpactedCases = (relationshipType: string, fromType: string, toType: string, side: string | null | undefined): boolean => {
  // The relationship is a related-to from an observable to "something" (generally, it is an intrusion set, a malware, etc.)
  // This is to avoid for instance Emotet having 200K related-to.
  // As a consequence, no entities view on the observable side.
  if (side === ROLE_TO && relationshipType === RELATION_RELATED_TO && isStixCyberObservable(fromType)) {
    return true;
  }
  // This relationship is a located-at from IPv4 / IPv6 / City to a country or a region
  // This is to avoid having too big region entities
  // As a consequence, no entities view in city / knowledge / regions,
  if (side === ROLE_TO && relationshipType === RELATION_LOCATED_AT && UNSUPPORTED_LOCATED_AT.includes(fromType) && LOCATED_AT_CLEANED.includes(toType)) {
    return true;
  }
  // Rel on the "to" side with targets from any threat to region / country / sector
  // Adding March 2025: For the NLQ, we now re-index those relationships for "in regards of threat victimology"
  // if (side === ROLE_TO && relationshipType === RELATION_TARGETS && [ENTITY_TYPE_LOCATION_REGION, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_IDENTITY_SECTOR].includes(toType)) {
  //   return true;
  // }
  return false;
};
export const isImpactedTypeAndSide = (type: string, fromType: string, toType: string, side: string): boolean => {
  if (isSpecialNonImpactedCases(type, fromType, toType, side)) {
    return false;
  }
  return !UNIMPACTED_ENTITIES_ROLE.includes(`${type}_${side}`);
};
export const isImpactedRole = (type: string, fromType: string, toType: string, role: string): boolean => {
  if (isSpecialNonImpactedCases(type, fromType, toType, role.split('_').at(1))) {
    return false;
  }
  return !UNIMPACTED_ENTITIES_ROLE.includes(role);
};

export let engine: ElkClient | OpenClient;
let isRuntimeSortingEnable = false;
let attachmentProcessorEnabled = false;

export const isAttachmentProcessorEnabled = () => {
  return attachmentProcessorEnabled;
};

// The OpenSearch/ELK Body Parser (oebp)
// Starting ELK8+, response are no longer inside a body envelop
// Query wrapping is still accepted in ELK8
export const oebp = (queryResult: any): any => {
  if (engine instanceof ElkClient) {
    return queryResult;
  }
  return queryResult.body;
};

export const elConfigureAttachmentProcessor = async (): Promise<boolean> => {
  let success = true;
  if (engine instanceof ElkClient) {
    await engine.ingest.putPipeline({
      id: 'attachment',
      description: 'Extract attachment information',
      processors: [
        {
          attachment: {
            field: 'file_data',
            remove_binary: true,
            // List of fields extracted by the attachment ingest processor.
            // The full list is available in the Elasticsearch docs:
            // (https://www.elastic.co/guide/en/elasticsearch/reference/8.19/attachment.html#attachment-fields).
            properties: [
              'content',
              'title',
              'author',
              'keywords',
              'date',
              'content_type',
              'content_length',
              'language',
              'modified',
              'format',
              // identifier,     NOT EXTRACTED
              // contributor,    NOT EXTRACTED
              // coverage,       NOT EXTRACTED
              'modifier',
              'creator_tool',
              // publisher,      NOT EXTRACTED
              // relation,       NOT EXTRACTED
              // rights,         NOT EXTRACTED
              // source,         NOT EXTRACTED
              // type,           NOT EXTRACTED
              'description',
              'print_date',
              'metadata_date',
              // latitude,       NOT EXTRACTED
              // longitude,      NOT EXTRACTED
              // altitude,       NOT EXTRACTED
              // rating,         NOT EXTRACTED
              'comments',
            ],
          },
        },
      ],
    }).catch((e) => {
      logApp.info('Engine attachment processor configuration fail', { cause: e });
      success = false;
    });
  } else {
    await engine.ingest.putPipeline({
      id: 'attachment',
      body: {
        description: 'Extract attachment information',
        processors: [
          {
            attachment: {
              field: 'file_data',
              // List of fields extracted by the attachment ingest processor, for OpenSearch.
              // The full list is available in the OS docs:
              // (https://docs.opensearch.org/latest/install-and-configure/additional-plugins/ingest-attachment-plugin/#extracted-information),
              // and code shows the check rejects unknown fields with an exception:
              // https://github.com/opensearch-project/OpenSearch/blob/315481148edaa43410e2e9f1801ec903fd62ec20/plugins/ingest-attachment/src/main/java/org/opensearch/ingest/attachment/AttachmentProcessor.java#L277
              properties: [
                'content',
                'title',
                'author',
                'keywords',
                'date',
                'content_type',
                'content_length',
                'language',
              ],
            },
          },
          {
            remove: {
              field: 'file_data',
            },
          },
        ],
      },
    }).catch((e) => {
      logApp.info('Engine attachment processor configuration fail', { cause: e });
      success = false;
    });
  }
  return success;
};

// Look for the engine version with OpenSearch client
export const searchEngineVersion = async () => {
  try {
    const { version: { distribution, number }, tagline } = oebp(await (engine as OpenClient).info());
    // Try to detect OpenSearch engine, based on https://github.com/opensearch-project/OpenSearch/blame/main/server/src/main/java/org/opensearch/action/main/MainResponse.java
    const platform = (distribution === OPENSEARCH_ENGINE || tagline?.includes('OpenSearch')) ? OPENSEARCH_ENGINE : ELK_ENGINE;
    return {
      platform: platform,
      version: number,
    } as const;
  } catch (e) {
    throw ConfigurationError('Search engine seems down', { cause: e });
  }
};

export const searchEngineInit = async (): Promise<boolean> => {
  logApp.info('[CHECK] Checking if Search engine is available');
  // Build the engine configuration
  const ca = conf.get('elasticsearch:ssl:ca')
    ? loadCert(conf.get('elasticsearch:ssl:ca'))
    : conf.get('elasticsearch:ssl:ca_plain') || null;
  const region = conf.get('opensearch:region');
  const elkSearchConfiguration = {
    node: conf.get('elasticsearch:url'),
    proxy: conf.get('elasticsearch:proxy') || null,
    auth: {
      username: conf.get('elasticsearch:username') || null,
      password: conf.get('elasticsearch:password') || null,
      apiKey: conf.get('elasticsearch:api_key') || null,
    },
    maxRetries: conf.get('elasticsearch:max_retries') || 3,
    requestTimeout: conf.get('elasticsearch:request_timeout') || 3600000,
    sniffOnStart: booleanConf('elasticsearch:sniff_on_start', false),
    ssl: { // For Opensearch 2+ and Elastic 7
      ca,
      rejectUnauthorized: booleanConf('elasticsearch:ssl:reject_unauthorized', true),
    },
    tls: { // For Elastic 8+
      ca,
      rejectUnauthorized: booleanConf('elasticsearch:ssl:reject_unauthorized', true),
    },
  };
  elkSearchConfiguration.auth = await enrichWithRemoteCredentials('elasticsearch', elkSearchConfiguration.auth);
  const openSearchConfiguration = {
    ...elkSearchConfiguration,
    ...(region ? AwsSigv4Signer({
      region,
      service: conf.get('opensearch:service') || 'es',
      getCredentials: () => {
        const credentialsProvider = defaultProvider({
          roleAssumerWithWebIdentity: getRoleAssumerWithWebIdentity({ region }),
        });
        return credentialsProvider();
      },
    }) : {}),
  };
  // Select the correct engine
  let engineVersion;
  let enginePlatform;
  const engineSelector = conf.get('elasticsearch:engine_selector') || 'auto';
  const engineCheck = booleanConf('elasticsearch:engine_check', true);
  const elasticSearchClient = new ElkClient(elkSearchConfiguration);
  const openSearchClient = new OpenClient(openSearchConfiguration);
  if (engineSelector === ELK_ENGINE) {
    logApp.info(`[SEARCH] Engine ${ELK_ENGINE} client selected by configuration`);
    engine = elasticSearchClient;
    const searchVersion = await searchEngineVersion();
    if (engineCheck && searchVersion.platform !== ELK_ENGINE) {
      throw ConfigurationError('Invalid Search engine selector', { configured: engineSelector, detected: searchVersion.platform });
    }
    enginePlatform = ELK_ENGINE;
    engineVersion = searchVersion.version;
  } else if (engineSelector === OPENSEARCH_ENGINE) {
    logApp.info(`[SEARCH] Engine ${OPENSEARCH_ENGINE} client selected by configuration`);
    engine = openSearchClient;
    const searchVersion = await searchEngineVersion();
    if (engineCheck && searchVersion.platform !== OPENSEARCH_ENGINE) {
      throw ConfigurationError('Invalid Search engine selector', { configured: engineSelector, detected: searchVersion.platform });
    }
    enginePlatform = OPENSEARCH_ENGINE;
    engineVersion = searchVersion.version;
  } else {
    logApp.info(`[SEARCH] Engine client not specified, trying to discover it with ${OPENSEARCH_ENGINE} client`);
    engine = openSearchClient;
    const searchVersion = await searchEngineVersion();
    enginePlatform = searchVersion.platform;
    logApp.info(`[SEARCH] Engine detected to ${enginePlatform}`);
    engineVersion = searchVersion.version;
    engine = enginePlatform === ELK_ENGINE ? elasticSearchClient : openSearchClient;
  }
  // Setup the platform runtime field option
  isRuntimeSortingEnable = enginePlatform === ELK_ENGINE && semver.satisfies(engineVersion, '>=7.12.x');
  const runtimeStatus = isRuntimeSortingEnable ? 'enabled' : 'disabled';
  // configure attachment processor
  attachmentProcessorEnabled = await elConfigureAttachmentProcessor();
  logApp.info(`[SEARCH][CHECK] Search Engine is alive. ${enginePlatform} (${engineVersion}) client selected / runtime sorting ${runtimeStatus} / attachment processor ${attachmentProcessorEnabled ? 'enabled' : 'disabled'}`);
  // Everything is fine, return true
  return true;
};
export const isRuntimeSortEnable = (): boolean => isRuntimeSortingEnable;

/**
 * Executes an engine operation with proper abort signal handling for both ElkClient and OpenSearch.
 * - ElkClient: passes the signal as an option natively.
 * - OpenSearch: manually hooks up the abort signal to call .abort() on the promise.
 */
const elExecuteWithAbortSignal = async (
  abortSignal: AbortSignal | undefined,
  elkOperation: (opts: { signal: AbortSignal | undefined }) => Promise<any>,
  openSearchOperation: () => Promise<any>,
): Promise<any> => {
  if (abortSignal?.aborted) {
    throw new AbortError('The http call was aborted before el request started.');
  }
  if (engine instanceof ElkClient) {
    const r = await elkOperation({ signal: abortSignal });
    return oebp(r);
  }
  const openSearchOperationPromise = openSearchOperation();
  const abortRequest = () => {
    // OpenSearch client does not support abort signal natively, so abort the request when possible.
    (openSearchOperationPromise as any).abort?.();
  };
  if (abortSignal) {
    abortSignal.addEventListener('abort', abortRequest, { once: true });
  }
  try {
    const r_1 = await openSearchOperationPromise;
    return oebp(r_1);
  } finally {
    if (abortSignal) {
      abortSignal.removeEventListener('abort', abortRequest);
    }
  }
};

const BULK_MAX_RETRIES = 5;
const BULK_INITIAL_DELAY_MS = 500;

const collectErrorFieldValues = (error: any, fieldName: string): string[] => {
  const values = [
    error?.[fieldName],
    error?.cause?.[fieldName],
    error?.cause?.meta?.body?.error?.[fieldName],
    error?.originalError?.[fieldName],
    error?.meta?.body?.error?.[fieldName],
    error?.extensions?.data?.cause?.[fieldName],
    error?.extensions?.data?.cause?.meta?.body?.error?.[fieldName],
    error?.extensions?.exception?.[fieldName],
  ];

  return values
    .filter((value): value is string => typeof value === 'string' && value.length > 0);
};

export const isTransitoryError = (error: any): boolean => {
  const statusCode = error?.statusCode
    ?? error?.meta?.statusCode
    ?? error?.status
    ?? error?.cause?.statusCode
    ?? error?.cause?.meta?.statusCode
    ?? error?.extensions?.data?.cause?.statusCode
    ?? error?.extensions?.data?.cause?.meta?.statusCode;
  // 429: Too many requests, 503: Service unavailable, both can be transient and should be retried
  if (statusCode === 429 || statusCode === 503) {
    return true;
  }

  const errorCode = error?.code
    ?? error?.cause?.code
    ?? error?.originalError?.code
    ?? error?.extensions?.data?.cause?.code;
  // All these error codes are commonly associated with transient issues that can occur in network communication
  // or when the search engine is under heavy load, and thus are good candidates for retrying the operation.
  if (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN'].includes(errorCode)) {
    return true;
  }

  const errorText = [
    ...collectErrorFieldValues(error, 'message'),
    ...collectErrorFieldValues(error, 'reason'),
    ...collectErrorFieldValues(error, 'type'),
    ...collectErrorFieldValues(error, 'name'),
    ...collectErrorFieldValues(error, 'stack'),
  ].join(' ');

  // All these error messages are commonly associated with transient issues that can occur when the search engine is under heavy load
  if (/circuit_breaking_exception|es_rejected_execution|too_many_requests|service_unavailable/i.test(errorText)) {
    return true;
  }
  return false;
};

// covers both engine clients: node-fetch's AbortError (ElkClient) and
// OpenSearch's RequestAbortedError.
export const isClientAbortError = (err: any): boolean => {
  return err instanceof AbortError || err?.name === 'AbortError' || err?.name === 'RequestAbortedError';
};

// Use this instead of throwing DatabaseError directly when catching an error
// from an abort-signal-aware engine call, so a client abort isn't misclassified
// as a genuine engine failure.
export const wrapEngineError = (reason: string, err: any, data: Record<string, any> = {}): GraphQLError => {
  if (isClientAbortError(err)) {
    return ClientAbortError(reason, { cause: err, ...data });
  }
  return DatabaseError(reason, { cause: err, ...data });
};

export const retryElOperations = async (operation: () => Promise<any>): Promise<any> => {
  for (let attempt = 0; attempt <= BULK_MAX_RETRIES; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      if (attempt < BULK_MAX_RETRIES && isTransitoryError(error)) {
        const delayMs = BULK_INITIAL_DELAY_MS * (2 ** attempt);
        logApp.warn(`[SEARCH] Bulk request transitory error, retrying in ${delayMs}ms (attempt ${attempt + 1}/${BULK_MAX_RETRIES})`, { cause: error });
        await wait(delayMs);
      } else {
        throw error;
      }
    }
  }
};

export const elRawSearch = (context: AuthContext, user: AuthUser, types: string[] | string | null, query: any) => {
  // Add default signal to prevent unwanted warning
  // Waiting for https://github.com/elastic/elastic-transport-js/issues/63
  const requestAbortSignal = context?.requestAbortSignal ?? new AbortController().signal;
  const elRawSearchFn = async () => {
    const parsedSearch = await elExecuteWithAbortSignal(
      requestAbortSignal,
      (opts) => (engine as ElkClient).search(query, opts),
      () => (engine as OpenClient).search(query),
    );
    if (parsedSearch._shards.failed > 0) {
    // We do not support response with shards failure.
    // Result must be always accurate to prevent data duplication and unwanted behaviors
    // If any shard fail during query, engine throw a shard exception with shards information
      throw EngineShardsError({ shards: parsedSearch._shards });
    }
    // Return result of the search if everything goes well
    return parsedSearch;
  };
  const retriedElRawSearchFn = async () => {
    const searchOperation = async () => elRawSearchFn();
    return retryElOperations(searchOperation);
  };
  return telemetry(context, user, `SELECT ${Array.isArray(types) ? types.join(', ') : (types || 'None')}`, {
    [ATTR_DB_NAMESPACE]: 'search_engine',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_NAME]: 'search_engine',
    [ATTR_DB_OPERATION_NAME]: 'read',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_OPERATION]: 'read',
    [ATTR_DB_QUERY_TEXT]: JSON.stringify(query),
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_STATEMENT]: JSON.stringify(query),
  }, retriedElRawSearchFn);
};

export const elRawGet = async (args: { id: string; index: string }) => {
  const rawGetOperation = async () => {
    if (engine instanceof ElkClient) {
      const r = await engine.get(args);
      return oebp(r);
    }
    const r_1 = await engine.get(args);
    return oebp(r_1);
  };
  return retryElOperations(rawGetOperation);
};
export const elRawIndex = async (args: any) => {
  const rawIndexOperation = async () => {
    if (engine instanceof ElkClient) {
      const r = await engine.index(args);
      return oebp(r);
    }
    const r_1 = await engine.index(args);
    return oebp(r_1);
  };
  return retryElOperations(rawIndexOperation);
};
export const elRawDelete = async (args: any) => {
  const rawDeleteOperation = async () => {
    if (engine instanceof ElkClient) {
      const r = await engine.delete(args);
      return oebp(r);
    }
    const r_1 = await engine.delete(args);
    return oebp(r_1);
  };
  return retryElOperations(rawDeleteOperation);
};
export const elRawDeleteByQuery = async (query: any) => {
  const rawDeleteOperation = async () => {
    if (engine instanceof ElkClient) {
      const r = await engine.deleteByQuery(query);
      return oebp(r);
    }
    const r_1 = await engine.deleteByQuery(query);
    return oebp(r_1);
  };
  return retryElOperations(rawDeleteOperation);
};
export const elRawBulk = async (context: AuthContext, args: any) => {
  const bulkOperation = async () => {
    return await elExecuteWithAbortSignal(
      context?.requestAbortSignal,
      (opts) => (engine as ElkClient).bulk(args, opts),
      () => (engine as OpenClient).bulk(args),
    );
  };
  return retryElOperations(bulkOperation);
};
export const elRawUpdateByQuery = async (query: any) => {
  const rawUpdateOperation = async () => {
    if (engine instanceof ElkClient) {
      const r = await engine.updateByQuery(query);
      return oebp(r);
    }
    const r_1 = await engine.updateByQuery(query);
    return oebp(r_1);
  };
  return retryElOperations(rawUpdateOperation);
};
export const elRawReindexByQuery = async (query: any) => {
  const rawReindexOperation = async () => {
    if (engine instanceof ElkClient) {
      const r = await engine.reindex(query);
      return oebp(r);
    }
    const r_1 = await engine.reindex(query);
    return oebp(r_1);
  };
  return retryElOperations(rawReindexOperation);
};

const elOperationForMigration = (operation: (query: any) => Promise<any>): (message: string, index: string, body: any) => Promise<any> => {
  const elGetTask = async (taskId: string): Promise<any> => {
    const taskArgs = { task_id: taskId };
    if (engine instanceof ElkClient) {
      const r = await engine.tasks.get(taskArgs);
      return oebp(r);
    }
    const r_1 = await engine.tasks.get(taskArgs);
    return oebp(r_1);
  };

  return async (message: string, index: string, body: any) => {
    logMigration.info(`${message} > started`);
    // Execute the update by query in async mode
    const queryAsync = await operation({
      ...(index ? { index } : {}),
      refresh: true,
      wait_for_completion: false,
      body,
    }).catch((err) => {
      throw DatabaseError('Async engine bulk migration fail', { migration: message, cause: err });
    });
    logMigration.info(`${message} > elastic running task ${queryAsync.task}`);
    // Wait 10 seconds for task to initialize
    await waitInSec(10);
    // Monitor the task until completion
    let taskStatus = await elGetTask(queryAsync.task);
    while (!taskStatus.completed) {
      const { total, updated } = taskStatus.task.status;
      logMigration.info(`${message} > in progress - ${updated}/${total}`);
      await waitInSec(5);
      taskStatus = await elGetTask(queryAsync.task);
    }
    const timeSec = Math.round(taskStatus.task.running_time_in_nanos / 1e9);
    logMigration.info(`${message} > done in ${timeSec} seconds`);
  };
};

export const elUpdateByQueryForMigration = elOperationForMigration(elRawUpdateByQuery);
export const elDeleteByQueryForMigration = elOperationForMigration(elRawDeleteByQuery);
export const elReindexByQueryForMigration = elOperationForMigration(elRawReindexByQuery);

export const elIndexExists = async (indexName: string): Promise<boolean> => {
  const indexExistsArg = { index: indexName };
  if (engine instanceof ElkClient) {
    return engine.indices.exists(indexExistsArg);
  }
  const existOpenSearchResult = await engine.indices.exists(indexExistsArg);
  return oebp(existOpenSearchResult) === true || existOpenSearchResult.body === true;
};
export const elIndexGetAlias = async (indexName: string): Promise<any> => {
  const args = { index: indexName };
  if (engine instanceof ElkClient) {
    const r = await engine.indices.getAlias(args);
    return oebp(r);
  }
  const r_1 = await engine.indices.getAlias(args);
  return oebp(r_1);
};
export const elPlatformIndices = async (): Promise<any> => {
  const args = { index: `${ES_INDEX_PREFIX}*`, format: 'JSON' };
  if (engine instanceof ElkClient) {
    const r = await engine.cat.indices(args);
    return oebp(r);
  }
  const r_1 = await engine.cat.indices(args);
  return oebp(r_1);
};
export const elPlatformMapping = async (index: any): Promise<Record<string, any>> => {
  if (engine instanceof ElkClient) {
    const r = await engine.indices.getMapping({ index });
    return oebp(r)[index].mappings.properties;
  }
  const r_1 = await engine.indices.getMapping({ index });
  return oebp(r_1)[index].mappings.properties;
};
export const elIndexSetting = async (index: any): Promise<{ settings: any; rollover_alias: string }> => {
  let settings;
  if (engine instanceof ElkClient) {
    const r = await engine.indices.getSettings({ index });
    settings = oebp(r)[index].settings;
  } else {
    const r_1 = await engine.indices.getSettings({ index });
    settings = oebp(r_1)[index].settings;
  }

  const rollover_alias = engine instanceof ElkClient ? settings.index.lifecycle?.rollover_alias
    : settings.index.plugins?.index_state_management?.rollover_alias;
  return { settings, rollover_alias };
};
export const elPlatformTemplates = async (): Promise<any[]> => {
  const args = { name: `${ES_INDEX_PREFIX}*`, format: 'JSON' };
  if (engine instanceof ElkClient) {
    const r = await engine.cat.templates(args);
    return oebp(r);
  }
  const r_1 = await engine.cat.templates(args);
  return oebp(r_1);
};
const elCreateLifecyclePolicy = async () => {
  if (engine instanceof ElkClient) {
    await engine.ilm.putLifecycle({
      name: `${ES_INDEX_PREFIX}-ilm-policy`,
      body: {
        policy: {
          phases: {
            hot: {
              min_age: '0ms',
              actions: {
                rollover: {
                  max_primary_shard_size: ES_PRIMARY_SHARD_SIZE,
                  max_docs: ES_MAX_DOCS,
                },
                set_priority: {
                  priority: 100,
                },
              },
            },
          },
        },
      },
    }).catch((e) => {
      throw DatabaseError('Creating lifecycle policy fail', { cause: e });
    });
  } else {
    const policyPath = `_plugins/_ism/policies/${ES_INDEX_PREFIX}-ism-policy`;
    const policyBody = {
      policy: {
        description: 'OpenCTI ISM Policy',
        default_state: 'hot',
        states: [
          {
            name: 'hot',
            actions: [
              {
                rollover: {
                  min_primary_shard_size: ES_PRIMARY_SHARD_SIZE,
                  min_doc_count: ES_MAX_DOCS,
                },
              }],
            transitions: [],
          }],
        ism_template: {
          index_patterns: [`${ES_INDEX_PREFIX}*`],
          priority: 100,
        },
      },
    };
    // Check if the ISM policy already exists before creating it
    let existingPolicy;
    try {
      const existingPolicyRequestResult = await engine.transport.request({
        method: 'GET',
        path: policyPath,
      });
      existingPolicy = oebp(existingPolicyRequestResult);
    } catch {
      existingPolicy = null;
    }
    if (!existingPolicy) {
      // Policy does not exist: create it
      try {
        await engine.transport.request({
          method: 'PUT',
          path: policyPath,
          body: policyBody,
        });
      } catch (e: any) {
        throw DatabaseError('Creating lifecycle policy fail', { cause: e });
      }
    }
  }
};
const updateCoreSettings = async (): Promise<void> => {
  const putComponentTemplateArgs = {
    name: `${ES_INDEX_PREFIX}-core-settings`,
    create: false,
    body: {
      template: {
        settings: {
          index: {
            max_result_window: ES_MAX_RESULT_WINDOW,
            number_of_shards: ES_INDEX_SHARD_NUMBER,
            number_of_replicas: ES_INDEX_REPLICA_NUMBER,
          },
          analysis: {
            normalizer: {
              string_normalizer: {
                type: 'custom' as const,
                filter: ['lowercase', 'asciifolding'],
              },
            },
          },
        },
      },
    },
  };
  if (engine instanceof ElkClient) {
    await engine.cluster.putComponentTemplate(putComponentTemplateArgs).catch((e) => {
      throw DatabaseError('Creating component template fail', { cause: e });
    });
  } else {
    await engine.cluster.putComponentTemplate(putComponentTemplateArgs).catch((e) => {
      throw DatabaseError('Creating component template fail', { cause: e });
    });
  }
};

const computeIndexSettings = (rolloverAlias: string | null | undefined): any => {
  if (engine instanceof ElkClient) {
    // Rollover alias can be undefined for platform initialized <= 5.8
    const cycle = rolloverAlias ? {
      lifecycle: {
        name: `${ES_INDEX_PREFIX}-ilm-policy`,
        rollover_alias: rolloverAlias,
      },
    } : {};
    return {
      index: {
        mapping: {
          total_fields: {
            limit: ES_MAX_MAPPINGS,
          },
        },
        ...cycle,
      },
    };
  }
  // Rollover alias can be undefined for platform initialized <= 5.8
  const cycle = rolloverAlias ? {
    plugins: {
      index_state_management: {
        rollover_alias: rolloverAlias,
      },
    },
  } : {};
  return {
    mapping: {
      total_fields: {
        limit: ES_MAX_MAPPINGS,
      },
    },
    ...cycle,
  };
};

const updateIndexTemplate = async (name: string, mapping_properties: Record<string, any>): Promise<any> => {
  // compute pattern to be retro compatible for platform < 5.9
  // Before 5.9, only one pattern for all indices
  const index_pattern = name === `${ES_INDEX_PREFIX}-index-template` ? `${ES_INDEX_PREFIX}*` : `${name}*`;
  const putIndexTemplateArg = {
    name,
    create: false,
    body: {
      index_patterns: [index_pattern],
      template: {
        settings: computeIndexSettings(name),
        mappings: ES_IS_OLD_MAPPING ? {
          properties: getRetroCompatibleMappings(engine),
        } : {
          // Global option to prevent elastic to try any magic
          dynamic: 'strict' as const,
          date_detection: false,
          numeric_detection: false,
          properties: mapping_properties,
        },
      },
      composed_of: [`${ES_INDEX_PREFIX}-core-settings`],
      version: 3,
      _meta: {
        description: 'To generate opencti expected index mappings',
      },
    },
  };
  if (engine instanceof ElkClient) {
    return engine.indices.putIndexTemplate(putIndexTemplateArg).catch((e) => {
      throw DatabaseError('Creating index template fail', { cause: e });
    });
  }
  return engine.indices.putIndexTemplate(putIndexTemplateArg).catch((e) => {
    throw DatabaseError('Creating index template fail', { cause: e });
  });
};

const elCreateIndexTemplate = async (index: string, mappingProperties: Record<string, any>): Promise<any> => {
  // Compat with platform initiated prior 5.9.X
  const existsIndexTemplateArgs = { name: `${ES_INDEX_PREFIX}-index-template` };
  let isPriorVersionExist;
  if (engine instanceof ElkClient) {
    isPriorVersionExist = await engine.indices.existsIndexTemplate(existsIndexTemplateArgs).then((r) => oebp(r));
  } else {
    isPriorVersionExist = await engine.indices.existsIndexTemplate(existsIndexTemplateArgs).then((r) => oebp(r));
  }
  if (isPriorVersionExist) {
    return null;
  }
  // Create / update template
  const existsComponentTemplateArgs = { name: `${ES_INDEX_PREFIX}-core-settings` };
  let componentTemplateExist;
  if (engine instanceof ElkClient) {
    componentTemplateExist = await engine.cluster.existsComponentTemplate(existsComponentTemplateArgs);
  } else {
    componentTemplateExist = await engine.cluster.existsComponentTemplate(existsComponentTemplateArgs);
  }
  if (!componentTemplateExist) {
    await updateCoreSettings();
  }
  return updateIndexTemplate(index, mappingProperties);
};
const sortMappingsKeys = (o: Record<string, any>): Record<string, any> => (Object(o) !== o || Array.isArray(o) ? o
  : Object.keys(o).sort().reduce((a, k) => ({ ...a, [k]: sortMappingsKeys(o[k]) }), {}));
export const elUpdateIndicesMappings = async (): Promise<void> => {
  // Update core settings
  await updateCoreSettings();
  // Reset the templates
  const mappingProperties = engineMappingGenerator(engine);
  const templates = await elPlatformTemplates();
  for (let index = 0; index < templates.length; index += 1) {
    const template = templates[index];
    await updateIndexTemplate(template.name, mappingProperties);
  }
  // Update the current indices if needed
  const indices = await elPlatformIndices();
  for (let indicesIndex = 0; indicesIndex < indices.length; indicesIndex += 1) {
    const { index } = indices[indicesIndex];
    const { rollover_alias } = await elIndexSetting(index);
    const indexMappingProperties = await elPlatformMapping(index);
    const platformSettings = computeIndexSettings(rollover_alias);
    const putSettingsArgs = { index, body: platformSettings };
    if (engine instanceof ElkClient) {
      await engine.indices.putSettings(putSettingsArgs).catch((e) => {
        throw DatabaseError('Updating index settings fail', { index, cause: e });
      });
    } else {
      await engine.indices.putSettings(putSettingsArgs).catch((e) => {
        throw DatabaseError('Updating index settings fail', { index, cause: e });
      });
    }
    // Type collision is not supported, mappingProperties must be forced to exist mapping in this case
    const indexMappingEntries = Object.entries(indexMappingProperties);
    for (let indexMapping = 0; indexMapping < indexMappingEntries.length; indexMapping += 1) {
      const [indexMappingKey, indexMappingValue] = indexMappingEntries[indexMapping];
      const mappingToCreate = mappingProperties[indexMappingKey];
      const currentType = indexMappingValue.type ?? 'object'; // object have no type and only properties
      const expectedType = mappingToCreate?.type ?? 'object'; // object have no type and only properties
      // mappingToCreate can be undefined as attributes has been removed since platform existence.
      if (mappingToCreate && currentType !== expectedType) {
        // Incompatible upgrade detected, override target with source to prevent any collision
        // This situation can happen with very old schema indices
        // Old indices will be maintained in old state as this situation is supported by the platform
        mappingProperties[indexMappingKey] = indexMappingProperties[indexMappingKey];
      }
    }

    const operations = jsonpatch.compare(sortMappingsKeys(indexMappingProperties), sortMappingsKeys(mappingProperties));
    // We can only complete new mappings
    // Replace is not possible for existing ones
    const addOperations = operations
      .filter((o) => o.op === UPDATE_OPERATION_ADD)
      .filter((o) => {
        // Add operation can be executed only if Value is an object and:
        // > Properties added inside an existing object (operation ends with /properties) - isPropertiesCompletion
        // > Is a simple new attribute - isDirectType
        // > Is a simple mew object attribute, containing properties - isObjectType
        const isPropertiesCompletion = o.path.endsWith('/properties');
        const isDirectType = o.value.type;
        const isObjectType = o.value.properties;
        return R.is(Object, o.value) && (isPropertiesCompletion || isDirectType || isObjectType);
      });
    if (addOperations.length > 0) {
      const properties = jsonpatch.applyPatch(indexMappingProperties, addOperations).newDocument;
      const body = { properties };
      const putMappingArgs = { index, body };
      if (engine instanceof ElkClient) {
        await engine.indices.putMapping(putMappingArgs).catch((e) => {
          throw DatabaseError('Updating index mapping fail', { index, cause: e });
        });
      } else {
        await engine.indices.putMapping(putMappingArgs).catch((e) => {
          throw DatabaseError('Updating index mapping fail', { index, cause: e });
        });
      }
    }
  }
};
export const elDeleteIndex = async (index: string) => {
  const indexesToRemove = await elIndexGetAlias(index);
  try {
    let response;
    const deleteArgs = { index: Object.keys(indexesToRemove) };
    if (engine instanceof ElkClient) {
      response = await engine.indices.delete(deleteArgs);
    } else {
      response = await engine.indices.delete(deleteArgs);
    }
    logApp.info(`Index '${indexesToRemove}' deleted successfully.`, response);
  } catch (error: any) {
    logApp.error('Error deleting indexes:', error);
  }
};
export const elCreateIndex = async (index: string) => {
  const mappingProperties = engineMappingGenerator(engine);
  return elCreateIndexWithMapping(index, mappingProperties);
};
const elCreateIndexWithMapping = async (index: string, mappingProperties: Record<string, any>): Promise<any> => {
  await elCreateIndexTemplate(index, mappingProperties);
  const indexName = `${index}${ES_INDEX_PATTERN_SUFFIX}`;
  let isExist;
  const existsArgs = { index: indexName };
  if (engine instanceof ElkClient) {
    isExist = await engine.indices.exists(existsArgs).then((r) => oebp(r));
  } else {
    isExist = await engine.indices.exists(existsArgs).then((r) => oebp(r));
  }
  if (!isExist) {
    const createArgs = { index: indexName, body: { aliases: { [index]: {} } } };
    if (engine instanceof ElkClient) {
      return engine.indices.create(createArgs);
    }
    return engine.indices.create(createArgs);
  }
  return null;
};
export const elCreateIndices = async (indexesToCreate = WRITE_PLATFORM_INDICES): Promise<any[]> => {
  await updateCoreSettings();
  await elCreateLifecyclePolicy();
  const createdIndices = [];
  const mappingProperties = engineMappingGenerator(engine);
  for (let i = 0; i < indexesToCreate.length; i += 1) {
    const index = indexesToCreate[i];
    const createdIndex = await elCreateIndexWithMapping(index, mappingProperties);
    if (createdIndex) {
      createdIndices.push(oebp(createdIndex));
    }
  }
  return createdIndices;
};

// Initialize
export const initializeSchema = async () => {
  // New platform so delete all indices to prevent conflict
  const isInternalIndexExists = await elIndexExists(INDEX_INTERNAL_OBJECTS);
  if (isInternalIndexExists) {
    throw ConfigurationError('Fail initialize schema, index already exists, previous initialization fail '
      + 'because you kill the platform before the end of the initialization. Please remove your '
      + 'elastic/opensearch data and restart.');
  }
  // Create default indexes
  await elCreateIndices();
  logApp.info('[INIT] Search engine indexes loaded');
  return true;
};

export const elDeleteIndices = async (indexesToDelete: string[]): Promise<any[]> => {
  return Promise.all(
    indexesToDelete.map((index) => {
      if (engine instanceof ElkClient) {
        return engine.indices.delete({ index })
          .then((response) => oebp(response))
          .catch((err) => {
            /* v8 ignore next */
            if (err.meta.body && err.meta.body.error.type !== 'index_not_found_exception') {
              logApp.error('Indices deletion fail', { cause: err });
            }
          });
      }
      return engine.indices.delete({ index })
        .then((response) => oebp(response))
        .catch((err) => {
          /* v8 ignore next */
          if (err.meta.body && err.meta.body.error.type !== 'index_not_found_exception') {
            logApp.error('Indices deletion fail', { cause: err });
          }
        });
    }),
  );
};
export type ElFindByIdsOpts = {
  indices?: string[] | string | null;
  baseData?: boolean | null;
  baseFields?: string[];
  withoutRels?: boolean | null;
  toMap?: boolean;
  mapWithAllIds?: boolean;
  type?: string | string[] | null;
  relCount?: boolean | null;
  includeDeletedInDraft?: boolean | null;
  historyFiltering?: boolean;
};

// elFindByIds is not defined to use ordering or sorting (ordering is forced by creation date)
// It's a way to load a bunch of ids and use in list or map
export const elFindByIds = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  ids: string[] | string,
  opts: ElFindByIdsOpts = {},
): Promise<T[] | Record<string, T>> => {
  const {
    indices,
    baseData = false,
    baseFields = [],
    withoutRels = true,
    toMap = false,
    mapWithAllIds = false,
    type = null,
    relCount = false,
  } = opts;
  const idsArray = Array.isArray(ids) ? ids : [ids];
  const types = (Array.isArray(type) || isEmptyField(type)) ? type : [type] as string[];
  const processIds = idsArray.filter((id) => isNotEmptyField(id));
  if (processIds.length === 0) {
    return toMap ? {} as Record<string, T> : [] as T[];
  }
  const queryIndices = computeQueryIndices(indices, types);
  const computedIndices = getIndicesToQuery(context, user, queryIndices);
  const hits: T[] = [];
  // Leave room in split size compared to max pagination to minimize data loss risk in case of duplicated ids in database
  const splitSize = Math.max(ES_MAX_PAGINATION / 2, ES_DEFAULT_PAGINATION);
  const groupIds = R.splitEvery(splitSize, processIds);
  for (let index = 0; index < groupIds.length; index += 1) {
    const mustTerms = [];
    const workingIds = groupIds[index];
    const idsTermsPerType = [];
    const elementTypes = [...IDS_ATTRIBUTES];
    for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
      const elementType = elementTypes[indexType];
      const terms = { [`${elementType}.keyword`]: workingIds };
      idsTermsPerType.push({ terms });
    }
    const should = {
      bool: {
        should: idsTermsPerType,
        minimum_should_match: 1,
      },
    };
    mustTerms.push(should);
    if (types && types.length > 0) {
      const shouldType = {
        bool: {
          should: [
            { terms: { 'entity_type.keyword': types } },
            { terms: { 'parent_types.keyword': types } },
          ],
          minimum_should_match: 1,
        },
      };
      mustTerms.push(shouldType);
    }
    const restrictionOptions = { includeAuthorities: true, historyFiltering: opts.historyFiltering }; // By default include authorized through capabilities
    // If an admin ask for a specific element, there is no need to ask him to explicitly extends his visibility to doing it.
    const markingRestrictions = await buildDataRestrictions(context, user, restrictionOptions);
    pushAll(mustTerms, markingRestrictions.must);
    // Handle draft
    const draftMust = buildDraftFilter(context, user, opts);
    const body: any = {
      query: {
        bool: {
          // Put everything under filter to prevent score computation
          // Search without score when no sort is applied is faster
          filter: [{
            bool: {
              must: [...mustTerms, ...draftMust],
              must_not: markingRestrictions.must_not,
            },
          }],
        },
      },
    };
    if (relCount) {
      body.script_fields = {
        script_field_denormalization_count: REL_COUNT_SCRIPT_FIELD,
      };
    }
    const _source: { excludes: string[]; includes?: string[] } = { excludes: [] };
    if (withoutRels) _source.excludes.push(`${REL_INDEX_PREFIX}*`);
    if (baseData) _source.includes = [...BASE_FIELDS, ...baseFields];
    const query: {
      size: number;
      index: string;
      _source: { excludes: string[]; includes?: string[] };
      body: any;
      track_total_hits: boolean;
      docvalue_fields?: string[];
    } = {
      index: computedIndices,
      size: ES_MAX_PAGINATION,
      track_total_hits: false,
      _source,
      body,
    };
    if (withoutRels) { // Force denorm rel security
      query.docvalue_fields = REL_DEFAULT_FETCH;
    }
    logApp.debug('[SEARCH] elInternalLoadById', { query });
    const searchType = `${ids} (${types ? (types as string[]).join(', ') : 'Any'})`;
    const data = await elRawSearch(context, user, searchType, query).catch((err) => {
      throw wrapEngineError('Find direct ids fail', err, { query: JSON.stringify(query), searchType });
    });
    const elements = data.hits.hits;
    if (elements.length > workingIds.length) {
      const duplicatedIds = findElementsDuplicateIds(elements);
      logApp.info('Search query returned more elements than expected', { resultCount: elements.length, queryCount: workingIds.length, duplicatedIds });
      if (elements.length >= ES_MAX_PAGINATION) {
        throw DatabaseError('Ids loading returned more elements than paging allowed for, some elements could not be loaded', { resultCount: elements.length, queryCount: workingIds.length, duplicatedIds });
      }
    }
    if (elements.length > 0) {
      const convertedHits = await elConvertHits<T>(elements);
      pushAll(hits, convertedHits);
    }
  }
  if (toMap) {
    return elConvertHitsToMap<T>(hits, { mapWithAllIds });
  }
  return hits;
};
export const elLoadById = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  opts: { ignoreDuplicates?: boolean } & ElFindByIdsOpts = {},
) => {
  const hits = await elFindByIds<T>(context, user, id, { ...opts, withoutRels: false }) as T[];
  //* v8 ignore if */
  if (hits.length > 1) {
    if (opts.ignoreDuplicates) {
      logApp.warn('Id loading expect only one response', { id, hits: hits.length });
    } else {
      throw DatabaseError('Id loading expect only one response', { id, hits: hits.length });
    }
  }
  return R.head(hits);
};
export const elBatchIds = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elements: { id: string; type: string }[],
) => {
  const ids = elements.map((e) => e.id);
  const types = elements.map((e) => e.type);
  const mapHits = await elFindByIds<T>(context, user, ids, { type: types, includeDeletedInDraft: true, toMap: true }) as Record<string, T>;
  const findHits = [];
  for (let index = 0; index < ids.length; index++) {
    const id = ids[index];
    if (INTERNAL_USERS[id]) {
      findHits.push(INTERNAL_USERS[id]);
    } else {
      findHits.push(mapHits[id]);
    }
  }
  return findHits;
};
export const elBatchIdsWithRelCount = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elements: { id: string; type: string }[],
) => {
  const ids = elements.map((e) => e.id);
  const types = elements.map((e) => e.type);
  const opts = { type: types, includeDeletedInDraft: true, relCount: true, baseData: true };
  const hits = await elFindByIds<T>(context, user, ids, opts) as T[];
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
};

const buildSearchResult = <T extends BasicStoreBase>(
  elements: (T & { regardingOfTypes?: any })[],
  first: number,
  searchAfter: string | undefined | null,
  globalCount: number,
  filterCount: number,
  connectionFormat: boolean,
) => {
  if (connectionFormat) {
    const nodeHits = elements.map((n) => ({ node: n, sort: n.sort, types: n.regardingOfTypes }));
    return buildPagination(first, searchAfter, nodeHits, globalCount, filterCount);
  }
  return elements;
};

const tagFiltersForPostFiltering = (
  filters: FilterGroup | undefined | null,
  noRegardingOfFilterIdsCheck?: boolean,
) => {
  const taggedFilters: (Filter & { postFilteringTag: string })[] = filters
    ? extractFiltersFromGroup(filters, [INSTANCE_REGARDING_OF, INSTANCE_DYNAMIC_REGARDING_OF])
        .filter((filter) => isEmptyField(filter.operator) || filter.operator === 'eq')
        .map((filter, i) => {
          const taggedFilter = filter as Filter & { postFilteringTag: string };
          taggedFilter.postFilteringTag = `${i}`;
          return taggedFilter;
        })
    : [];

  if (taggedFilters.length > 0) {
    return async <T extends BasicStoreBase>(context: AuthContext, user: AuthUser, elementsIds: string[]) => {
      const postFilters: { tag: string; postFilter: (element: T) => boolean }[] = [];
      for (let i = 0; i < taggedFilters.length; i++) {
        const taggedFilter = taggedFilters[i];
        postFilters.push({
          tag: taggedFilter.postFilteringTag,
          postFilter: await buildRegardingOfFilter<T>(context, user, elementsIds, taggedFilter, noRegardingOfFilterIdsCheck),
        });
      }
      return (element: T, tagsToIgnore: Set<string>) =>
        postFilters
          .filter(({ tag }) => !tagsToIgnore.has(tag))
          .every(({ postFilter }) => postFilter(element));
    };
  }
  return undefined;
};

export type PaginateOpts = QueryBodyBuilderOpts & {
  baseData?: boolean;
  baseFields?: string[];
  bypassSizeLimit?: boolean;
  withoutRels?: boolean;
  types?: string[] | string | null;
  withResultMeta?: boolean;
  first?: number;
  filters?: FilterGroup | null;
  connectionFormat?: boolean;
};
type PaginateResultWithMeta<T extends BasicStoreBase> = {
  elements: T[] | BasicConnection<T>;
  endCursor: string | null;
  total: number;
  filterCount: number;
};
export const elPaginate = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined | null,
  options: PaginateOpts = {},
): Promise<BasicConnection<T> | T[] | PaginateResultWithMeta<T>> => {
  const {
    baseData = false,
    baseFields = [],
    bypassSizeLimit = false,
    withoutRels = true,
    types = null,
    withResultMeta = false,
    first = ES_DEFAULT_PAGINATION,
    connectionFormat = true,
    noRegardingOfFilterIdsCheck = false,
  } = options;
  // tagFiltersForPostFiltering have side effect on options.filters, it must be done before elQueryBodyBuilder
  const createPostFilter = tagFiltersForPostFiltering(options.filters, noRegardingOfFilterIdsCheck);
  const body = await elQueryBodyBuilder(context, user, options);
  if (body.size > ES_MAX_PAGINATION && !bypassSizeLimit) {
    logApp.info('[SEARCH] Pagination limited to max result config', { size: body.size, max: ES_MAX_PAGINATION });
    body.size = ES_MAX_PAGINATION;
  }
  const _source: { excludes: string[]; includes?: string[] } = { excludes: [] };
  if (withoutRels) _source.excludes.push(`${REL_INDEX_PREFIX}*`);
  if (baseData) _source.includes = [...BASE_FIELDS, ...baseFields];
  const query: any = {
    index: getIndicesToQuery(context, user, indexName),
    track_total_hits: true,
    _source,
    body,
  };
  if (withoutRels) { // Force denorm rel security
    query.docvalue_fields = REL_DEFAULT_FETCH;
  }
  logApp.debug('[SEARCH] paginate', { query });
  try {
    const { hits: { hits, total: { value: globalCount } } } = await elRawSearch(context, user, types !== null ? types : 'Any', query);
    const elements = await elConvertHits<T>(hits);
    let finalElements = elements;
    if (finalElements.length > 0 && createPostFilter) {
      // Since filters contains filters requiring post filtering (regardingOf, dynamicRegardingOf), a post-security filtering is needed
      const postFilter = await createPostFilter<T>(context, user, elements.map(({ id }) => id));
      finalElements = elements.filter((element, i) => {
        const dataHit = hits[i];
        const tagsToIgnoreSet = new Set<string>((dataHit.matched_queries ?? [])
          .flatMap((matchedQuery: string) => matchedQuery.split(NAMED_QUERIES_UNIQUENESS_SEPARATOR)[0].split(POST_FILTER_TAG_SEPARATOR)));
        return postFilter(element, tagsToIgnoreSet);
      });
    }
    const filterCount = elements.length - finalElements.length;
    const result = buildSearchResult(finalElements, first, body.search_after, globalCount, filterCount, connectionFormat);
    if (withResultMeta) {
      const lastProcessedSort = R.last(elements)?.sort;
      const endCursor = lastProcessedSort ? offsetToCursor(lastProcessedSort) : null;
      return { elements: result, endCursor, total: globalCount, filterCount };
    }
    return result;
  } catch (err: any) {
    const root_cause = err.meta?.body?.error?.caused_by?.type;
    if (root_cause === TOO_MANY_CLAUSES) throw ComplexSearchError();
    throw wrapEngineError('Fail to execute engine pagination', err, { root_cause, query: JSON.stringify(query), queryArguments: options });
  }
};
export type RepaginateOpts<T extends BasicStoreBase> = PaginateOpts & {
  maxSize?: number;
  logForMigration?: boolean;
  callback?: (elements: T[], globalCount: number) => Promise<boolean | undefined>;
};
const elRepaginate = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined | null,
  connectionFormat: boolean,
  opts: RepaginateOpts<T> = {},
) => {
  const {
    first = ES_DEFAULT_PAGINATION,
    maxSize = undefined,
    logForMigration = false,
    callback,
  } = opts;
  let batch = 0;
  let emitSize = 0;
  let globalHitsCount = 0;
  let totalFilteredCount = 0;
  let hasNextPage = true;
  let continueProcess = true;
  let searchAfter = opts.after;
  const listing: T[] | BasicNodeEdge<T>[] = [];
  while (continueProcess && (maxSize === undefined || emitSize < maxSize) && hasNextPage) {
    // Force options to get connection format and manage search after and metadata
    const paginateOpts = { ...opts, first, after: searchAfter, connectionFormat: true, withResultMeta: true };
    const { elements: page, filterCount, total, endCursor } = await elPaginate<T>(context, user, indexName, paginateOpts) as any;

    // when first === maxSize only one iteration is necessary except in case of post filtering
    if (first === maxSize && batch > 10) {
      logApp.warn('[PERFORMANCE] Expensive post filtering detected', { batch, opts });
    }
    if (logForMigration) {
      logMigration.info('Migrating loading batch...');
    }

    if (page.edges.length > 0) {
      const edgeToPublish = maxSize !== undefined ? page.edges.slice(0, maxSize - emitSize) : page.edges;
      const elements = connectionFormat ? edgeToPublish : await asyncMap(edgeToPublish, (edge: BasicNodeEdge<T>) => edge.node);
      if (callback) {
        const callbackResult = await callback(elements, total);
        continueProcess = callbackResult === true || callbackResult === undefined;
      } else {
        pushAll<T | BasicNodeEdge<T>>(listing, elements);
      }
      emitSize += elements.length;
    }

    batch += 1;
    hasNextPage = page.pageInfo.hasNextPage;
    searchAfter = endCursor;
    totalFilteredCount += filterCount;
    globalHitsCount = total - totalFilteredCount;
  }
  return { elements: listing, totalCount: globalHitsCount };
};

export const elConnection = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | null | undefined,
  opts: RepaginateOpts<T> = {},
) => {
  const { elements, totalCount } = await elRepaginate<T>(context, user, indexName, true, opts);
  return buildPaginationFromEdges<T>(opts.first, opts.after, elements as BasicNodeEdge<T>[], totalCount);
};

export const elList = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined | null,
  opts: RepaginateOpts<T> = {},
) => {
  const data = await elRepaginate<T>(context, user, indexName, false, opts);
  return data.elements as T[];
};

export const elLoadBy = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  field: string,
  value: any,
  type = null,
  indices: string[] = READ_DATA_INDICES,
) => {
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: [field], values: [value] }],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, types: type ? [type] : [] };
  const hits = await elPaginate<T>(context, user, indices, opts) as T[];
  if (hits.length > 1) {
    throw UnsupportedError('Id loading expected only one response', { size: hits.length });
  }
  return R.head(hits);
};

export const elRawCount = async (query: any): Promise<number> => {
  if (engine instanceof ElkClient) {
    return engine.count(query)
      .then((data) => {
        return oebp(data).count;
      });
  }
  return engine.count(query)
    .then((data) => {
      return oebp(data).count;
    });
};

export const elCardinalityCount = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined,
  field: string,
  options = {},
): Promise<number> => {
  const cardinalityAggs: any = {
    cardinality_count: {
      cardinality: {
        field: `${field}.keyword`,
        precision_threshold: ES_CARDINALITY_THRESHOLD,
      },
    },
  };
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  body.aggs = cardinalityAggs;
  const cardinalityQuery = {
    index: getIndicesToQuery(context, user, indexName),
    body,
  };
  const searchType = `Aggregations (${field})`;
  const cardinalityData = await elRawSearch(context, user, searchType, cardinalityQuery).catch((err) => {
    throw wrapEngineError('Cardinality computing fail', err, { cardinalityQuery: JSON.stringify(cardinalityQuery) });
  });
  return cardinalityData.aggregations.cardinality_count.value;
};

export const elCount = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined,
  options = {},
): Promise<number> => {
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  const query = { index: getIndicesToQuery(context, user, indexName), body };
  logApp.debug('[SEARCH] elCount', { query });
  return elRawCount(query);
};
export type HistogramCountOpts = QueryBodyBuilderOpts & {
  interval?: string;
  field?: string;
};
export const elHistogramCount = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined,
  options: HistogramCountOpts = {},
  unique: boolean = false,
  countField: string = '',
) => {
  const { interval, field, types = null } = options;
  const body = await elQueryBodyBuilder(context, user, { ...options, dateAttribute: field, noSize: true, noSort: true, intervalInclude: true });
  body.size = 0; // we only need aggregations
  let dateFormat;
  switch (interval) {
    case 'year':
      dateFormat = 'yyyy';
      break;
    case 'quarter':
    case 'month':
      dateFormat = 'yyyy-MM';
      break;
    case 'week':
    case 'day':
      dateFormat = 'yyyy-MM-dd';
      break;
    case 'hour':
      dateFormat = 'yyyy-MM-dd hh:mm:ss';
      break;
    default:
      throw FunctionalError('Unsupported interval, please choose between year, quarter, month, week, day or hour', { interval });
  }
  const uniqueAggregation = {
    unique: {
      cardinality: {
        field: `${countField}.keyword`,
      },
    },
  };
  const sumAggregation = {
    weight: {
      sum: {
        field: 'i_inference_weight',
        missing: 1,
      },
    },
  };
  body.aggs = {
    count_over_time: {
      date_histogram: {
        field,
        calendar_interval: interval,
        // time_zone: tzStart,
        format: dateFormat,
        keyed: true,
      },
      aggs: unique ? uniqueAggregation : sumAggregation,
    },
  };
  const query = {
    index: getIndicesToQuery(context, user, indexName),
    _source_excludes: '*', // Dont need to get anything
    body,
  };
  logApp.debug('[SEARCH] histogramCount', { query });
  return elRawSearch(context, user, types, query).then((data) => {
    const { buckets } = data.aggregations.count_over_time;
    const dataToPairs = R.toPairs(buckets);
    return R.map((b) => ({ date: R.head(b), value: R.last(b)[unique ? 'unique' : 'weight'].value }), dataToPairs);
  });
};
type AggregationCountOpts = QueryBodyBuilderOpts & {
  field: string;
  weightField?: string | null;
  normalizeLabel?: boolean | null;
  convertEntityTypeLabel?: boolean | null;
};
export const elAggregationCount = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string[] | string | undefined,
  options: AggregationCountOpts = { field: '' },
): Promise<{ label: string; value: any; count: number }[]> => {
  const { field, types = null, weightField = 'i_inference_weight', normalizeLabel = true, convertEntityTypeLabel = false } = options;
  const isIdFields = field?.endsWith('internal_id') || field?.endsWith('.id');
  const queryField = buildFieldForQuery(field);
  // Only keyword fields accept a string missing value; date/numeric/boolean/object-flat fields do not.
  const isKeywordField = queryField.endsWith('.keyword');
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  body.size = 0;
  body.aggs = {
    genres: {
      terms: {
        field: queryField,
        size: MAX_AGGREGATION_SIZE,
      },
      aggs: {
        weight: {
          sum: {
            field: weightField,
            missing: 1,
          },
        },
      },
    },
  };
  if (isKeywordField) {
    body.aggs.genres.terms.missing = 'unknown';
  }
  const query = {
    index: getIndicesToQuery(context, user, indexName),
    body,
  };
  logApp.debug('[SEARCH] aggregationCount', { query });
  return elRawSearch(context, user, types, query)
    .then((data) => {
      const { buckets } = data.aggregations.genres;
      return buckets.map((b: any) => {
        let label = b.key;
        if (typeof label === 'number') {
          label = String(b.key);
        } else if (field === 'entity_type' && convertEntityTypeLabel) {
          // entity_type is returned in lowercase, we want to return the label with the right entity type.
          label = isStixCoreRelationship(b.key) ? b.key : generateInternalType({ type: b.key });
        } else if (!isIdFields && normalizeLabel) {
          label = pascalize(b.key);
        }
        return { label, value: b.weight.value, count: b.doc_count };
      });
    })
    .catch((err) => {
      throw DatabaseError('Aggregation computation count fail', { cause: err, query });
    });
};

const extractNestedQueriesFromBool = (boolQueryArray: { bool: any }[], nestedPath = 'connections') => {
  let result: any[] = [];
  for (let i = 0; i < boolQueryArray.length; i += 1) {
    const boolQuery = boolQueryArray[i];
    const shouldArray = boolQuery.bool?.should ?? [];
    const nestedQueries = [];
    for (let j = 0; j < shouldArray.length; j += 1) {
      const queryElement = shouldArray[j];
      if (queryElement.nested && queryElement.nested.path === nestedPath) nestedQueries.push(queryElement.nested.query);
      if (queryElement.bool?.should) { // case nested is in an imbricated filterGroup (not possible for the moment)
        const nestedBoolResult = extractNestedQueriesFromBool([queryElement]);
        if (nestedBoolResult.length > 0) {
          nestedQueries.push(nestedBoolResult);
        }
      }
    }
    if (nestedQueries.length > 0) result = result.concat(nestedQueries);
  }
  return result;
};

// field can be "entity_type" or "internal_id"
const buildAggregationRelationFilters = async (
  context: AuthContext,
  user: AuthUser,
  aggregationFilters?: { filter: FilterGroup },
): Promise<{ bool: { must: any; must_not: any } }> => {
  const aggBody = await elQueryBodyBuilder(context, user, { ...aggregationFilters, noSize: true, noSort: true });
  return {
    bool: {
      must: extractNestedQueriesFromBool(aggBody.query.bool.must ?? []),
      must_not: extractNestedQueriesFromBool(aggBody.query.bool.must_not ?? []),
    },
  };
};
export type AggregationRelationsCount = {
  types?: string[];
  field?: string;
  searchOptions?: QueryBodyBuilderOpts;
  aggregationOptions?: { filter: FilterGroup };
  aggregateOnConnections?: boolean;
};
export const elAggregationRelationsCount = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined,
  options: AggregationRelationsCount = {},
): Promise<{ label: string; value: number }[]> => {
  const { types = [], field = null, searchOptions, aggregationOptions, aggregateOnConnections = true } = options;
  const aggregationFields = [
    'entity_type',
    'internal_id',
    'rel_object-marking.internal_id',
    'rel_kill-chain-phase.internal_id',
    'creator_id',
    'relationship_type',
    'x_opencti_workflow_id',
    'rel_created-by.internal_id',
    'pir_explanation.dependencies.author_id',
    null,
  ];
  if (!aggregationFields.includes(field)) {
    throw FunctionalError('Aggregation computing use an unsupported field', { field });
  }
  const body = await elQueryBodyBuilder(context, user, { ...searchOptions, noSize: true, noSort: true });
  const aggregationFilters = await buildAggregationRelationFilters(context, user, aggregationOptions);
  body.size = 0;
  const isAggregationConnection = aggregateOnConnections && (field === 'internal_id' || field === 'entity_type' || field === null);
  if (isAggregationConnection) {
    body.aggs = {
      connections: {
        nested: {
          path: 'connections',
        },
        aggs: {
          filtered: {
            filter: aggregationFilters,
            aggs: {
              genres: {
                terms: {
                  size: MAX_AGGREGATION_SIZE,
                  field: field === 'internal_id' ? 'connections.internal_id.keyword' : 'connections.types.keyword',
                },
                aggs: {
                  parent: {
                    reverse_nested: {},
                  },
                },
              },
            },
          },
        },
      },
    };
  } else {
    body.aggs = {
      genres: {
        terms: {
          field: field && isBooleanAttribute(field)
            ? field
            : `${field}.keyword`,
          size: MAX_AGGREGATION_SIZE,
        },
      },
    };
  }
  const query = { index: getIndicesToQuery(context, user, indexName), body };
  logApp.debug('[SEARCH] aggregationRelationsCount', { query });
  const isIdFields = field?.endsWith('internal_id');
  return elRawSearch(context, user, types, query)
    .then(async (data) => {
      if (isAggregationConnection) {
        const { buckets } = data.aggregations.connections.filtered.genres;
        if (field === 'internal_id') {
          return buckets.map((b: any) => ({ label: b.key, value: b.parent.doc_count }));
        }
        // entity_type
        const filteredBuckets = buckets.filter((b: any) => !(isAbstract(pascalize(b.key)) || isAbstract(b.key)));
        return R.map((b) => ({ label: pascalize(b.key), value: b.parent.doc_count }), filteredBuckets);
      }
      const { buckets } = data.aggregations.genres;
      return buckets.map((b: any) => {
        let label = b.key;
        if (typeof label === 'number') {
          label = b.key_as_string;
        } else if (!isIdFields) {
          label = pascalize(b.key);
        }
        return { label, value: b.doc_count };
      });
    })
    .catch((e) => {
      throw DatabaseError('Processing aggregation relations count fail', { cause: e });
    });
};
type AggregationNestedTermsWithFilterOpts = QueryBodyBuilderOpts & {
  size?: number;
};
export const elAggregationNestedTermsWithFilter = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string[] | string | undefined,
  aggregation: { path: string; field: string; filter: any },
  opts: AggregationNestedTermsWithFilterOpts = {},
): Promise<{ label: string; key: string; value: number }[]> => {
  const { types = [], size = ES_DEFAULT_PAGINATION } = opts;
  const { path, field, filter } = aggregation;
  const body = await elQueryBodyBuilder(context, user, { ...opts, noSize: true, noSort: true });
  body.size = 0;
  body.aggs = {
    nestedAgg: {
      nested: { path },
      aggs: {
        filterAggs: {
          filter,
          aggs: {
            termsAgg: {
              terms: { field, size },
            },
          },
        },
      },
    },
  };
  const query = {
    index: getIndicesToQuery(context, user, indexName),
    body,
  };
  logApp.debug('[SEARCH] elAggregationNestedTermsWithFilter', { query });
  return elRawSearch(context, user, types, query)
    .then((data) => {
      const aggBucketsResult = data.aggregations?.nestedAgg?.filterAggs?.termsAgg?.buckets ?? [];
      return aggBucketsResult.map((b: any) => {
        let label = b.key;
        if (typeof label === 'number') {
          label = String(b.key);
        }
        return { label, key: b.key, value: b.doc_count };
      });
    })
    .catch((err) => {
      throw DatabaseError('Aggregation computation count fail', { cause: err, query });
    });
};
type AggregationsListOpts = QueryBodyBuilderOpts & {
  resolveToRepresentative?: boolean;
  postResolveFilter?: (element: any) => Promise<any>;
};
export const elAggregationsList = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string[] | string | undefined,
  aggregations: { field: string; name: string }[],
  opts: AggregationsListOpts = {},
): Promise<{ name: string; values: any }[]> => {
  const { types = [], resolveToRepresentative = true, postResolveFilter } = opts;
  const queryAggs: any = {};
  aggregations.forEach((agg) => {
    queryAggs[agg.name] = {
      terms: {
        field: agg.field,
        size: 500, // Aggregate on top 500 should get all needed results
      },
    };
  });
  const body: any = {
    aggs: queryAggs,
    size: 0, // No limit on the search
  };
  if (types?.length) {
    // handle options for entity context (entity types)
    const searchBody = await elQueryBodyBuilder(context, user, opts);
    if (searchBody.query) {
      body.query = searchBody.query;
    }
  }
  const query = {
    index: getIndicesToQuery(context, user, indexName),
    track_total_hits: false,
    _source: false,
    body,
  };
  const searchType = `Aggregations (${aggregations.map((agg) => agg.field)?.join(', ')})`;
  const data = await elRawSearch(context, user, searchType, query).catch((err) => {
    throw wrapEngineError('Aggregations computing list fail', err, { query: JSON.stringify(query) });
  });
  const aggsMap = Object.keys(data.aggregations);
  const aggsValues = R.uniq(R.flatten(aggsMap.map((agg) => data.aggregations[agg].buckets?.map((b: { key: string }) => b.key))));
  if (resolveToRepresentative) {
    const baseFields = ['internal_id', 'name', 'entity_type']; // Needs to take elements required to fill extractEntityRepresentative function
    // If post filter is required, we need to retrieve all fields
    let aggsElements = await elFindByIds(context, user, aggsValues, { baseData: !postResolveFilter, baseFields }) as BasicStoreBase[];
    if (postResolveFilter) {
      aggsElements = await postResolveFilter(aggsElements);
    }
    const aggsElementsCache = R.mergeAll(aggsElements.map((element) => ({ [element.internal_id]: extractEntityRepresentativeName(element) })));
    return aggsMap.map((agg) => {
      const values = data.aggregations[agg].buckets?.map((b: { key: string }) => ({ label: aggsElementsCache[b.key], value: b.key }))?.filter((v: { label: any }) => !!v.label);
      return { name: agg, values };
    });
  }
  return aggsMap.map((agg) => {
    const values = data.aggregations[agg].buckets?.map((b: any) => ({ label: b.key, value: b.key }));
    return { name: agg, values };
  });
};

const buildRegardingOfFilter = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elementIds: string[],
  filter: Filter,
  noRegardingOfFilterIdsCheck?: boolean,
) => {
  // We need to ensure elements are filtered according to denormalization rights.
  const targetValidatedIds = new Set();
  const sideIdManualInferred = new Map();
  const { values } = filter;
  const ids = values.filter((v) => v.key === ID_SUBFILTER).map((f) => f.values).flat();
  const types = values.filter((v) => v.key === RELATION_TYPE_SUBFILTER).map((f) => f.values).flat();
  const inferredParameterValues = values.filter((v) => v.key === RELATION_INFERRED_SUBFILTER).map((f) => f.values).flat();
  const directionForced = R.head(values.filter((v) => v.key === INSTANCE_REGARDING_OF_DIRECTION_FORCED).map((f) => f.values).flat()) ?? false;
  const directionReverse = R.head(values.filter((v) => v.key === INSTANCE_REGARDING_OF_DIRECTION_REVERSE).map((f) => f.values).flat()) ?? false;
  // resolve all relationships that target the id values, forcing the type is available
  const paginateArgs: RepaginateOpts<BasicStoreRelation> = { baseData: true, types };
  if (directionForced) {
    // If a direction is forced, build the filter in the correct direction
    const directedFilters = [];
    if (directionReverse) {
      directedFilters.push({ key: ['fromId'], values: elementIds });
      if (ids.length > 0) { // Ids can be empty if nothing configured by the user
        directedFilters.push({ key: ['toId'], values: ids });
      }
    } else {
      directedFilters.push({ key: ['toId'], values: elementIds });
      if (ids.length > 0) { // Ids can be empty if nothing configured by the user
        directedFilters.push({ key: ['fromId'], values: ids });
      }
    }
    paginateArgs.filters = { mode: FilterMode.And, filters: directedFilters, filterGroups: [] };
  } else {
    // If no direction is setup, create the filter group for both directions
    const filterTo = [{ key: ['fromId'], values: elementIds }];
    const filterFrom = [{ key: ['toId'], values: elementIds }];
    if (ids.length > 0) { // Ids can be empty if nothing configured by the user
      filterTo.push({ key: ['toId'], values: ids });
      filterFrom.push({ key: ['fromId'], values: ids });
    }
    paginateArgs.filters = {
      mode: FilterMode.Or,
      filters: [],
      filterGroups: [
        { mode: FilterMode.And, filterGroups: [], filters: filterTo },
        { mode: FilterMode.And, filterGroups: [], filters: filterFrom }],
    };
  }
  let relationshipIndices = READ_RELATIONSHIPS_INDICES;
  if (inferredParameterValues.length > 0) {
    if (inferredParameterValues.includes('true')) {
      relationshipIndices = [READ_INDEX_INFERRED_RELATIONSHIPS];
    } else if (inferredParameterValues.includes('false')) {
      relationshipIndices = READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
    }
  }
  const userListingRelationships = noRegardingOfFilterIdsCheck
    ? SYSTEM_USER // relationships are listed by a user with all the rights to fetch all the relationships among relationshipIndices (relationships inferred or not)
    : user;
  const relationships = await elList<BasicStoreRelation>(context, userListingRelationships, relationshipIndices, paginateArgs);
  // compute side ids
  const addTypeSide = (sideId: string, sideType: string) => {
    targetValidatedIds.add(sideId);
    if (sideIdManualInferred.has(sideId)) {
      const toTypes = sideIdManualInferred.get(sideId);
      toTypes.add(sideType);
      sideIdManualInferred.set(sideId, toTypes);
    } else {
      const toTypes = new Set();
      toTypes.add(sideType);
      sideIdManualInferred.set(sideId, toTypes);
    }
  };
  for (let relIndex = 0; relIndex < relationships.length; relIndex += 1) {
    await doYield();
    const relation = relationships[relIndex];
    const relType = isInferredIndex(relation._index) ? 'inferred' : 'manual';
    addTypeSide(relation.fromId, relType);
    addTypeSide(relation.toId, relType);
  }
  return (element: (T & { regardingOfTypes?: string })) => {
    const accepted = targetValidatedIds.has(element.id);
    if (accepted) {
      element.regardingOfTypes = sideIdManualInferred.get(element.id);
    }
    return accepted;
  };
};
type AttributeValues = {
  orderMode?: string | null;
  search?: string | null;
  first?: number | null;
};
export const elAttributeValues = async (
  context: AuthContext,
  user: AuthUser,
  field: string,
  opts: AttributeValues = {},
) => {
  const { orderMode = 'asc', search } = opts;
  const first = opts.first ?? ES_DEFAULT_PAGINATION;
  const markingRestrictions = await buildDataRestrictions(context, user);
  const must = [];
  if (isNotEmptyField(search) && (search as string).length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search as string);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    must.push(bool);
  }
  pushAll(must, markingRestrictions.must);
  const body = {
    query: {
      bool: {
        must,
        must_not: markingRestrictions.must_not,
      },
    },
    aggs: {
      values: {
        terms: {
          field: buildFieldForQuery(field),
          size: first,
          order: { _key: orderMode },
        },
      },
    },
  };
  const query = { index: [READ_DATA_INDICES], body };
  const data = await elRawSearch(context, user, field, query);
  const { buckets } = data.aggregations.values;
  const values = (buckets ?? []).map((n: { key: any }) => n.key).filter((val: string[]) => (search ? val.includes(search.toLowerCase()) : true));
  const nodeElements = values.map((val: any) => ({ node: { id: val, key: field, value: val } }));
  return buildPagination(0, null, nodeElements, nodeElements.length);
};
// endregion

// The list of per-item errors considered transient: elasticsearch refused the item under load or contention,
// the operation was NOT applied and can be resubmitted as-is.
const BULK_ITEM_TRANSIENT_ERRORS = [
  'es_rejected_execution_exception',
  'circuit_breaking_exception',
  'too_many_requests',
  'unavailable_shards_exception',
  'version_conflict_engine_exception', // only after retry_on_conflict is exhausted
];
const isTransientBulkItemError = (itemResult: any): boolean => {
  return itemResult.status === 429 || BULK_ITEM_TRANSIENT_ERRORS.includes(itemResult.error?.type);
};
const bulkItemResult = (item: any) => item.index ?? item.update ?? item.delete ?? item.create;

export const elBulk = async (context: AuthContext, args: any) => {
  const data = await elRawBulk(context, args);
  if (!data.errors) {
    return data;
  }
  // So, from here, we have a partial failure (HTTP 200 for the top-level HTTP response, but with per-item errors).
  // We need to retry the failed items, but only the transient ones. Permanent errors will be reported.
  // -> Succeeded items are already applied and must not be resubmitted;
  // -> Failed items are guaranteed not applied on Elasticsearch side. So we retry only the failed transient ones.

  const { body, ...bulkArgs } = args;
  const operations: Array<{ lines: any[]; index: number }> = [];
  for (let i = 0; i < body.length; i += 1) {
    // We need to group the bulk lines into operations, because the bulk API is a sequence of action lines and source lines.
    // And for that we need to know if the action is a delete or not, because delete has no source line.
    const isDelete = body[i].delete !== undefined;
    const lines = isDelete ? [body[i]] : [body[i], body[i + 1]];
    operations.push({ lines, index: operations.length });
    i += lines.length - 1;
  }
  const bulkId = generateInternalId().substring(0, 8);
  const finalItems: any[] = new Array(operations.length);
  let pending = operations;
  let response = data;

  // Start the retry loop, with exponential backoff.
  for (let attempt = 0; attempt <= BULK_MAX_RETRIES; attempt += 1) {
    if (attempt > 0) {
      response = await elRawBulk(context, { ...bulkArgs, body: pending.flatMap((operation) => operation.lines) });
    }
    const items = response.items ?? [];
    const retryable: typeof pending = [];
    const transientErrors: any[] = [];
    const permanentErrors: any[] = [];
    for (let k = 0; k < items.length; k += 1) {
      const operation = pending[k];
      finalItems[operation.index] = items[k];
      const itemResult = bulkItemResult(items[k]);
      const error = itemResult?.error;
      if (!error || error.type === DOCUMENT_MISSING_EXCEPTION) {
        // We skip this case of missing document,
        // because it is a tolerated update of an already deleted document (the document is not there, but the operation is considered successful).
        continue;
      }
      if (isTransientBulkItemError(itemResult)) {
        // This is a transient error, we will retry this operation in the next loop iteration.
        retryable.push(operation);
        transientErrors.push(error);
      } else {
        permanentErrors.push(error);
      }
    }
    if (permanentErrors.length > 0) {
      // So here we have permanent errors, we cannot continue, we need to throw an error with the details of the permanent errors.
      throw DatabaseError('Bulk indexing fail', { bulkId, attempts: attempt + 1, errors: permanentErrors });
    }
    if (retryable.length === 0) {
      if (attempt > 0) {
        logApp.info('[SEARCH] Bulk recovered after partial failures', { bulkId, attempts: attempt + 1, opsTotal: operations.length });
      }
      return { ...response, items: finalItems, errors: finalItems.some((item) => item && bulkItemResult(item)?.error !== undefined) };
    }
    if (attempt === BULK_MAX_RETRIES) {
      // We have exhausted the maximum number of retries, we need to throw an error with the details of the transient errors.
      throw DatabaseError('Bulk indexing fail', { bulkId, attempts: attempt + 1, errors: transientErrors });
    }
    const delayMs = BULK_INITIAL_DELAY_MS * (2 ** attempt);
    const errorTypes: Record<string, number> = {};
    transientErrors.forEach((error) => {
      errorTypes[error.type] = (errorTypes[error.type] ?? 0) + 1;
    });
    logApp.warn(`[SEARCH] Bulk partial failure, retrying failed items in ${delayMs}ms (attempt ${attempt + 1}/${BULK_MAX_RETRIES})`, {
      bulkId,
      opsTotal: operations.length,
      opsOk: operations.length - retryable.length,
      opsRetrying: retryable.length,
      errorTypes,
    });
    await wait(delayMs);
    pending = retryable;
  }
  return response;
};
/* v8 ignore next */
export const elIndex = async (
  indexName: string[] | string | undefined,
  documentBody: Record<string, any>,
  opts: { refresh?: boolean; pipeline?: any } = {},
) => {
  const { refresh = true, pipeline } = opts;
  const documentId = documentBody.internal_id;
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  logApp.debug(`[SEARCH] index > ${entityType} ${documentId} in ${indexName}`, { documentBody });
  let indexParams: any = {
    index: indexName,
    id: documentBody.internal_id,
    refresh,
    timeout: '60m',
    body: R.dissoc('_index', documentBody),
  };
  if (pipeline) {
    indexParams = { ...indexParams, pipeline };
  }
  if (engine instanceof ElkClient) {
    await engine.index(indexParams).catch((err: any) => {
      throw DatabaseError('Simple indexing fail', { cause: err, documentId, entityType, ...extendedErrors({ documentBody }) });
    });
  } else {
    await engine.index(indexParams).catch((err: any) => {
      throw DatabaseError('Simple indexing fail', { cause: err, documentId, entityType, ...extendedErrors({ documentBody }) });
    });
  }

  return documentBody;
};
/* v8 ignore next */
export const elUpdate = async (
  context: AuthContext,
  indexName: string,
  documentId: string,
  documentBody: any,
  retry = ES_RETRY_ON_CONFLICT,
) => {
  const updateOperation = async () => {
    const entityType = documentBody.entity_type ? documentBody.entity_type : '';
    const updateRequest = {
      id: documentId,
      index: indexName,
      retry_on_conflict: retry,
      timeout: BULK_TIMEOUT,
      refresh: true,
      body: documentBody,
    };
    try {
      return await elExecuteWithAbortSignal(
        context?.requestAbortSignal,
        (opts) => (engine as ElkClient).update(updateRequest, opts),
        () => (engine as OpenClient).update(updateRequest),
      );
    } catch (err: any) {
      throw wrapEngineError('Update indexing fail', err, { documentId, entityType, ...extendedErrors({ documentBody }) });
    }
  };
  return retryElOperations(updateOperation);
};
// Field names are passed as script parameters and never interpolated in the source.
// Interpolating them would create one script per field combination, and every distinct
// source has to be compiled by the engine, quickly exhausting script.max_compilations_rate.
export const EL_REPLACE_SCRIPT_SOURCE = 'for (entry in params.replacements.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }'
  + ' for (key in params.removals) { ctx._source.remove(key); }';
export const buildReplaceScriptParams = (doc: Record<string, any>) => {
  const replacements: Record<string, any> = {};
  const removals: string[] = [];
  const entries = Object.entries(doc);
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    // We clean the attribute only if data is null or undefined
    if (val === undefined || val === null) {
      removals.push(key);
    } else {
      replacements[key] = val;
    }
  }
  return { replacements, removals };
};
export const elReplace = async (
  context: AuthContext,
  indexName: string,
  documentId: string,
  documentBody: any,
) => {
  const doc = R.dissoc('_index', documentBody.doc);
  return elUpdate(context, indexName, documentId, {
    script: { source: EL_REPLACE_SCRIPT_SOURCE, params: buildReplaceScriptParams(doc) },
  });
};
export const elDelete = (indexName: string, documentId: string) => {
  const deleteOperation = async () => {
    const deleteRequest = {
      id: documentId,
      index: indexName,
      timeout: BULK_TIMEOUT,
      refresh: true,
    };
    try {
      if (engine instanceof ElkClient) {
        return await engine.delete(deleteRequest);
      }
      return await engine.delete(deleteRequest);
    } catch (err: any) {
      throw DatabaseError('Deleting indexing fail', { cause: err, documentId });
    }
  };
  return retryElOperations(deleteOperation);
};
const getRelatedRelations = async (
  context: AuthContext,
  user: AuthUser,
  targetIds: string | string[],
  elements: BasicStoreRelation[],
  level: number,
  cache: Map<string, string>,
  opts: RepaginateOpts<BasicStoreRelation> = {},
) => {
  const fromOrToIds = Array.isArray(targetIds) ? targetIds : [targetIds];
  const filtersContent = [{
    key: ['connections'],
    nested: [{ key: 'internal_id', values: fromOrToIds }],
    values: [],
  }];
  const filters = {
    mode: FilterMode.And,
    filters: filtersContent,
    filterGroups: [],
  };
  const foundRelations: string[] = [];
  const callback = async (hits: BasicStoreRelation[]) => {
    const preparedElements: (BasicStoreRelation & { level: number })[] = [];
    hits.forEach((hit) => {
      if (!cache.has(hit.internal_id)) {
        foundRelations.push(hit.internal_id);
        cache.set(hit.internal_id, '');
      }
      preparedElements.push({ ...hit, level });
    });
    unshiftAll(elements, preparedElements);
    return true;
  };
  const finalOpts: RepaginateOpts<BasicStoreRelation> = { ...opts, filters, callback, types: [ABSTRACT_BASIC_RELATIONSHIP] };
  await elList<BasicStoreRelation>(context, user, READ_RELATIONSHIPS_INDICES, finalOpts);
  // If relations find, need to recurse to find relations to relations
  if (foundRelations.length > 0) {
    const groups = R.splitEvery(MAX_BULK_OPERATIONS, foundRelations);
    const concurrentFetch = (gIds: string[]) => getRelatedRelations(context, user, gIds, elements, level + 1, cache, opts);
    await BluePromise.map(groups, concurrentFetch, { concurrency: ES_MAX_CONCURRENCY });
  }
};
export const getRelationsToRemove = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elements: T[],
  opts: RepaginateOpts<BasicStoreRelation> = {},
) => {
  const relationsToRemoveMap: Map<string, string> = new Map();
  const relationsToRemove: BasicStoreRelation[] = [];
  const ids = elements.map((e) => e.internal_id);
  await getRelatedRelations(context, user, ids, relationsToRemove, 0, relationsToRemoveMap, opts);
  return { relations: R.flatten(relationsToRemove), relationsToRemoveMap };
};
export const elDeleteInstances = async <T extends BasicStoreBase>(
  context: AuthContext,
  instances: T[],
  opts: { forceRefresh?: boolean } = {},
) => {
  const { forceRefresh = true } = opts;
  // If nothing to delete, return immediately to prevent elastic to delete everything
  if (instances.length > 0) {
    logApp.debug(`[SEARCH] Deleting ${instances.length} instances`);
    const groupsOfInstances = R.splitEvery(MAX_BULK_OPERATIONS, instances);
    for (let i = 0; i < groupsOfInstances.length; i += 1) {
      const instancesBulk = groupsOfInstances[i];
      const bodyDelete = instancesBulk.flatMap((doc) => {
        return [{ delete: { _index: doc._index, _id: doc._id ?? doc.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } }];
      });
      await elBulk(context, { refresh: forceRefresh, timeout: BULK_TIMEOUT, body: bodyDelete });
    }
  }
};
export const elRemoveRelationConnection = async (
  context: AuthContext,
  user: AuthUser,
  elementsImpact: any,
  opts: { forceRefresh?: boolean } = {},
) => {
  const { forceRefresh = true } = opts;
  const impacts: [string, any][] = Object.entries(elementsImpact);
  if (impacts.length > 0) {
    const idsToResolve = impacts.map(([k]) => k);
    const dataIds = await elFindByIds(context, user, idsToResolve, { baseData: true, baseFields: ['pir_information'] }) as BasicStoreEntity[];
    // Build cache for rest of execution
    const elIdsCache: Record<string, string> = {};
    const indexCache: Record<string, string> = {};
    const pirInformationCache: Record<string, any> = {};
    for (let idIndex = 0; idIndex < dataIds.length; idIndex += 1) {
      await doYield();
      const element = dataIds[idIndex];
      elIdsCache[element.internal_id] = element._id;
      indexCache[element.internal_id] = element._index;
      pirInformationCache[element.internal_id] = element.pir_information;
    }
    // Split by max operations, create the bulk
    const groupsOfImpacts = R.splitEvery(MAX_BULK_OPERATIONS, impacts);
    for (let i = 0; i < groupsOfImpacts.length; i += 1) {
      await doYield();
      const impactsBulk = groupsOfImpacts[i];
      const bodyUpdateRaw = impactsBulk.map(([impactId, elementMeta]) => {
        return Object.entries(elementMeta).map(([typeAndIndex, cleanupIds]) => {
          const updates: any = [];
          const elId = elIdsCache[impactId];
          const fromIndex = indexCache[impactId];
          const entityPirInformation = pirInformationCache[impactId];
          if (isEmptyField(fromIndex)) { // No need to clean up the connections if the target is already deleted.
            return updates;
          }
          const [relationType, relationIndex, side, sideType] = typeAndIndex.split('|');
          const refField = isStixRefRelationship(relationType) && isInferredIndex(relationIndex) ? ID_INFERRED : ID_INTERNAL;
          const rel_key = buildRefRelationKey(relationType, refField);
          let source = `if(ctx._source[params.rel_key] != null){
              for (int i=params.cleanupIds.length-1; i>=0; i--) {
                def cleanupIndex = ctx._source[params.rel_key].indexOf(params.cleanupIds[i]);
                if(cleanupIndex !== -1){
                  ctx._source[params.rel_key].remove(cleanupIndex);
                }
            }
          }
          `;
          // Only impact the updated at on the from side of the ref relationship
          const fromSide = side === 'from';
          if (fromSide && isStixRefRelationship(relationType)) {
            if (isUpdatedAtObject(sideType)) {
              source += 'ctx._source[\'updated_at\'] = params.updated_at;';
            }
            if (isModifiedObject(sideType)) {
              source += 'ctx._source[\'modified\'] = params.updated_at;';
            }
          }
          // freshness of an entity
          if (isUpdatedAtObject(sideType)) {
            source += 'ctx._source[\'refreshed_at\'] = params.updated_at;';
          }
          // Remove the pir information concerning the Pir in case of in-pir rel deletion
          if (relationType === RELATION_IN_PIR && entityPirInformation) {
            source += `
              if (ctx._source.containsKey('pir_information') && ctx._source['pir_information'] != null) {
                ctx._source['pir_information'].removeIf(item -> params.cleanupIds.contains(item.pir_id));
              }
            `;
          }
          const script = { source, params: { rel_key, cleanupIds, updated_at: now() } };
          updates.push([
            { update: { _index: fromIndex, _id: elId, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
            { script },
          ]);
          return updates;
        });
      });
      const bodyUpdate = R.flatten(bodyUpdateRaw);
      if (bodyUpdate.length > 0) {
        await elBulk(context, { refresh: forceRefresh, timeout: BULK_TIMEOUT, body: bodyUpdate });
      }
    }
  }
};

export const computeDeleteElementsImpacts = async (
  cleanupRelations: BasicStoreRelation[],
  toBeRemovedIds: string[],
  relationsToRemoveMap: Map<string, string>,
) => {
  // Update all rel connections that will remain
  const elementsImpact: Record<string, Record<string, string[]>> = {};
  for (let i = 0; i < cleanupRelations.length; i += 1) {
    await doYield();
    const relation = cleanupRelations[i];
    const fromWillNotBeRemoved = !relationsToRemoveMap.has(relation.fromId) && !toBeRemovedIds.includes(relation.fromId);
    const isFromCleanup = fromWillNotBeRemoved && isImpactedTypeAndSide(relation.entity_type, relation.fromType, relation.toType, ROLE_FROM);
    if (isFromCleanup) {
      const cleanKey = `${relation.entity_type}|${relation._index}|from|${relation.fromType}`;
      if (isEmptyField(elementsImpact[relation.fromId])) {
        elementsImpact[relation.fromId] = { [cleanKey]: [relation.toId] };
      } else {
        const current = elementsImpact[relation.fromId];
        if (current[cleanKey]) {
          elementsImpact[relation.fromId][cleanKey].push(relation.toId);
        } else {
          elementsImpact[relation.fromId][cleanKey] = [relation.toId];
        }
      }
    }
    const toWillNotBeRemoved = !relationsToRemoveMap.has(relation.toId) && !toBeRemovedIds.includes(relation.toId);
    const isToCleanup = toWillNotBeRemoved && isImpactedTypeAndSide(relation.entity_type, relation.fromType, relation.toType, ROLE_TO);
    if (isToCleanup) {
      const cleanKey = `${relation.entity_type}|${relation._index}|to|${relation.toType}`;
      if (isEmptyField(elementsImpact[relation.toId])) {
        elementsImpact[relation.toId] = { [cleanKey]: [relation.fromId] };
      } else {
        const current = elementsImpact[relation.toId];
        if (current[cleanKey]) {
          elementsImpact[relation.toId][cleanKey].push(relation.fromId);
        } else {
          elementsImpact[relation.toId][cleanKey] = [relation.fromId];
        }
      }
    }
  }
  return elementsImpact;
};

export const elReindexElements = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  sourceIndex: string,
  destIndex: string,
  opts: { dbId?: string; sourceUpdate?: any } = {},
) => {
  const reindexOperation = async () => {
    const { dbId, sourceUpdate = {} } = opts;
    const sourceCleanupScript = "ctx._source.remove('fromType'); ctx._source.remove('toType'); "
      + "ctx._source.remove('spec_version'); ctx._source.remove('representative'); ctx._source.remove('objectOrganization'); "
      + "ctx._source.remove('rel_has-reference'); ctx._source.remove('rel_has-reference.internal_id'); "
      + "ctx._source.remove('i_valid_from_day'); ctx._source.remove('i_valid_until_day'); "
      + "ctx._source.remove('i_valid_from_month'); ctx._source.remove('i_valid_until_month'); "
      + "ctx._source.remove('i_valid_from_year'); ctx._source.remove('i_valid_until_year'); "
      + "ctx._source.remove('i_stop_time_year'); ctx._source.remove('i_start_time_year'); "
      + "ctx._source.remove('i_start_time_month'); ctx._source.remove('i_stop_time_month'); "
      + "ctx._source.remove('i_start_time_day'); ctx._source.remove('i_stop_time_day'); "
      + "ctx._source.remove('i_created_at_year'); ctx._source.remove('i_created_at_month'); ctx._source.remove('i_created_at_day'); "
      + "ctx._source.remove('rel_can-share'); ctx._source.remove('rel_can-share.internal_id');"
      + "ctx._source.remove('x_opencti_cvss_vector'); ctx._source.remove('x_opencti_cvss_v2_vector'); ctx._source.remove('x_opencti_cvss_v4_vector');"
      + "ctx._source.remove('authorized_members');"; // after renaming authorized_members to restricted_members
    const idReplaceScript = 'if (params.replaceId) { ctx._id = params.newId }';
    const sourceUpdateScript = 'for (change in params.changes.entrySet()) { ctx._source[change.getKey()] = change.getValue() }';
    const source = `${sourceCleanupScript} ${idReplaceScript} ${sourceUpdateScript}`;
    const reindexParams = {
      body: {
        source: {
          index: sourceIndex,
          query: {
            ids: {
              values: ids,
            },
          },
        },
        dest: {
          index: destIndex,
        },
        script: { // remove old fields that are not mapped anymore but can be present in DB
          params: { changes: sourceUpdate, replaceId: !!dbId, newId: dbId },
          source,
        },
      },
      refresh: true,
    };
    try {
      if (engine instanceof ElkClient) {
        return await engine.reindex(reindexParams);
      }
      return await engine.reindex(reindexParams);
    } catch (err: any) {
      throw DatabaseError(`Reindexing fail from ${sourceIndex} to ${destIndex}`, { cause: err, body: reindexParams.body });
    }
  };
  return retryElOperations(reindexOperation);
};

export const elRemoveDraftIdFromElements = async (
  context: AuthContext,
  user: AuthUser,
  draftId: string,
  elementsIds: string[],
) => {
  const revertDraftIdSource = `
    if (ctx._source.containsKey('draft_ids')) {
      for (int i = 0; i < ctx._source.draft_ids.length; ++i){
        if(ctx._source.draft_ids[i] == params.draftId){
          ctx._source.draft_ids.remove(i);
        }
      }
    }
  `;

  if (elementsIds.length > 0) {
    await elRawUpdateByQuery({
      index: READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
      refresh: true,
      conflicts: 'proceed',
      body: {
        script: { source: revertDraftIdSource, params: { draftId } },
        query: {
          terms: {
            'id.keyword': elementsIds,
          },
        },
      },
    }).catch((err) => {
      throw DatabaseError('Revert live entities indexing fail', { cause: err });
    });
  }
};
export const elListExistingDraftWorkspaces = async (context: AuthContext, user: AuthUser) => {
  const listArgs = {
    filters: { mode: FilterMode.And, filters: [{ key: ['entity_type'], values: [ENTITY_TYPE_DRAFT_WORKSPACE] }], filterGroups: [] },
  };
  return elList(context, user, READ_INDEX_INTERNAL_OBJECTS, listArgs);
};
// Creates a copy of a live element in the draft index with the current draft context
export const copyLiveElementToDraft = async (
  context: AuthContext,
  user: AuthUser,
  element: BasicStoreBase,
  draftOperation = DRAFT_OPERATION_UPDATE_LINKED,
) => {
  const draftContext = getDraftContext(context, user);
  if (!draftContext || isDraftIndex(element._index)) return element;

  const updatedElement = structuredClone(element);
  const newId = generateInternalId();
  const reindexOpts = { dbId: newId, sourceUpdate: { draft_ids: [draftContext], draft_change: { draft_operation: draftOperation } } };
  await elReindexElements(context, user, [element.internal_id], element._index, INDEX_DRAFT_OBJECTS, reindexOpts);
  updatedElement._id = newId;
  updatedElement._index = INDEX_DRAFT_OBJECTS;

  // Add draftId to live element draftsIds
  const allDrafts = await elListExistingDraftWorkspaces(context, SYSTEM_USER);
  const allDraftIds = allDrafts.map((d) => d.internal_id);
  const addDraftIdScript = {
    script: {
      // draftId is a script parameter, never interpolated: interpolating it would compile
      // a new script for every draft ever created (see script.max_compilations_rate).
      source: `
        if (ctx._source.containsKey('draft_ids')) {
          for (int i=ctx._source['draft_ids'].length-1; i>=0; i--) {
            if (!params.allDraftIds.contains(ctx._source['draft_ids'][i])) {
              ctx._source['draft_ids'].remove(i);
            }
          }
          ctx._source['draft_ids'].add(params.draftId);
        }
        else
          {ctx._source.draft_ids = [params.draftId]}
      `,
      params: { allDraftIds, draftId: draftContext },
    },
  };
  await elUpdate(context, element._index, element.internal_id, addDraftIdScript);

  return updatedElement;
};
// Gets the version of the element in current draft context if it exists
// If it doesn't exist, creates a copy of live element to draft context then returns it
const draftCopyLockPrefix = 'draft_copy';
export const loadDraftElement = async (
  context: AuthContext,
  user: AuthUser,
  element: BasicStoreBase,
) => {
  if (isDraftIndex(element._index) || !isDraftSupportedEntity(element)) return element;

  let lock;
  const currentDraft = getDraftContext(context, user);
  const lockKey = `${draftCopyLockPrefix}_${currentDraft}_${element.internal_id}`;
  try {
    lock = await lockResources([lockKey]);
    const loadedElement = await elLoadById(context, user, element.internal_id);
    if (loadedElement && isDraftIndex(loadedElement._index)) return loadedElement;

    return await copyLiveElementToDraft(context, user, element);
  } catch (e: any) {
    if (e.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [lockKey] });
    }
    throw e;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};
const elCopyRelationsTargetsToDraft = async (
  context: AuthContext,
  user: AuthUser,
  elements: BasicStoreBase[],
) => {
  const draftContext = getDraftContext(context, user);
  if (!draftContext) {
    return;
  }
  for (let i = 0; i < elements.length; i += 1) {
    const e = elements[i];
    if (e.base_type === BASE_TYPE_RELATION) {
      const relElement = e as StoreRelation;
      const { from, fromId, to, toId } = relElement as StoreRelation;
      const resolvedFrom = (from ?? (await elLoadById(context, user, fromId, { includeDeletedInDraft: true }))) as BasicStoreBase;
      const draftFrom = await loadDraftElement(context, user, resolvedFrom);
      relElement.from = draftFrom;
      relElement.fromId = draftFrom.id;
      const resolvedTo = (to ?? (await elLoadById(context, user, toId, { includeDeletedInDraft: true }))) as BasicStoreBase;
      const draftTo = await loadDraftElement(context, user, resolvedTo);
      relElement.to = draftTo;
      relElement.toId = draftTo.id;
    }
  }
};

export const elMarkElementsAsDraftDelete = async (context: AuthContext, user: AuthUser, elements: BasicStoreBase[]) => {
  if (elements.some((e) => !isDraftSupportedEntity(e))) throw UnsupportedError('Cannot delete unsupported element in draft context', { elements });

  // 01. Remove all elements that are draft creations, mark as delete for others
  const liveElements = elements.filter((f) => !isDraftIndex(f._index));
  const draftCreatedElements = elements.filter((f) => isDraftIndex(f._index) && f.draft_change?.draft_operation === DRAFT_OPERATION_CREATE);
  const draftNonCreatedElements = elements.filter((f) => isDraftIndex(f._index) && f.draft_change?.draft_operation !== DRAFT_OPERATION_CREATE);

  const copyLiveElementsPromise = liveElements.map((e) => copyLiveElementToDraft(context, user, e, DRAFT_OPERATION_DELETE));
  const deleteDraftCreatedElementsPromise = elDeleteInstances(context, draftCreatedElements);
  const updateDraftElementsPromise = draftNonCreatedElements.map((draftE) => {
    // TODO we might want to apply the reverse patch to draft updated elements
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_DELETE } };
    return elReplace(context, draftE._index, draftE._id, { doc: newDraftChange });
  });
  const copiedLiveElements = await Promise.all(copyLiveElementsPromise);
  const allDraftElements = [...copiedLiveElements, ...draftCreatedElements, ...draftNonCreatedElements];

  // 02. Remove all related relations and elements: delete instances created in draft, mark as deletionLink for others
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, allDraftElements, { includeDeletedInDraft: true });
  const liveRelations = relations.filter((f) => !isDraftIndex(f._index));
  const draftCreatedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change?.draft_operation === DRAFT_OPERATION_CREATE);
  const draftNonCreatedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change?.draft_operation !== DRAFT_OPERATION_CREATE);

  const deleteDraftCreatedRelationsPromise = elDeleteInstances(context, draftCreatedRelations);
  const copyLiveRelationsPromise = liveRelations.map((e) => copyLiveElementToDraft(context, user, e, DRAFT_OPERATION_DELETE_LINKED));
  const updateDraftRelationsPromise = draftNonCreatedRelations.map((draftR) => {
    // TODO we might want to apply the reverse patch to draft updated elements
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_DELETE_LINKED } };
    return elReplace(context, draftR._index, draftR._id, { doc: newDraftChange });
  });
  await Promise.all([deleteDraftCreatedElementsPromise, ...updateDraftElementsPromise]);
  await Promise.all([...copyLiveRelationsPromise, deleteDraftCreatedRelationsPromise, ...updateDraftRelationsPromise]);

  // 03. Clear all connections rel, import all dependencies into draft if not already in draft
  await elCopyRelationsTargetsToDraft(context, user, [...allDraftElements, ...liveRelations]);
  // Compute the id that needs to be removed from rel
  const basicCleanup = elements.filter((f) => isBasicRelationship(f.entity_type)) as BasicStoreRelation[];
  // Update all rel connections that will remain
  const cleanupRelations = relations.concat(basicCleanup);
  const toBeRemovedIds = elements.map((e) => e.internal_id);
  const elementsImpact = await computeDeleteElementsImpacts(cleanupRelations, toBeRemovedIds, relationsToRemoveMap);
  await elRemoveRelationConnection(context, user, elementsImpact);
};

// TODO: get rid of this function and let elastic fail queries, so we can fix all of them by using the right type of data
export const prepareElementForIndexing = async (element: Record<string, any>) => {
  const thing: Record<string, any> = {};
  const keyItems = Object.keys(element);
  for (let index = 0; index < keyItems.length; index += 1) {
    await doYield();
    const key = keyItems[index];
    const value = element[key];
    if (Array.isArray(value)) { // Array of Date, objects, string or number
      const preparedArray = [];
      let yieldCount = 0;
      for (let valueIndex = 0; valueIndex < value.length; valueIndex += 1) {
        if (await doYield()) {
          // If we extend the preparation 5 times, log a warn
          // It will help to understand what kind of key have so many elements
          if (yieldCount === 5) {
            logApp.warn('[ENGINE] Element preparation too many values', { id: element.id ?? element.internal_id, key, size: value.length });
          }
          yieldCount += 1;
        }
        const valueElement = value[valueIndex];
        if (valueElement) {
          if (isDateAttribute(key)) { // Date is an object but natively supported
            preparedArray.push(valueElement);
          } else if (R.is(String, valueElement)) { // For string, trim by default
            preparedArray.push(valueElement.trim());
          } else if (R.is(Object, valueElement) && Object.keys(value).length > 0) { // For complex object, prepare inner elements
            const complexPrepared = await prepareElementForIndexing(valueElement);
            preparedArray.push(complexPrepared);
          } else {
            // For all other types, no transform (list of boolean is not supported)
            preparedArray.push(valueElement);
          }
        }
      }
      thing[key] = preparedArray;
    } else if (isDateAttribute(key)) { // Date is an object but natively supported
      thing[key] = value;
    } else if (isBooleanAttribute(key)) { // Patch field is string generic so need to be cast to boolean
      thing[key] = typeof value === 'boolean' ? value : value?.toLowerCase() === 'true';
    } else if (isNumericAttribute(key)) {
      thing[key] = isNotEmptyField(value) ? Number(value) : undefined;
    } else if (R.is(Object, value) && Object.keys(value).length > 0) { // For complex object, prepare inner elements
      thing[key] = await prepareElementForIndexing(value);
    } else if (R.is(String, value)) { // For string, trim by default
      thing[key] = value.trim();
    } else { // For all other types (numeric, ...), no transform
      thing[key] = value;
    }
  }
  return thing;
};
const prepareRelation = (thing: Record<string, any>) => {
  if (thing.fromRole === undefined || thing.toRole === undefined) {
    throw DatabaseError('Cant index relation connections without from or to', {
      id: thing.internal_id,
      fromId: thing.fromId,
      toId: thing.toId,
    });
  }
  const connections = [];
  if (!thing.from || !thing.to) {
    throw DatabaseError('Cant index relation, error resolving dependency IDs', {
      id: thing.internal_id,
      fromId: thing.fromId,
      toId: thing.toId,
    });
  }
  const { from, to } = thing;

  if (!from.entity_type || !to.entity_type) {
    throw DatabaseError('Cant index relation, error resolving from or to entity type', {
      id: thing.internal_id,
      fromId: thing.fromId,
      toId: thing.toId,
      fromResolved: from,
      toResolved: to,
    });
  }

  connections.push({
    internal_id: from.internal_id,
    name: extractEntityRepresentativeName(from),
    types: [from.entity_type, ...getParentTypes(from.entity_type)],
    role: thing.fromRole,
  });
  connections.push({
    internal_id: to.internal_id,
    name: extractEntityRepresentativeName(to),
    types: [to.entity_type, ...getParentTypes(to.entity_type)],
    role: thing.toRole,
  });
  return R.pipe(
    R.assoc('connections', connections),
    R.dissoc(INTERNAL_TO_FIELD),
    R.dissoc(INTERNAL_FROM_FIELD),
    // Dissoc from
    R.dissoc('from'),
    R.dissoc('fromId'),
    R.dissoc('fromRole'),
    R.dissoc('fromType'),
    // Dissoc to
    R.dissoc('to'),
    R.dissoc('toId'),
    R.dissoc('toRole'),
    R.dissoc('toType'),
  )(thing);
};
const prepareEntity = (thing: Record<string, any>) => {
  return R.pipe(R.dissoc(INTERNAL_TO_FIELD), R.dissoc(INTERNAL_FROM_FIELD))(thing);
};
const prepareIndexingElement = async (thing: Record<string, any>) => {
  if (thing.base_type === BASE_TYPE_RELATION) {
    const relation = prepareRelation(thing as StoreRelation);
    return prepareElementForIndexing(relation);
  }
  const entity = prepareEntity(thing);
  return prepareElementForIndexing(entity);
};
const prepareIndexing = async (context: AuthContext, user: AuthUser, elements: Record<string, any>[]) => {
  const draftContext = getDraftContext(context, user);
  const preparedElements = [];
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    if (draftContext) {
      // If we are in a draft, relations from and to need to be elements that are also in draft.
      if (element.base_type === BASE_TYPE_RELATION) {
        const relElement = element as StoreRelation;
        const { from, to } = relElement;
        const resolvedFrom = relElement.from as BasicStoreBase;
        const resolvedTo = relElement.to as BasicStoreBase;
        if (!elements.some((e) => e.internal_id === from?.internal_id)) {
          const draftFrom = await loadDraftElement(context, user, resolvedFrom);
          relElement.from = draftFrom;
          relElement.fromId = draftFrom.id;
        } else {
          resolvedFrom._index = INDEX_DRAFT_OBJECTS;
        }
        if (!elements.some((e) => e.internal_id === to?.internal_id)) {
          const draftTo = await loadDraftElement(context, user, resolvedTo);
          relElement.to = draftTo;
          relElement.toId = draftTo.id;
        } else {
          resolvedTo._index = INDEX_DRAFT_OBJECTS;
        }
      }
      element._index = INDEX_DRAFT_OBJECTS;
      element.draft_ids = [draftContext];
      element.draft_change = { draft_operation: DRAFT_OPERATION_CREATE };
    }
    const prepared = await prepareIndexingElement(element);
    preparedElements.push(prepared);
  }
  return preparedElements;
};
const validateElementsToIndex = (context: AuthContext, user: AuthUser, elements: Record<string, any>[]) => {
  const draftContext = getDraftContext(context, user);
  // If any element to index is not supported in draft, raise exception
  if (draftContext && elements.some((e) => !isDraftSupportedEntity(e))) {
    throw UnsupportedError('Cannot index unsupported element in draft context');
  }
};
type DenormalizedRefTarget = { relation: string; field: string; elements: any[] };
// Field names are script parameters and never interpolated in the source. Interpolating them
// would compile one script per combination of ref relationship types carried by an entity,
// which grows with the powerset of the ref types and quickly exhausts script.max_compilations_rate.
export const EL_DENORMALIZED_REFS_SCRIPT_SOURCE = `
  for (ref in params.appended_refs) {
    if (ctx._source[ref.field] == null) { ctx._source[ref.field] = []; }
    ctx._source[ref.field].addAll(ref.ids);
  }
  for (ref in params.distinct_refs) {
    if (ctx._source[ref.field] == null) { ctx._source[ref.field] = []; }
    for (id in ref.ids) {
      if (!ctx._source[ref.field].contains(id)) { ctx._source[ref.field].add(id); }
    }
  }
  for (field in params.timestamp_fields) { ctx._source[field] = params.updated_at; }
  if (params.pir_ids != null) {
    if (ctx._source.containsKey('pir_information') && ctx._source['pir_information'] != null) {
      ctx._source['pir_information'].removeIf(item -> params.pir_ids.contains(item.pir_id));
      ctx._source['pir_information'].addAll(params.new_pir_information);
    } else { ctx._source['pir_information'] = params.new_pir_information; }
  }
`;
export const buildDenormalizedRefsScriptParams = (targetsElements: DenormalizedRefTarget[], updatedAt: string) => {
  const appendedRefs: { field: string; ids: string[] }[] = [];
  const distinctRefs: { field: string; ids: string[] }[] = [];
  const timestampFields: string[] = [];
  const addTimestampField = (field: string) => {
    if (!timestampFields.includes(field)) timestampFields.push(field);
  };
  let pirIds: string[] | null = null;
  let newPirInformation: any[] | null = null;
  for (let index = 0; index < targetsElements.length; index += 1) {
    const target = targetsElements[index];
    const field = buildRefRelationKey(target.relation, target.field);
    const ids = target.elements.map((e: any) => e.id);
    if (isStixRefUnidirectionalRelationship(target.relation)) {
      // don't try to add unidirectional ref rel if already present (issue#7535)
      distinctRefs.push({ field, ids });
    } else {
      appendedRefs.push({ field, ids });
    }
    const fromSide = target.elements.find((e: any) => e.side === 'from');
    const toSide = target.elements.find((e: any) => e.side === 'to');
    if (fromSide && isStixRefRelationship(target.relation)) {
      // updated_at and modified only updated for ref relationships
      if (isUpdatedAtObject(fromSide.type)) addTimestampField('updated_at');
      if (isModifiedObject(fromSide.type)) addTimestampField('modified');
    }
    // freshness of an entity updated for any relationship
    if ((fromSide && isUpdatedAtObject(fromSide.type)) || (toSide && isUpdatedAtObject(toSide.type))) {
      addTimestampField('refreshed_at');
    }
    // Add Pir information for in-pir relationships
    if (target.relation === RELATION_IN_PIR) {
      // remove pir_information concerning the pir and add the new pir_information
      newPirInformation = target.elements.map((e: any) => ({
        pir_id: e.id,
        pir_score: e.pir_score,
        last_pir_score_date: updatedAt,
      }));
      pirIds = ids;
    }
  }
  return {
    updated_at: updatedAt,
    appended_refs: appendedRefs,
    distinct_refs: distinctRefs,
    timestamp_fields: timestampFields,
    pir_ids: pirIds,
    new_pir_information: newPirInformation,
  };
};
export const elIndexElements = async (
  context: AuthContext,
  user: AuthUser,
  indexingType: string | undefined,
  elements: Record<string, any>[],
) => {
  validateElementsToIndex(context, user, elements);
  const elIndexElementsFn = async () => {
    // 00. Relations must be transformed before indexing.
    const transformedElements = await prepareIndexing(context, user, elements);
    // 01. Bulk the indexing of row elements
    // split since there can be a lot of relationships for the same element
    const transformedElementsSplit = R.splitEvery(MAX_BULK_OPERATIONS, transformedElements);
    for (let i = 0; i < transformedElementsSplit.length; i += 1) {
      const elementsBulk = transformedElementsSplit[i];
      const body = elementsBulk.flatMap((elementDoc) => {
        const doc = elementDoc;
        return [
          { index: { _index: doc._index, _id: doc._id ?? doc.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
          R.pipe(R.dissoc('_index'))(doc),
        ];
      });
      if (body.length > 0) {
        meterManager.directBulk(body.length, { type: indexingType });
        await elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body });
      }
    }
    // 02. If relation, generate impacts for from and to sides
    const cache: Record<string, BasicStoreBase | null | undefined> = {};
    const impactedEntities = R.pipe(
      R.filter((e: BasicStoreBase) => e.base_type === BASE_TYPE_RELATION),
      R.map((e: StoreRelation) => {
        const { fromType, fromRole, toType, toRole } = e;
        const impacts = [];
        // We impact target entities of the relation only if not global entities like
        // MarkingDefinition (marking) / KillChainPhase (kill_chain_phase) / Label (tagging)
        cache[e.fromId] = e.from;
        cache[e.toId] = e.to;
        const refField = isStixRefRelationship(e.entity_type) && isInferredIndex(e._index) ? ID_INFERRED : ID_INTERNAL;
        const relationshipType = e.entity_type;
        if (isImpactedRole(relationshipType, fromType, toType, fromRole)) {
          if (relationshipType === RELATION_IN_PIR) {
            const { pir_score } = e as any;
            impacts.push({ refField, from: e.fromId, relationshipType, to: e.to, type: e.from?.entity_type, side: 'from', pir_score });
          } else {
            impacts.push({ refField, from: e.fromId, relationshipType, to: e.to, type: e.from?.entity_type, side: 'from' });
          }
        }
        if (isImpactedRole(relationshipType, fromType, toType, toRole)) {
          impacts.push({ refField, from: e.toId, relationshipType, to: e.from, type: e.to?.entity_type, side: 'to' });
        }
        return impacts;
      }),
      R.flatten,
      R.groupBy((i) => i.from),
    )(elements);
    const elementsToUpdate = Object.keys(impactedEntities).map((entityId) => {
      const entity = cache[entityId];
      const targets = impactedEntities[entityId];
      // Build document fields to update ( per relation type )
      const targetsByRelation = R.groupBy((i: any) => `${i.relationshipType}|${i.refField}`, targets as any);
      const targetsElements = Object.keys(targetsByRelation).map((relTypeAndField) => {
        const [relType, refField] = relTypeAndField.split('|');
        const data: any = targetsByRelation[relTypeAndField];
        const resolvedData = data.map((d: any) => {
          return { id: d.to.internal_id, side: d.side, type: d.type, pir_score: d.pir_score };
        });
        return { relation: relType, field: refField, elements: resolvedData };
      });
      // Create params and scripted update
      const params = buildDenormalizedRefsScriptParams(targetsElements, now());
      return { ...entity, id: entityId, data: { script: { source: EL_DENORMALIZED_REFS_SCRIPT_SOURCE, params } } };
    });
    // bulk update elements (denormalized relations)
    if (elementsToUpdate.length > 0) {
      const groupsOfElementsToUpdate = R.splitEvery(MAX_BULK_OPERATIONS, elementsToUpdate);
      for (let i = 0; i < groupsOfElementsToUpdate.length; i += 1) {
        const elementsBulk = groupsOfElementsToUpdate[i];
        const bodyUpdate = elementsBulk.flatMap((doc: any) => [
          { update: { _index: doc._index, _id: doc._id ?? doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
          R.dissoc('_index', doc.data),
        ]);
        if (bodyUpdate.length > 0) {
          meterManager.sideBulk(bodyUpdate.length, { type: indexingType });
          const bulkPromise = elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
          await Promise.all([bulkPromise]);
        }
      }
    }
    return transformedElements.length;
  };
  return telemetry(context, user, `INSERT ${indexingType}`, {
    [ATTR_DB_NAMESPACE]: 'search_engine',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_NAME]: 'search_engine',
    [ATTR_DB_OPERATION_NAME]: 'insert',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_OPERATION]: 'insert',
  }, elIndexElementsFn);
};

export const elUpdateRelationConnections = async (context: AuthContext, elements: any[]) => {
  if (elements.length > 0) {
    const source = 'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); '
      + 'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
    const bodyUpdate = elements.flatMap((doc) => [
      { update: { _index: doc._index, _id: doc._id ?? doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
      { script: { source, params: { id: doc.toReplace, changes: doc.data } } },
    ]);
    const bulkPromise = elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    await Promise.all([bulkPromise]);
  }
};
export const elUpdateEntityConnections = async (context: AuthContext, elements: any[]) => {
  if (elements.length > 0) {
    const source = `if (ctx._source[params.key] == null) {
      ctx._source[params.key] = params.to;
    } else if (params.from == null) {
      ctx._source[params.key].addAll(params.to);
    } else {
      def values = params.to;
      for (current in ctx._source[params.key]) {
        if (current != params.from && !values.contains(current)) { values.add(current); }
      }
      ctx._source[params.key] = values;
    }
  `;
    // doc.toReplace === null => from = null
    const addMultipleFormat = (doc: any) => {
      return Array.isArray(doc.data.internal_id) ? doc.data.internal_id : [doc.data.internal_id];
    };
    const bodyUpdate = elements.flatMap((doc) => {
      const refField = isStixRefRelationship(doc.relationType) && isInferredIndex(doc._index) ? ID_INFERRED : ID_INTERNAL;
      return [
        { update: { _index: doc._index, _id: doc._id ?? doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
        {
          script: {
            source,
            params: {
              key: buildRefRelationKey(doc.relationType, refField),
              from: doc.toReplace,
              to: addMultipleFormat(doc),
            },
          },
        },
      ];
    });
    await elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
  }
};

const elUpdateConnectionsOfElement = async (documentId: string, documentBody: any) => {
  const source = 'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); '
    + 'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
  return elRawUpdateByQuery({
    index: READ_RELATIONSHIPS_INDICES,
    refresh: true,
    conflicts: 'proceed',
    slices: 'auto', // improve performance by slicing the request
    wait_for_completion: false, // async (query can update a lot of elements)
    body: {
      script: { source, params: { id: documentId, changes: documentBody } },
      query: {
        nested: {
          path: 'connections',
          query: {
            bool: {
              must: [{ match_phrase: { 'connections.internal_id.keyword': documentId } }],
            },
          },
        },
      },
    },
  }).catch((err) => {
    throw DatabaseError('Error updating connections', { cause: err, documentId, body: documentBody });
  });
};
const createDeleteOperationElement = async (
  context: AuthContext,
  user: AuthUser,
  mainElement: StoreObject,
  deletedElements: BasicStoreBase[],
) => {
  // We currently only handle deleteOperations of 1 element
  const deleteOperationDeletedElements = deletedElements.map((e) => ({ id: e.internal_id, source_index: e._index }));
  const deleteOperationInput = {
    entity_type: ENTITY_TYPE_DELETE_OPERATION,
    main_entity_type: mainElement.entity_type,
    main_entity_id: mainElement.internal_id,
    main_entity_name: extractRepresentative(mainElement).main ?? mainElement.internal_id,
    deleted_elements: deleteOperationDeletedElements,
    confidence: (mainElement as BasicStoreEntity).confidence ?? 100,
    objectMarking: mainElement.objectMarking ?? [], // we retrieve resolved objectMarking if it exists
    objectOrganization: mainElement.objectOrganization ?? [], // we retrieve resolved objectOrganization if it exists
  };
  const { element, relations } = await buildEntityData(context, user, deleteOperationInput, ENTITY_TYPE_DELETE_OPERATION);

  await elIndexElements(context, user, ENTITY_TYPE_DELETE_OPERATION, [element, ...(relations ?? [])]);
};
type DeleteElementsOpts = {
  forceRefresh?: boolean;
  forceDelete?: boolean;
};
export const elDeleteElements = async (
  context: AuthContext,
  user: AuthUser,
  elements: BasicStoreBase[],
  opts: DeleteElementsOpts = {},
) => {
  if (elements.length === 0) return;
  if (getDraftContext(context, user)) {
    await elMarkElementsAsDraftDelete(context, user, elements);
    return;
  }
  const { forceDelete = true } = opts;
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, elements);
  // User must have access to all relations to remove to be able to delete
  const filteredRelations = await userFilterStoreElements(context, user, relations);
  if (relations.length !== filteredRelations.length) {
    throw FunctionalError('Cannot delete element: cannot access all related relations');
  }
  relations.forEach((instance) => controlUserConfidenceAgainstElement(user, instance));
  relations.forEach((instance) => controlUserRestrictDeleteAgainstElement(user, instance));
  // Compute the id that needs to be removed from rel
  const basicCleanup = elements.filter((f) => isBasicRelationship(f.entity_type)) as BasicStoreRelation[];
  // Update all rel connections that will remain
  const cleanupRelations = relations.concat(basicCleanup);
  const toBeRemovedIds = elements.map((e) => e.internal_id);
  const elementsImpact = await computeDeleteElementsImpacts(cleanupRelations, toBeRemovedIds, relationsToRemoveMap);
  const entitiesToDelete = [...elements, ...relations];
  // Store deleted objects
  // CURRENT LIMITATION: we only handle forceDelete when elDeleteElements is called with 1 element. This is because getRelationsToRemove returns all related relations without
  // linking the relations to a specific element, which we would need for the deleted_elements of deleteOperations. The difficulty in changing getRelationsToRemove is handling the
  // case where a relationship is linked to two elements given in elDeleteElements: how do we decide which element to link the relationship to?
  if (conf.get('app:trash:enabled') && !forceDelete && elements.length === 1) {
    // map of index => ids to save
    const idsByIndex = new Map();
    entitiesToDelete.forEach((element) => {
      if (!idsByIndex.has(element._index)) {
        idsByIndex.set(element._index, []);
      }
      idsByIndex.get(element._index).push(element.id);
    });
    const reindexPromises: Promise<any>[] = [];
    [...idsByIndex.keys()].forEach((sourceIndex) => {
      const ids = idsByIndex.get(sourceIndex);
      reindexPromises.push(elReindexElements(context, user, ids, sourceIndex, INDEX_DELETED_OBJECTS));
    });
    await Promise.all(reindexPromises);
    await createDeleteOperationElement(context, user, elements[0] as StoreObject, entitiesToDelete);
  }
  // 01. Start by clearing connections rel
  await elRemoveRelationConnection(context, user, elementsImpact, opts);
  // 02. Remove all related relations and elements
  logApp.debug('[SEARCH] Deleting related relations', { size: relations.length });
  await elDeleteInstances(context, relations, opts);
  // 03/ Remove all elements
  logApp.debug('[SEARCH] Deleting elements', { size: elements.length });
  await elDeleteInstances(context, elements, opts);
};
const getInstanceToUpdate = async (context: AuthContext, user: AuthUser, instance: BasicStoreBase) => {
  const draftContext = getDraftContext(context, user);
  // We still want to be able to update internal entities in draft, but we don't want to copy them to draft index
  if (draftContext && isDraftSupportedEntity(instance)) {
    return loadDraftElement(context, user, instance);
  }
  return instance;
};
export const elUpdateElement = async (context: AuthContext, user: AuthUser, instance: BasicStoreBase) => {
  const instanceToUse = await getInstanceToUpdate(context, user, instance);
  const esData = await prepareElementForIndexing(instanceToUse);
  validateDataBeforeIndexing(esData);
  const dataToReplace = R.pipe(R.dissoc('representative'), R.dissoc('_id'))(esData);
  const replacePromise = elReplace(context, instanceToUse._index, instanceToUse._id ?? instanceToUse.internal_id, { doc: dataToReplace });
  // If entity with a name, must update connections
  let connectionPromise = Promise.resolve();
  if (esData.name && isStixObject(instanceToUse.entity_type)) {
    connectionPromise = elUpdateConnectionsOfElement(instance.internal_id, { name: extractEntityRepresentativeName(esData) });
  }
  return Promise.all([replacePromise, connectionPromise]);
};

export const getStats = (indices = READ_PLATFORM_INDICES) => {
  const statsOperation = async () => {
    if (engine instanceof ElkClient) {
      const engineIndicesStats = await engine.indices.stats({ index: indices });
      return oebp(engineIndicesStats)._all.primaries;
    }
    const engineIndicesStats = await engine.indices.stats({ index: indices });
    return oebp(engineIndicesStats)._all.primaries;
  };
  return retryElOperations(statsOperation);
};

// Branches are kept separate: ELK types the metric as an array, OpenSearch as a string,
// and their client signatures are not mutually assignable.
// Scoped to `${ES_INDEX_PREFIX}*` (not '*'): on a cluster shared with other applications,
// a plain wildcard would sum every index in the cluster, not just OpenCTI's own size.
const fetchEngineUsedSize = async (): Promise<number> => {
  if (engine instanceof ElkClient) {
    const engineIndicesStats = await engine.indices.stats({ index: `${ES_INDEX_PREFIX}*`, metric: ['store'], expand_wildcards: 'all' as any });
    return Number(oebp(engineIndicesStats)?._all?.primaries?.store?.size_in_bytes ?? 0);
  }
  const engineIndicesStats = await engine.indices.stats({ index: `${ES_INDEX_PREFIX}*`, metric: 'store', expand_wildcards: 'all' as any });
  return Number(oebp(engineIndicesStats)?._all?.primaries?.store?.size_in_bytes ?? 0);
};

export const getEngineUsedSize = async (): Promise<number> => {
  return retryElOperations(fetchEngineUsedSize);
};

export const isEngineAlive = async () => {
  const context = executionContext('healthcheck');
  const options = { types: [ENTITY_TYPE_MIGRATION_STATUS], connectionFormat: false };
  const migrations = await elPaginate(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, options) as BasicStoreBase[];
  if (migrations.length === 0) {
    throw DatabaseError('Invalid database content, missing migration schema');
  }
};
