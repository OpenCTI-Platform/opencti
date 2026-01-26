import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
import { AwsSigv4Signer } from '@opensearch-project/opensearch/aws';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import semver from 'semver';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION, SEMATTRS_DB_STATEMENT } from '@opentelemetry/semantic-conventions';
import * as jsonpatch from 'fast-json-patch';
import {
  buildPagination,
  buildPaginationFromEdges,
  cursorToOffset,
  ES_INDEX_PREFIX,
  getIndicesToQuery,
  INDEX_DELETED_OBJECTS,
  INDEX_DRAFT_OBJECTS,
  INDEX_INTERNAL_OBJECTS,
  inferIndexFromConceptType,
  isDraftIndex,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  offsetToCursor,
  pascalize,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED,
  READ_ENTITIES_INDICES,
  READ_ENTITIES_INDICES_WITHOUT_INFERRED,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_PLATFORM_INDICES,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  waitInSec,
  WRITE_PLATFORM_INDICES,
} from './utils';
import conf, { booleanConf, extendedErrors, loadCert, logApp, logMigration } from '../config/conf';
import { ComplexSearchError, ConfigurationError, DatabaseError, EngineShardsError, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import {
  isStixRefRelationship,
  isStixRefUnidirectionalRelationship,
  RELATION_BORN_IN,
  RELATION_CREATED_BY,
  RELATION_ETHNICITY,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  RELATION_OBJECT_PARTICIPANT,
  STIX_REF_RELATIONSHIP_TYPES,
} from '../schema/stixRefRelationship';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  buildRefRelationSearchKey,
  ENTITY_TYPE_IDENTITY,
  ID_INFERRED,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  isAbstract,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
} from '../schema/general';
import { isModifiedObject, isUpdatedAtObject } from '../schema/fieldDataAdapter';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_DESCRIPTION,
  ATTRIBUTE_DESCRIPTION_OPENCTI,
  ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  isStixDomainObject,
  STIX_ORGANIZATIONS_RESTRICTED,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import { isBasicObject, isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationship } from '../schema/stixRelationship';
import { isStixCoreRelationship, RELATION_INDICATES, RELATION_LOCATED_AT, RELATION_PUBLISHES, RELATION_RELATED_TO, STIX_CORE_RELATIONSHIPS } from '../schema/stixCoreRelationship';
import { generateInternalId, INTERNAL_FROM_FIELD, INTERNAL_TO_FIELD } from '../schema/identifier';
import {
  BYPASS,
  computeUserMemberAccessIds,
  controlUserRestrictDeleteAgainstElement,
  executionContext,
  INTERNAL_USERS,
  isBypassUser,
  isServiceAccountUser,
  MEMBER_ACCESS_ALL,
  SYSTEM_USER,
  userFilterStoreElements,
} from '../utils/access';
import { isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { now, runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_MARKING_DEFINITION, isStixMetaObject } from '../schema/stixMetaObject';
import { getEntitiesListFromCache, getEntityFromCache } from './cache';
import { refang } from '../utils/refang';
import { ENTITY_TYPE_MIGRATION_STATUS, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER, isInternalObject } from '../schema/internalObject';
import { meterManager, telemetry } from '../config/tracing';
import {
  isBooleanAttribute,
  isDateAttribute,
  isDateNumericOrBooleanAttribute,
  isNumericAttribute,
  isObjectFlatAttribute,
  schemaAttributesDefinition,
  validateDataBeforeIndexing,
} from '../schema/schema-attributes';
import { convertTypeToStixType } from './stix-2-1-converter';
import { extractEntityRepresentativeName, extractRepresentative } from './entity-representative';
import { checkAndConvertFilters, extractFiltersFromGroup, isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import {
  ID_SUBFILTER,
  IDS_FILTER,
  INSTANCE_DYNAMIC_REGARDING_OF,
  INSTANCE_REGARDING_OF,
  INSTANCE_REGARDING_OF_DIRECTION_FORCED,
  INSTANCE_REGARDING_OF_DIRECTION_REVERSE,
  RELATION_INFERRED_SUBFILTER,
  RELATION_TYPE_SUBFILTER,
  TYPE_FILTER,
} from '../utils/filtering/filtering-constants';
import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../generated/graphql';
import {
  type AttributeDefinition,
  authorizedMembers,
  baseType,
  booleanMapping,
  dateMapping,
  entityType as entityTypeAttribute,
  id as idAttribute,
  internalId,
  longStringFormats,
  numericMapping,
  shortMapping,
  shortStringFormats,
  standardId,
  textMapping,
} from '../schema/attribute-definition';
import { connections as connectionsAttribute } from '../modules/attributes/basicRelationship-registrationAttributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import { INTERNAL_RELATIONSHIPS, isInternalRelationship, RELATION_IN_PIR, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { rule_definitions } from '../rules/rules-definition';
import { buildElasticSortingForAttributeCriteria } from '../utils/sorting';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { buildEntityData } from './data-builder';
import { buildDraftFilter, type BuildDraftFilterOpts, isDraftSupportedEntity } from './draft-utils';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { getDraftContext } from '../utils/draftContext';
import { enrichWithRemoteCredentials } from '../config/credentials';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, isStixCyberObservable } from '../schema/stixCyberObservable';
import { lockResources } from '../lock/master-lock';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE, DRAFT_OPERATION_DELETE_LINKED, DRAFT_OPERATION_UPDATE_LINKED } from '../modules/draftWorkspace/draftOperations';
import { RELATION_SAMPLE } from '../modules/malwareAnalysis/malwareAnalysis-types';
import { asyncMap } from '../utils/data-processing';
import { doYield } from '../utils/eventloop-utils';
import { RELATION_COVERED } from '../modules/securityCoverage/securityCoverage-types';
import type { AuthContext, AuthUser } from '../types/user';
import type {
  BasicConnection,
  BasicNodeEdge,
  BasicStoreBase,
  BasicStoreEntity,
  BasicStoreEntityMarkingDefinition,
  BasicStoreObject,
  BasicStoreRelation,
  StoreConnection,
  StoreMarkingDefinition,
  StoreObject,
  StoreRelation,
} from '../types/store';
import type { BasicStoreSettings } from '../types/settings';
import { completeSpecialFilterKeys } from '../utils/filtering/filtering-completeSpecialFilterKeys';
import { IDS_ATTRIBUTES } from '../domain/attribute-utils';
import type { FiltersWithNested } from './middleware-loader';

const ELK_ENGINE = 'elk';
const OPENSEARCH_ENGINE = 'opensearch';
export const ES_MAX_CONCURRENCY: number = conf.get('elasticsearch:max_concurrency');
export const ES_DEFAULT_WILDCARD_PREFIX: boolean = booleanConf('elasticsearch:search_wildcard_prefix', false);
export const ES_DEFAULT_FUZZY: boolean = booleanConf('elasticsearch:search_fuzzy', false);
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

let engine: ElkClient | OpenClient;
let isRuntimeSortingEnable = false;
let attachmentProcessorEnabled = false;

export const isAttachmentProcessorEnabled = () => {
  return attachmentProcessorEnabled;
};

// The OpenSearch/ELK Body Parser (oebp)
// Starting ELK8+, response are no longer inside a body envelop
// Query wrapping is still accepted in ELK8
const oebp = (queryResult: any): any => {
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
          roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity({ region }),
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
  logApp.info(`[SEARCH] ${enginePlatform} (${engineVersion}) client selected / runtime sorting ${runtimeStatus} / attachment processor ${attachmentProcessorEnabled ? 'enabled' : 'disabled'}`);
  // Everything is fine, return true
  return true;
};
export const isRuntimeSortEnable = (): boolean => isRuntimeSortingEnable;

export const elRawSearch = (context: AuthContext, user: AuthUser, types: string[] | string | null, query: any) => {
  // Add signal to prevent unwanted warning
  // Waiting for https://github.com/elastic/elastic-transport-js/issues/63
  const searchOpts = { signal: new AbortController().signal };
  const elRawSearchFn = async () => (engine instanceof ElkClient ? engine.search(query, searchOpts) : engine.search(query)).then((r: any) => {
    const parsedSearch = oebp(r);
    if (parsedSearch._shards.failed > 0) {
      // We do not support response with shards failure.
      // Result must be always accurate to prevent data duplication and unwanted behaviors
      // If any shard fail during query, engine throw a shard exception with shards information
      throw EngineShardsError({ shards: parsedSearch._shards });
    }
    // Return result of the search if everything goes well
    return parsedSearch;
  });
  return telemetry(context, user, `SELECT ${Array.isArray(types) ? types.join(', ') : (types || 'None')}`, {
    [SEMATTRS_DB_NAME]: 'search_engine',
    [SEMATTRS_DB_OPERATION]: 'read',
    [SEMATTRS_DB_STATEMENT]: JSON.stringify(query),
  }, elRawSearchFn);
};

export const elRawGet = async (args: { id: string; index: string }) => {
  if (engine instanceof ElkClient) {
    const r = await engine.get(args);
    return oebp(r);
  }
  const r_1 = await engine.get(args);
  return oebp(r_1);
};
export const elRawIndex = async (args: any) => {
  if (engine instanceof ElkClient) {
    const r = await engine.index(args);
    return oebp(r);
  }
  const r_1 = await engine.index(args);
  return oebp(r_1);
};
export const elRawDelete = async (args: any) => {
  if (engine instanceof ElkClient) {
    const r = await engine.delete(args);
    return oebp(r);
  }
  const r_1 = await engine.delete(args);
  return oebp(r_1);
};
export const elRawDeleteByQuery = async (query: any) => {
  if (engine instanceof ElkClient) {
    const r = await engine.deleteByQuery(query);
    return oebp(r);
  }
  const r_1 = await engine.deleteByQuery(query);
  return oebp(r_1);
};
export const elRawBulk = async (args: any) => {
  if (engine instanceof ElkClient) {
    const r = await engine.bulk(args);
    return oebp(r);
  }
  const r_1 = await engine.bulk(args);
  return oebp(r_1);
};
export const elRawUpdateByQuery = async (query: any) => {
  if (engine instanceof ElkClient) {
    const r = await engine.updateByQuery(query);
    return oebp(r);
  }
  const r_1 = await engine.updateByQuery(query);
  return oebp(r_1);
};
export const elRawReindexByQuery = async (query: any) => {
  if (engine instanceof ElkClient) {
    const r = await engine.reindex(query);
    return oebp(r);
  }
  const r_1 = await engine.reindex(query);
  return oebp(r_1);
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

const buildUserMemberAccessFilter = (user: AuthUser, opts: { includeAuthorities?: boolean | null; excludeEmptyAuthorizedMembers?: boolean }) => {
  const { includeAuthorities = false, excludeEmptyAuthorizedMembers = false } = opts;
  const capabilities = user.capabilities.map((c) => c.name);
  if (includeAuthorities && capabilities.includes(BYPASS)) {
    return [];
  }
  const userAccessIds = computeUserMemberAccessIds(user);
  // if access_users exists, it should have the user access ids
  const emptyAuthorizedMembers = { bool: { must_not: { nested: { path: authorizedMembers.name, query: { match_all: { } } } } } };
  // condition on authorizedMembers id
  const authorizedMembersIdsTerms = { terms: { [`${authorizedMembers.name}.id.keyword`]: [MEMBER_ACCESS_ALL, ...userAccessIds] } };
  // condition on group restriction ids
  const userGroupsIds = user.groups.map((group) => group.internal_id);
  const groupRestrictionCondition = {
    bool: {
      should: [
        { bool: { must_not: [{ exists: { field: `${authorizedMembers.name}.groups_restriction_ids` } }] } },
        {
          terms_set: {
            [`${authorizedMembers.name}.groups_restriction_ids.keyword`]: {
              terms: userGroupsIds,
              minimum_should_match_script: {
                source: `doc['${authorizedMembers.name}.groups_restriction_ids.keyword'].length`,
              },
            },
          },
        },
      ],
    },
  };
  const authorizedFilters = [
    { bool: { must: [authorizedMembersIdsTerms, groupRestrictionCondition] } },
  ];
  const shouldConditions = [];
  if (includeAuthorities) {
    const roleIds = user.roles.map((r) => r.id);
    const owners = [...userAccessIds, ...capabilities, ...roleIds];
    shouldConditions.push({ terms: { 'authorized_authorities.keyword': owners } });
  }
  if (!excludeEmptyAuthorizedMembers) {
    shouldConditions.push(emptyAuthorizedMembers);
  }

  const bypassAuthorizedMembers = isServiceAccountUser(user);
  const nestedQuery = {
    nested: {
      path: authorizedMembers.name,
      query: {
        // For service accounts, bypass authorized members restrictions
        bool: { should: bypassAuthorizedMembers ? [] : authorizedFilters },
      },
    },
  };
  shouldConditions.push(nestedQuery);
  return [{ bool: { should: shouldConditions } }];
};

export const buildDataRestrictions = async (
  context: AuthContext,
  user: AuthUser,
  opts: { includeAuthorities?: boolean | null } | null | undefined = {},
): Promise<{ must: any[]; must_not: any[] }> => {
  const must: any[] = [];
  const must_not: any[] = [];
  // If internal users of the system, we cancel rights checking
  if (INTERNAL_USERS[user.id]) {
    return { must, must_not };
  }
  // check user access
  must.push(...buildUserMemberAccessFilter(user, { includeAuthorities: opts?.includeAuthorities }));
  // If user have bypass, no need to check restrictions
  if (!isBypassUser(user)) {
    // region Handle marking restrictions
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Compute all markings that the user doesnt have access to
      const allMarkings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
      const mustNotHaveOneOf = [];
      const userMarkingsIds = new Set(user.allowed_marking.map((m) => m.internal_id));
      for (let index = 0; index < allMarkings.length; index += 1) {
        const marking = allMarkings[index];
        const markingId = marking.internal_id;
        if (!userMarkingsIds.has(markingId)) {
          mustNotHaveOneOf.push(markingId);
        }
      }
      // If use have marking, he can access to data with no marking && data with according marking
      const mustNotMarkingTerms = [{
        terms: {
          [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: mustNotHaveOneOf,
        },
      }];
      const markingBool = {
        bool: {
          should: [
            {
              bool: {
                must_not: [{ exists: { field: buildRefRelationSearchKey(RELATION_OBJECT_MARKING) } }],
              },
            },
            {
              bool: {
                must_not: mustNotMarkingTerms,
              },
            },
          ],
          minimum_should_match: 1,
        },
      };
      must.push(markingBool);
    }
    // endregion
    // region Handle organization restrictions
    // If user have organization management role, he can bypass this restriction.
    // If platform is for specific organization, only user from this organization can access empty defined
    const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
    // We want to exclude a set of entities from organization restrictions while forcing restrictions for another set of entities
    const excludedEntityMatches = {
      bool: {
        must: [
          {
            bool: { must_not: [{ terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_RESTRICTED } }] },
          },
          {
            bool: {
              should: [
                { terms: { 'parent_types.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } },
                { terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } },
              ],
              minimum_should_match: 1,
            },
          },
        ],
      },
    };
    if (settings.platform_organization) {
      if (context.user_inside_platform_organization) {
        // Data are visible independently of the organizations
        // Nothing to restrict.
      } else {
        // Data with Empty granted_refs are not visible
        // Data with granted_refs users that participate to at least one
        const should: any[] = [excludedEntityMatches];
        const shouldOrgs = user.organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        should.push(...shouldOrgs);
        // User individual or data created by this individual must be accessible
        if (user.individual_id) {
          should.push({ match: { 'internal_id.keyword': user.individual_id } });
          should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
        }
        // For tasks
        should.push({ match: { 'initiator_id.keyword': user.internal_id } });
        // Access to authorized members
        should.push(...buildUserMemberAccessFilter(user, { includeAuthorities: opts?.includeAuthorities, excludeEmptyAuthorizedMembers: true }));
        // Finally build the bool should search
        must.push({ bool: { should, minimum_should_match: 1 } });
      }
    }
    // endregion
  }
  return { must, must_not };
};

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
    await engine.transport.request({
      method: 'PUT',
      path: `_plugins/_ism/policies/${ES_INDEX_PREFIX}-ism-policy`,
      body: {
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
      },
    }).catch((e) => {
      throw DatabaseError('Creating lifecycle policy fail', { cause: e });
    });
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

// Engine mapping generation on attributes definition
const attributeMappingGenerator = (entityAttribute: AttributeDefinition): any => {
  if (entityAttribute.type === 'string') {
    if (shortStringFormats.includes(entityAttribute.format)) {
      return shortMapping;
    }
    if (longStringFormats.includes(entityAttribute.format)) {
      return textMapping;
    }
    throw UnsupportedError('Cant generated string mapping', { format: entityAttribute.format });
  }
  if (entityAttribute.type === 'date') {
    return dateMapping;
  }
  if (entityAttribute.type === 'numeric') {
    return numericMapping(entityAttribute.precision);
  }
  if (entityAttribute.type === 'boolean') {
    return booleanMapping;
  }
  if (entityAttribute.type === 'object') {
    // For flat object
    if (entityAttribute.format === 'flat') {
      return { type: engine instanceof ElkClient ? 'flattened' : 'flat_object' };
    }
    // For standard object
    const properties: Record<string, any> = {};
    for (let i = 0; i < entityAttribute.mappings.length; i += 1) {
      const mapping = entityAttribute.mappings[i];
      properties[mapping.name] = attributeMappingGenerator(mapping);
    }
    const config: { dynamic: string; properties: any; type?: string } = { dynamic: 'strict', properties };
    // Add nested option if needed
    if (entityAttribute.format === 'nested') {
      config.type = 'nested';
    }
    return config;
  }
  throw UnsupportedError('Cant generated mapping', { type: entityAttribute.type });
};
const ruleMappingGenerator = (): Record<string, { dynamic: string; properties: any }> => {
  const schemaProperties: Record<string, { dynamic: string; properties: any }> = {};
  for (let attrIndex = 0; attrIndex < rule_definitions.length; attrIndex += 1) {
    const rule = rule_definitions[attrIndex];
    schemaProperties[`i_rule_${rule.id}`] = {
      dynamic: 'strict',
      properties: {
        explanation: shortMapping,
        dependencies: shortMapping,
        hash: shortMapping,
        data: { type: engine instanceof ElkClient ? 'flattened' : 'flat_object' },
      },
    };
  }
  return schemaProperties;
};
const denormalizeRelationsMappingGenerator = (): Record<string, { dynamic: string; properties: any }> => {
  const databaseRelationshipsName = [
    STIX_SIGHTING_RELATIONSHIP,
    ...STIX_CORE_RELATIONSHIPS,
    ...INTERNAL_RELATIONSHIPS,
    ...schemaTypesDefinition.get(ABSTRACT_STIX_REF_RELATIONSHIP),
  ];
  const schemaProperties: Record<string, { dynamic: string; properties: any }> = {};
  for (let attrIndex = 0; attrIndex < databaseRelationshipsName.length; attrIndex += 1) {
    const relName = databaseRelationshipsName[attrIndex];
    schemaProperties[`rel_${relName}`] = {
      dynamic: 'strict',
      properties: {
        internal_id: shortMapping,
        inferred_id: shortMapping,
      },
    };
  }
  return schemaProperties;
};
const attributesMappingGenerator = (): Record<string, any> => {
  const entityAttributes = schemaAttributesDefinition.getAllAttributes();
  const schemaProperties: Record<string, any> = {};
  for (let attrIndex = 0; attrIndex < entityAttributes.length; attrIndex += 1) {
    const entityAttribute = entityAttributes[attrIndex];
    schemaProperties[entityAttribute.name] = attributeMappingGenerator(entityAttribute);
  }
  return schemaProperties;
};

export const engineMappingGenerator = (): Record<string, any> => {
  return { ...attributesMappingGenerator(), ...ruleMappingGenerator(), ...denormalizeRelationsMappingGenerator() };
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

// Only useful for option ES_INIT_RETRO_MAPPING_MIGRATION
// This mode let the platform initialize old mapping protection before direct stop
// Its only useful when old platform needs to be reindex
const getRetroCompatibleMappings = (): any => {
  const flattenedType = engine instanceof ElkClient ? 'flattened' : 'flat_object';
  return {
    internal_id: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    standard_id: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    user_email: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    name: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    height: {
      type: 'nested',
      properties: {
        measure: { type: 'float' },
        date_seen: { type: 'date' },
      },
    },
    weight: {
      type: 'nested',
      properties: {
        measure: { type: 'float' },
        date_seen: { type: 'date' },
      },
    },
    timestamp: {
      type: 'date',
    },
    created: {
      type: 'date',
    },
    created_at: {
      type: 'date',
    },
    modified: {
      type: 'date',
    },
    modified_at: {
      type: 'date',
    },
    indexed_at: {
      type: 'date',
    },
    uploaded_at: {
      type: 'date',
    },
    first_seen: {
      type: 'date',
    },
    last_seen: {
      type: 'date',
    },
    start_time: {
      type: 'date',
    },
    stop_time: {
      type: 'date',
    },
    published: {
      type: 'date',
    },
    valid_from: {
      type: 'date',
    },
    valid_until: {
      type: 'date',
    },
    observable_date: {
      type: 'date',
    },
    event_date: {
      type: 'date',
    },
    received_time: {
      type: 'date',
    },
    processed_time: {
      type: 'date',
    },
    completed_time: {
      type: 'date',
    },
    ctime: {
      type: 'date',
    },
    mtime: {
      type: 'date',
    },
    atime: {
      type: 'date',
    },
    current_state_date: {
      type: 'date',
    },
    confidence: {
      type: 'integer',
    },
    attribute_order: {
      type: 'integer',
    },
    base_score: {
      type: 'integer',
    },
    is_family: {
      type: 'boolean',
    },
    number_observed: {
      type: 'integer',
    },
    x_opencti_negative: {
      type: 'boolean',
    },
    default_assignation: {
      type: 'boolean',
    },
    x_opencti_detection: {
      type: 'boolean',
    },
    x_opencti_order: {
      type: 'integer',
    },
    import_expected_number: {
      type: 'integer',
    },
    import_processed_number: {
      type: 'integer',
    },
    x_opencti_score: {
      type: 'integer',
    },
    connections: {
      type: 'nested',
    },
    manager_setting: {
      type: flattenedType,
    },
    context_data: {
      properties: {
        input: { type: flattenedType },
      },
    },
    size: {
      type: 'integer',
    },
    lastModifiedSinceMin: {
      type: 'integer',
    },
    lastModified: {
      type: 'date',
    },
    metaData: {
      properties: {
        order: {
          type: 'integer',
        },
        inCarousel: {
          type: 'boolean',
        },
        messages: { type: flattenedType },
        errors: { type: flattenedType },
      },
    },
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
          properties: getRetroCompatibleMappings(),
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
  const mappingProperties = engineMappingGenerator();
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
export const elCreateIndex = async (index: string, mappingProperties: Record<string, any>): Promise<any> => {
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
  const mappingProperties = engineMappingGenerator();
  for (let i = 0; i < indexesToCreate.length; i += 1) {
    const index = indexesToCreate[i];
    const createdIndex = await elCreateIndex(index, mappingProperties);
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
const getRuntimeUsers = async (context: AuthContext, user: AuthUser) => {
  const users = await getEntitiesListFromCache<AuthUser>(context, user, ENTITY_TYPE_USER);
  return R.mergeAll(users.map((i) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
};
const getRuntimeMarkings = async (context: AuthContext, user: AuthUser) => {
  const identities = await getEntitiesListFromCache<BasicStoreEntityMarkingDefinition>(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.definition })));
};
const withInferencesEntities = (indices: string[], withInferences: boolean) => {
  return withInferences ? [READ_INDEX_INFERRED_ENTITIES, ...indices] : indices;
};
const withInferencesRels = (indices: string[], withInferences: boolean) => {
  return withInferences ? [READ_INDEX_INFERRED_RELATIONSHIPS, ...indices] : indices;
};
export const computeQueryIndices = (
  indices: string[] | string | undefined | null,
  typeOrTypes: string[] | string | undefined | null,
  withInferences = true,
): string[] | string | undefined | null => {
  const types = (Array.isArray(typeOrTypes) || isEmptyField(typeOrTypes)) ? typeOrTypes : [typeOrTypes] as string[];
  // If indices are explicitly defined, just rely on the definition
  if (isEmptyField(indices)) {
    // If not and have no clue about the expected types, ask for all indices.
    // Worst case scenario that need to be avoided.
    if (isEmptyField(types)) {
      return withInferences ? READ_DATA_INDICES : READ_DATA_INDICES_WITHOUT_INFERRED;
    }
    // If types are defined we need to infer from them the correct indices
    const definedTypes = types as string[];
    return R.uniq(definedTypes.map((findType) => {
      // If defined types are abstract, try to restrict the indices as much as possible
      if (isAbstract(findType)) {
        // For objects
        if (isBasicObject(findType)) {
          if (isInternalObject(findType)) {
            return withInferencesEntities([READ_INDEX_INTERNAL_OBJECTS], withInferences);
          }
          if (isStixMetaObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_META_OBJECTS], withInferences);
          }
          if (isStixDomainObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_DOMAIN_OBJECTS], withInferences);
          }
          if (isStixCoreObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], withInferences);
          }
          if (isStixObject(findType)) {
            return withInferencesEntities([READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES], withInferences);
          }
          return withInferences ? READ_ENTITIES_INDICES : READ_ENTITIES_INDICES_WITHOUT_INFERRED;
        }
        // For relationships
        if (isBasicRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
          if (isInternalRelationship(findType)) {
            return withInferencesRels([READ_INDEX_INTERNAL_RELATIONSHIPS], withInferences);
          }
          if (isStixSightingRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_SIGHTING_RELATIONSHIPS], withInferences);
          }
          if (isStixCoreRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_CORE_RELATIONSHIPS], withInferences);
          }
          if (isStixRefRelationship(findType) || STIX_REF_RELATIONSHIP_TYPES.includes(findType)) {
            return withInferencesRels([READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS], withInferences);
          }
          if (isStixRelationship(findType)) {
            return withInferencesRels([READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, READ_INDEX_STIX_META_RELATIONSHIPS,
              READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS], withInferences);
          }
          return withInferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
        }
        // Fallback
        throw UnsupportedError('Fail to compute indices for unknown type', { type: findType });
      }
      // If concrete type, infer the index from the type
      if (isBasicObject(findType)) {
        return withInferencesEntities([`${inferIndexFromConceptType(findType)}*`], withInferences);
      }
      return withInferencesRels([`${inferIndexFromConceptType(findType)}*`], withInferences);
    }).flat());
  }
  return indices;
};
// Default fetch used by loadThroughDenormalized
// This rel_ must be low volume
// DO NOT ADD Anything here if you are not sure about that you doing
const REL_DEFAULT_SUFFIX = '*.keyword';
const REL_DEFAULT_FETCH = [
  // SECURITY
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_GRANTED_TO}${REL_DEFAULT_SUFFIX}`,
  // DEFAULT (LOW VOLUME)
  `${REL_INDEX_PREFIX}${RELATION_COVERED}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_PARTICIPANT}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_OBJECT_ASSIGNEE}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_KILL_CHAIN_PHASE}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_BORN_IN}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_ETHNICITY}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_SAMPLE}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_PARTICIPATE_TO}${REL_DEFAULT_SUFFIX}`,
  `${REL_INDEX_PREFIX}${RELATION_IN_PIR}${REL_DEFAULT_SUFFIX}`,
];
const REL_COUNT_SCRIPT_FIELD = {
  script: {
    lang: 'painless',
    source: `
          int totalElements = 0;
          for (String fieldName : params['_source'].keySet()) {
            if (fieldName.startsWith('rel_')) {
              def fieldValue = params['_source'].get(fieldName);
              if (fieldValue != null) {
                if (fieldValue instanceof List) {
                  totalElements += ((List) fieldValue).size();
                } else {
                  totalElements++;
                }
              }
            }
          }
          return totalElements;
        `,
  },
};
const BASE_FIELDS = [
  '_index',
  idAttribute.name,
  internalId.name,
  standardId.name,
  'sort',
  baseType.name,
  entityTypeAttribute.name,
  connectionsAttribute.name,
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  authorizedMembers.name,
];
const RANGE_OPERATORS = ['gt', 'gte', 'lt', 'lte'];

// region relation reconstruction
const elBuildRelation = (type: string, connection: StoreConnection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: connection.types.find((connectionType) => !isAbstract(connectionType)),
  };
};
const elMergeRelation = (
  concept: { internal_id: string; base_type: string; entity_type: string },
  fromConnection: StoreConnection | undefined,
  toConnection: StoreConnection | undefined,
) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('Reconstruction of the relation fail', concept.internal_id);
  }
  const from = elBuildRelation('from', fromConnection);
  from.source_ref = `${convertTypeToStixType(from.fromType as string)}--temporary`;
  const to = elBuildRelation('to', toConnection);
  to.target_ref = `${convertTypeToStixType(to.toType as string)}--temporary`;
  return R.mergeAll([concept, from, to]);
};
export const elRebuildRelation = (concept: { internal_id: string; base_type: string; entity_type: string }) => {
  if (concept.base_type === BASE_TYPE_RELATION) {
    const { connections } = concept as BasicStoreRelation;
    const entityType = concept.entity_type;
    const fromConnection = R.find((connection) => connection.role === `${entityType}_from`, connections);
    const toConnection = R.find((connection) => connection.role === `${entityType}_to`, connections);
    const relation = elMergeRelation(concept as BasicStoreRelation, fromConnection, toConnection);
    relation.relationship_type = relation.entity_type;
    return R.dissoc('connections', relation);
  }
  return concept;
};
const elDataConverter = <T>(esHit: any): T => {
  const elementData = esHit._source;
  const data: Record<string, any> = {
    _index: esHit._index,
    _id: esHit._id,
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
    ...(isNotEmptyField(esHit.fields) ? esHit.fields : {}),
  };
  const entries = Object.entries(data);
  const ruleInferences = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions: any = Object.values(val);
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = R.toPairs(inferred).map((s) => ({ field: R.head(s), value: String(R.last(s)) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
      data[key] = val;
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      const rel = key.substring(REL_INDEX_PREFIX.length);
      const [relType] = rel.split('.');
      if (isSingleRelationsRef(data.entity_type, relType)) {
        data[relType] = R.head(val);
      } else {
        const relData = [...(data[relType] ?? []), ...val];
        data[relType] = isStixRefUnidirectionalRelationship(relType) ? R.uniq(relData) : relData;
      }
    } else {
      data[key] = val;
    }
  }
  if (ruleInferences.length > 0) {
    data.x_opencti_inferences = ruleInferences;
  }
  if (data.event_data) {
    data.event_data = JSON.stringify(data.event_data);
  }
  return data as T;
};
// endregion
export const elConvertHitsToMap = async <T extends BasicStoreBase>(
  elements: T[],
  opts: { mapWithAllIds?: boolean } = {},
): Promise<Record<string, T>> => {
  const { mapWithAllIds = false } = opts;
  const convertedHitsMap: Record<string, T> = {};
  for (let n = 0; n < elements.length; n += 1) {
    await doYield();
    const element = elements[n];
    convertedHitsMap[element.internal_id] = element;
    if (mapWithAllIds) {
      // Add the standard id key
      if (element.standard_id) {
        convertedHitsMap[element.standard_id] = element;
      }
      // Add the stix ids keys
      (element.x_opencti_stix_ids ?? []).forEach((id) => {
        convertedHitsMap[id] = element;
      });
    }
  }
  return convertedHitsMap;
};

export const elConvertHits = async <T extends BasicStoreBase> (data: any): Promise<T[]> => asyncMap<any, T>(data, (hit) => elDataConverter<T>(hit));

const findElementsDuplicateIds = (elements: BasicStoreBase[]): string[] => {
  const duplicatedIds = new Set<string>();
  const elementIds = new Set<string>();
  const checkCurrentIds = (id: string | undefined | null) => {
    if (!id) return;
    if (elementIds.has(id) && !duplicatedIds.has(id)) {
      duplicatedIds.add(id);
    } else {
      elementIds.add(id);
    }
  };
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    const { internal_id, standard_id, x_opencti_stix_ids, i_aliases_ids } = element;
    checkCurrentIds(internal_id);
    checkCurrentIds(standard_id);
    x_opencti_stix_ids?.map((id) => checkCurrentIds(id));
    i_aliases_ids?.map((id) => checkCurrentIds(id));
  }
  return Array.from(duplicatedIds);
};

// region elastic common loader.
export const specialElasticCharsEscape = (query: string) => {
  return query.replace(/([/+|\-*()^~={}[\]:?!"\\])/g, '\\$1');
};
type ElFindByIdsOpts = {
  indices?: string[] | string | null;
  baseData?: boolean | null;
  baseFields?: string[];
  withoutRels?: boolean | null;
  toMap?: boolean;
  mapWithAllIds?: boolean;
  type?: string | string [] | null;
  relCount?: boolean | null;
  includeDeletedInDraft?: boolean | null;
};

// elFindByIds is not defined to use ordering or sorting (ordering is forced by creation date)
// It's a way to load a bunch of ids and use in list or map
export const elFindByIds = async <T extends BasicStoreBase> (
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
  const processIds = R.filter((id) => isNotEmptyField(id), idsArray);
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
    const restrictionOptions = { includeAuthorities: true }; // By default include authorized through capabilities
    // If an admin ask for a specific element, there is no need to ask him to explicitly extends his visibility to doing it.
    const markingRestrictions = await buildDataRestrictions(context, user, restrictionOptions);
    mustTerms.push(...markingRestrictions.must);
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
      throw DatabaseError('Find direct ids fail', { cause: err, query, searchType });
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
      hits.push(...convertedHits);
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
  const hits = await elFindByIds<T>(context, user, ids, { type: types, includeDeletedInDraft: true }) as T[];
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
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

// Global search attributes are limited
// Its due to opensearch / elastic limitations
const BASE_SEARCH_CONNECTIONS = [
  // Pounds for connections search
  `connections.${ATTRIBUTE_NAME}^4`,
  // Add all other attributes
  'connections.*',
];
const BASE_SEARCH_ATTRIBUTES = [
  // Pounds for attributes search
  `${ATTRIBUTE_NAME}^5`,
  `${ATTRIBUTE_ABSTRACT}^5`,
  `${ATTRIBUTE_EXPLANATION}^5`,
  `${ID_INTERNAL}^5`,
  `${ID_STANDARD}^5`,
  `${IDS_STIX}^5`,
  `${ATTRIBUTE_DESCRIPTION}^2`,
  `${ATTRIBUTE_DESCRIPTION_OPENCTI}^2`,
  // For activities
  'event_type',
  'event_scope',
  'context_data.message',
  // Add all other attributes
  'aliases',
  'x_opencti_aliases',
  'persona_name',
  'roles',
  'objective',
  'content',
  'content_mapping',
  'explanation',
  'opinion',
  'x_mitre_id',
  'x_opencti_threat_hunting',
  'x_opencti_log_sources',
  'postal_code',
  'street_address',
  'source',
  'context',
  'pattern',
  'path',
  'value',
  'display_name',
  'account_login',
  'user_id',
  'body',
  'hashes.MD5',
  'hashes.SHA-1',
  'hashes.SHA-256',
  'hashes.SHA-512',
  'hashes.SHA3-256',
  'hashes.SHA3-512',
  'hashes.SSDEEP',
  'hashes.SDHASH',
  'hashes.TLSH',
  'hashes.LZJD',
  'url',
  'subject',
  'payload_bin',
  'x_opencti_additional_names',
  'serial_number',
  'issuer',
  'cwd',
  'command_line',
  'cpe',
  'swid',
  'iban',
  'bic',
  'account_number',
  'card_number',
  'holder_name',
  'title',
  'result_name',
  'phase_name',
  'kill_chain_name',
  'definition',
  'definition_type',
  'user_email',
  'main_entity_name', // deletedOperation
];

type ProcessSearchArgs = {
  useWildcardPrefix?: boolean;
};
function processSearch(
  search: string,
  args: ProcessSearchArgs,
): { exactSearch: string[]; querySearch: string[] } {
  const { useWildcardPrefix = ES_DEFAULT_WILDCARD_PREFIX } = args;
  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(refang(search))
      .trim();
  } catch (_e) {
    decodedSearch = refang(search).trim();
  }
  let remainingSearch = decodedSearch;
  const exactSearch = (decodedSearch.match(/"[^"]+"/g) || []) //
    .filter((e) => isNotEmptyField(e.replace(/"/g, '')
      .trim()));
  for (let index = 0; index < exactSearch.length; index += 1) {
    remainingSearch = remainingSearch.replace(exactSearch[index], '');
  }
  const querySearch = [];

  const partialSearch = remainingSearch.replace(/"/g, '')
    .trim()
    .split(' ');

  for (let searchIndex = 0; searchIndex < partialSearch.length; searchIndex += 1) {
    const partialElement = partialSearch[searchIndex];
    const cleanElement = specialElasticCharsEscape(partialElement);
    if (isNotEmptyField(cleanElement)) {
      querySearch.push(`${useWildcardPrefix ? '*' : ''}${cleanElement}*`);
      if (ES_DEFAULT_FUZZY) {
        querySearch.push(`${cleanElement}~`);
      }
    }
  }
  return {
    exactSearch,
    querySearch,
  };
}
export const elGenerateFullTextSearchShould = (search: string, args: ProcessSearchArgs = {}) => {
  const { exactSearch, querySearch } = processSearch(search, args);
  // Return the elastic search engine expected bool should terms
  // Build the search for all exact match (between double quotes)
  const shouldSearch = [];
  const cleanExactSearch = R.uniq(exactSearch.map((e) => e.replace(/"|http?:/g, '')));
  shouldSearch.push(
    ...cleanExactSearch.map((ex) => [
      {
        multi_match: {
          type: 'phrase',
          query: ex,
          lenient: true,
          fields: BASE_SEARCH_ATTRIBUTES,
        },
      },
      {
        nested: {
          path: 'connections',
          query: {
            bool: {
              must: [
                {
                  multi_match: {
                    type: 'phrase',
                    query: ex,
                    lenient: true,
                    fields: BASE_SEARCH_CONNECTIONS,
                  },
                },
              ],
            },
          },
        },
      },
    ]).flat(),
  );
  // Build the search for all other fields
  const searchPhrase = R.uniq(querySearch).join(' ');
  if (searchPhrase) {
    shouldSearch.push(...[
      {
        query_string: {
          query: searchPhrase,
          analyze_wildcard: true,
          fields: BASE_SEARCH_ATTRIBUTES,
        },
      },
      {
        multi_match: {
          type: 'phrase',
          query: searchPhrase,
          lenient: true,
          fields: BASE_SEARCH_ATTRIBUTES,
        },
      },
      {
        nested: {
          path: 'connections',
          query: {
            bool: {
              must: [
                {
                  query_string: {
                    query: searchPhrase,
                    analyze_wildcard: true,
                    fields: BASE_SEARCH_CONNECTIONS,
                  },
                },
              ],
            },
          },
        },
      },
    ]);
  }
  return shouldSearch;
};

export const elGenerateFieldTextSearchShould = (
  search: string,
  arrayKeys: string[],
  args: ProcessSearchArgs = {},
) => {
  const { exactSearch, querySearch } = processSearch(search, args);
  const cleanExactSearch = R.uniq(exactSearch.map((e) => e.replace(/"|http?:/g, '')));
  const shouldSearch = [];
  shouldSearch.push(
    ...cleanExactSearch.map((ex) => [
      {
        multi_match: {
          type: 'phrase',
          query: ex,
          lenient: true,
          fields: arrayKeys,
        },
      },
    ]).flat(),
  );
  // Build the search for all other fields
  const searchPhrase = R.uniq(querySearch).join(' ');
  if (searchPhrase) {
    shouldSearch.push(...[
      {
        query_string: {
          query: searchPhrase,
          analyze_wildcard: true,
          fields: arrayKeys,
        },
      },
      {
        multi_match: {
          type: 'phrase',
          query: searchPhrase,
          lenient: true,
          fields: arrayKeys,
        },
      },
    ]);
  }

  return shouldSearch;
};
const buildFieldForQuery = (field: string) => {
  return isDateNumericOrBooleanAttribute(field) || field === '_id' || isObjectFlatAttribute(field)
    ? field
    : `${field}.keyword`;
};
export const buildLocalMustFilter = (validFilter: any) => {
  const valuesFiltering = [];
  const noValuesFiltering = [];
  const { key, values, nested, operator = 'eq', mode: localFilterMode = 'or' } = validFilter;
  if (isEmptyField(key)) {
    throw FunctionalError('A filter key must be defined', { key });
  }
  const arrayKeys = Array.isArray(key) ? key : [key];
  const headKey = R.head(arrayKeys);
  const dontHandleMultipleKeys = nested || operator === 'nil' || operator === 'not_nil';
  if (dontHandleMultipleKeys && arrayKeys.length > 1) {
    throw UnsupportedError('Filter must have only one field', { keys: arrayKeys, operator });
  }
  // 01. Handle nested filters
  // TODO IF KEY is PART OF Rule we need to add extra fields search
  // TODO Add connections like filters to have native fromId, toId filters handling.
  // See opencti-front\src\private\components\events\StixSightingRelationships.tsx
  if (nested) {
    const nestedMust = [];
    const nestedMustNot = [];
    for (let nestIndex = 0; nestIndex < nested.length; nestIndex += 1) {
      const nestedElement = nested[nestIndex];
      const parentKey = arrayKeys.at(0);
      const { key: nestedKey, values: nestedValues, operator: nestedOperator = 'eq' } = nestedElement;
      const nestedShould = [];
      const nestedFieldKey = `${parentKey}.${nestedKey}`;
      // nil and not_nil operators
      if (nestedOperator === 'nil') {
        nestedMustNot.push({
          exists: {
            field: nestedFieldKey,
          },
        });
      } else if (nestedOperator === 'not_nil') {
        nestedShould.push({
          exists: {
            field: nestedFieldKey,
          },
        });
      }
      // other operators
      if (nestedKey === ID_INTERNAL) {
        if (nestedOperator === 'not_eq') {
          nestedMustNot.push({ terms: { [`${nestedFieldKey}.keyword`]: nestedValues } });
        } else { // nestedOperator = 'eq'
          nestedShould.push({ terms: { [`${nestedFieldKey}.keyword`]: nestedValues } });
        }
      } else { // nested key !== internal_id
        if (nestedOperator === FilterOperator.Within) {
          nestedShould.push({
            range: {
              [nestedFieldKey]: { gte: nestedValues[0], lte: nestedValues[1] },
            },
          });
        } else if (isNotEmptyField(nestedValues)) {
          for (let i = 0; i < nestedValues.length; i += 1) {
            const nestedSearchValue = nestedValues[i].toString();
            if (nestedOperator === 'wildcard') {
              nestedShould.push({ query_string: { query: `${nestedSearchValue}`, fields: [nestedFieldKey] } });
            } else if (nestedOperator === 'not_eq') {
              nestedMustNot.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                },
              });
            } else if (RANGE_OPERATORS.includes(nestedOperator)) {
              nestedShould.push({
                range: {
                  [nestedFieldKey]: { [nestedOperator]: nestedSearchValue },
                },
              });
            } else { // nestedOperator = 'eq'
              nestedShould.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                },
              });
            }
          }
        }
      }
      const should = {
        bool: {
          should: nestedShould,
          minimum_should_match: localFilterMode === 'or' ? 1 : nestedValues.length,
        },
      };
      nestedMust.push(should);
    }
    const nestedQuery = {
      path: headKey,
      query: {
        bool: {
          must: nestedMust,
          must_not: nestedMustNot,
        },
      },
    };
    return { nested: nestedQuery };
  }
  // 02. Handle nil and not_nil operators
  if (operator === 'nil') {
    const filterDefinition = schemaAttributesDefinition.getAttributeByName(headKey);
    let valueFiltering: any = { // classic filters: field doesn't exist
      bool: {
        must_not: {
          exists: {
            field: headKey,
          },
        },
      },
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must_not: {
              wildcard: {
                [headKey]: '*',
              },
            },
          },
        };
      } else { // string filters: nil <-> (field doesn't exist) OR (field = empty string)
        valueFiltering = {
          bool: {
            should: [
              {
                bool: {
                  must_not: {
                    exists: {
                      field: headKey,
                    },
                  },
                },
              },
              {
                term: {
                  [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                },
              },
            ],
            minimum_should_match: 1,
          },
        };
      }
    } else if (filterDefinition?.type === 'date') { // date filters: nil <-> (field doesn't exist) OR (date <= epoch) OR (date >= 5138)
      valueFiltering = {
        bool: {
          should: [
            {
              bool: {
                must_not: {
                  exists: {
                    field: headKey,
                  },
                },
              },
            },
            { range: { [headKey]: { lte: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { gte: '5138-11-16T09:46:40.000Z' } } },
          ],
          minimum_should_match: 1,
        },
      };
    }
    valuesFiltering.push(valueFiltering);
  } else if (operator === 'not_nil') {
    const filterDefinition = schemaAttributesDefinition.getAttributeByName(headKey);
    let valueFiltering: any = { // classic filters: field exists
      exists: {
        field: headKey,
      },
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must: {
              wildcard: {
                [headKey]: '*',
              },
            },
          },
        };
      } else { // other filters: not_nil <-> (field exists) AND (field != empty string)
        valueFiltering = {
          bool: {
            must: [
              {
                exists: {
                  field: headKey,
                },
              },
              {
                bool: {
                  must_not: {
                    term: {
                      [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                    },
                  },
                },
              },
            ],
          },
        };
      }
    } else if (filterDefinition?.type === 'date') { // date filters: not_nil <-> (field exists) AND (date > epoch) AND (date < 5138)
      valueFiltering = {
        bool: {
          must: [
            {
              exists: {
                field: headKey,
              },
            },
            { range: { [headKey]: { gt: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { lt: '5138-11-16T09:46:40.000Z' } } },
          ],
        },
      };
    }
    valuesFiltering.push(valueFiltering);
  }
  // 03. Handle values according to the operator
  if (operator !== 'nil' && operator !== 'not_nil') {
    if (operator === 'within') {
      if (arrayKeys.length > 1) {
        throw UnsupportedError('Within filter must have only one field', { keys: arrayKeys });
      }
      if (values.length !== 2) {
        throw UnsupportedError('Within filter must have two values', { values });
      }
      valuesFiltering.push({ range: { [headKey]: { gte: values[0], lte: values[1] } } });
    } else {
      // case where we would like to build a terms query
      const isTermsQuery = (operator === 'eq' || operator === 'not_eq') && values.length > 0 && !values.includes('EXISTS')
        && arrayKeys.every((k) => (!k.includes('*') && (k.endsWith(ID_INTERNAL) || k.endsWith(ID_INFERRED))) || IDS_ATTRIBUTES.includes(k));
      if (isTermsQuery) {
        if (operator === 'eq') {
          for (let i = 0; i < arrayKeys.length; i += 1) {
            valuesFiltering.push({
              terms: { [`${arrayKeys[i]}.keyword`]: values },
            });
          }
        } else {
          valuesFiltering.push({
            bool: {
              must_not: arrayKeys.map((k) => ({
                terms: { [`${k}.keyword`]: values },
              })),
            },
          });
        }
      } else {
        for (let i = 0; i < values.length; i += 1) {
          if (values[i] === 'EXISTS') {
            if (arrayKeys.length > 1) {
              throw UnsupportedError('Filter must have only one field', { keys: arrayKeys });
            }
            if (operator === 'eq') {
              valuesFiltering.push({ exists: { field: headKey } });
            } else {
              noValuesFiltering.push({ exists: { field: headKey } });
            }
          } else if (operator === 'eq' || operator === 'not_eq') {
            const targets = operator === 'eq' ? valuesFiltering : noValuesFiltering;
            targets.push({
              multi_match: {
                fields: arrayKeys.map((k) => buildFieldForQuery(k)),
                query: values[i].toString(),
              },
            });
          } else if (operator === 'match') {
            valuesFiltering.push({
              multi_match: {
                fields: arrayKeys,
                query: values[i].toString(),
              },
            });
          } else if (operator === 'wildcard' || operator === 'not_wildcard') {
            const targets = operator === 'wildcard' ? valuesFiltering : noValuesFiltering;
            targets.push({
              query_string: {
                query: values[i] === '*' ? values[i] : `"${values[i].toString()}"`,
                fields: arrayKeys,
              },
            });
          } else if (operator === 'contains' || operator === 'not_contains') {
            const targets = operator === 'contains' ? valuesFiltering : noValuesFiltering;
            const val = specialElasticCharsEscape(values[i].toString());
            targets.push({
              query_string: {
                query: `*${val.replace(/\s/g, '\\ ')}*`,
                analyze_wildcard: true,
                fields: arrayKeys.map((k) => `${k}.keyword`),
              },
            });
          } else if (operator === 'starts_with' || operator === 'not_starts_with') {
            const targets = operator === 'starts_with' ? valuesFiltering : noValuesFiltering;
            const val = specialElasticCharsEscape(values[i].toString());
            targets.push({
              query_string: {
                query: `${val.replace(/\s/g, '\\ ')}*`,
                analyze_wildcard: true,
                fields: arrayKeys.map((k) => `${k}.keyword`),
              },
            });
          } else if (operator === 'ends_with' || operator === 'not_ends_with') {
            const targets = operator === 'ends_with' ? valuesFiltering : noValuesFiltering;
            const val = specialElasticCharsEscape(values[i].toString());
            targets.push({
              query_string: {
                query: `*${val.replace(/\s/g, '\\ ')}`,
                analyze_wildcard: true,
                fields: arrayKeys.map((k) => `${k}.keyword`),
              },
            });
          } else if (operator === 'script') {
            valuesFiltering.push({
              script: {
                script: values[i].toString(),
              },
            });
          } else if (operator === 'search') {
            const shouldSearch = elGenerateFieldTextSearchShould(values[i].toString(), arrayKeys);
            const bool = {
              bool: {
                should: shouldSearch,
                minimum_should_match: 1,
              },
            };
            valuesFiltering.push(bool);
          } else { // range operators
            if (arrayKeys.length > 1) {
              throw UnsupportedError('Range filter must have only one field', { keys: arrayKeys });
            }
            valuesFiltering.push({
              range: {
                [headKey]: { [operator]: values[i] },
              },
            });
          }
        }
      }
    }
  }
  // 04. Push the values
  if (valuesFiltering.length > 0) {
    return {
      bool: {
        should: valuesFiltering,
        minimum_should_match: localFilterMode === 'or' ? 1 : valuesFiltering.length,
      },
    };
  }
  if (noValuesFiltering.length > 0) {
    return {
      bool: {
        should: noValuesFiltering.map((o) => ({
          bool: {
            must_not: [o],
          },
        })),
        minimum_should_match: localFilterMode === 'or' ? 1 : noValuesFiltering.length,
      },
    };
  }
  throw UnsupportedError('Invalid filter configuration', validFilter);
};

const POST_FILTER_TAG_SEPARATOR = ';';
const buildSubQueryForFilterGroup = (
  context: AuthContext,
  user: AuthUser,
  inputFilters: FilterGroup,
): { subQuery: any; postFiltersTags: Set<string> } => {
  const { mode = 'and', filters = [], filterGroups = [] } = inputFilters;
  const localSubQueries: { subQuery: any; associatedTags: Set<string> }[] = [];
  const localPostFilterTags = new Set<string>();
  // Handle filterGroups
  for (let index = 0; index < filterGroups.length; index += 1) {
    const group = filterGroups[index];
    if (isFilterGroupNotEmpty(group)) {
      const { subQuery, postFiltersTags } = buildSubQueryForFilterGroup(context, user, group);
      if (subQuery) { // can be null
        localSubQueries.push({ subQuery, associatedTags: postFiltersTags });
      }
      postFiltersTags.forEach((t: string) => localPostFilterTags.add(t));
    }
  }
  // Handle filters
  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index] as FiltersWithNested & { postFilteringTag?: string };
    const isValidFilter = filter.values || (filter.nested && filter.nested?.length > 0);
    if (isValidFilter) {
      const localMustFilter = buildLocalMustFilter(filter);
      if (filter.postFilteringTag) {
        const associatedTag = filter.postFilteringTag;
        localPostFilterTags.add(associatedTag);
        const associatedTags = new Set<string>([associatedTag]);
        localSubQueries.push({ subQuery: localMustFilter, associatedTags });
      } else {
        localSubQueries.push({ subQuery: localMustFilter, associatedTags: new Set<string>() });
      }
    }
  }

  // Wrap every tagged subquery in a bool must with _name tag
  const localMustFilters = localSubQueries.map(({ subQuery, associatedTags }) => {
    const tagsToApply = mode === 'or' ? [...localPostFilterTags].filter((t: string) => !associatedTags.has(t)) : [];
    if (tagsToApply.length > 0) {
      return {
        bool: {
          must: [subQuery],
          ['_name']: tagsToApply.join(POST_FILTER_TAG_SEPARATOR),
        },
      };
    }
    return subQuery;
  });

  const currentSubQuery = localMustFilters.length > 0
    ? {
        bool: {
          should: localMustFilters,
          minimum_should_match: mode === 'or' ? 1 : localMustFilters.length,
        } }
    : null;
  return { subQuery: currentSubQuery, postFiltersTags: localPostFilterTags };
};

const getRuntimeEntities = async (context: AuthContext, user: AuthUser, entityType: string) => {
  const elements = await elPaginate<BasicStoreEntity>(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types: [entityType],
    first: MAX_RUNTIME_RESOLUTION_SIZE,
    bypassSizeLimit: true, // ensure that max runtime prevent on ES_MAX_PAGINATION
    connectionFormat: false,
  }) as BasicStoreEntity[];
  return R.mergeAll(elements.map((i) => ({ [i.internal_id]: i.name })));
};
export const RUNTIME_ATTRIBUTES: Record<string, any> = {
  observable_value: {
    field: 'observable_value.keyword',
    type: 'keyword',
    getSource: async () => runtimeFieldObservableValueScript(),
    getParams: async () => {},
  },
  createdBy: {
    field: 'createdBy.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_created-by.internal_id')) {
          def creatorId = doc['rel_created-by.internal_id.keyword'];
          if (creatorId.size() == 1) {
            def creatorName = params[creatorId[0]];
            emit(creatorName != null ? creatorName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_IDENTITY),
  },
  deletedBy: {
    field: 'deletedBy.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('creator_id')) {
          def creatorId = doc['creator_id.keyword'];
          if (creatorId.size() == 1) {
            def creatorName = params[creatorId[0]];
            emit(creatorName != null ? creatorName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
  },
  bornIn: {
    field: 'bornIn.keyword',
    type: 'keyword',
    getSource: async () => `
      if (doc.containsKey('rel_born-in.internal_id)) {
        def countryId = doc['rel_born-in.internal_id.keyword'];
        if (countryId.size() == 1) {
          def countryName = params[countryId[0]];
          emit(countryName != null ? creatorName : 'Unknown')
        } else {
          emit('Unknown')
        }
      } else {
        emit('Unknown')
      }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_LOCATION_COUNTRY),
  },
  ethnicity: {
    field: 'ethnicity.keyword',
    type: 'keyword',
    getSource: async () => `
      if (doc.containsKey('rel_of-ethnicity.internal_id)) {
        def countryId = doc['rel_of-ethnicity.internal_id.keyword'];
        if (countryId.size() == 1) {
          def countryName = params[countryId[0]];
          emit(countryName != null ? creatorName : 'Unknown')
        } else {
          emit('Unknown')
        }
      } else {
        emit('Unknown')
      }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_LOCATION_COUNTRY),
  },
  creator: {
    field: 'creator.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('creator_id')) {
          def creatorId = doc['creator_id.keyword'];
          if (creatorId.size() == 1) {
            def creatorName = params[creatorId[0]];
            emit(creatorName != null ? creatorName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
  },
  objectMarking: {
    field: 'objectMarking.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_object-marking.internal_id')) {
          def markingId = doc['rel_object-marking.internal_id.keyword'];
          if (markingId.size() >= 1) {
            def markingName = params[markingId[0]];
            emit(markingName != null ? markingName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeMarkings(context, user),
  },
  killChainPhases: {
    field: 'killChainPhases.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_kill-chain-phase.internal_id')) {
          def killChainPhaseId = doc['rel_kill-chain-phase.internal_id.keyword'];
          if (killChainPhaseId.size() >= 1) {
            def killChainPhaseName = params[killChainPhaseId[0]];
            emit(killChainPhaseName != null ? killChainPhaseName : 'Unknown')
          } else {
            emit('Unknown')
          }
        } else {
          emit('Unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeEntities(context, user, ENTITY_TYPE_KILL_CHAIN_PHASE),
  },
  objectAssignee: {
    field: 'objectAssignee.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_object-assignee.internal_id')) {
          def assigneeId = doc['rel_object-assignee.internal_id.keyword'];
          if (assigneeId.size() >= 1) {
            def assigneeName = params[assigneeId[0]].toLowerCase();
            emit(assigneeName != null ? assigneeName : 'unknown')
          } else {
              emit('unknown')
            }
        } else {
          emit('unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
  },
  participant: {
    field: 'objectParticipant.keyword',
    type: 'keyword',
    getSource: async () => `
        if (doc.containsKey('rel_object-participant.internal_id')) {
          def participantId = doc['rel_object-participant.internal_id.keyword'];
          if (participantId.size() >= 1) {
            def participantName = params[participantId[0]].toLowerCase();
            emit(participantName != null ? participantName : 'unknown')
          } else {
              emit('unknown')
            }
        } else {
          emit('unknown')
        }
    `,
    getParams: async (context: AuthContext, user: AuthUser) => getRuntimeUsers(context, user),
  },
};
type QueryBodyBuilderOpts = ProcessSearchArgs & BuildDraftFilterOpts & {
  ids?: string[];
  after?: string | null;
  orderBy?: any;
  orderMode?: 'asc' | 'desc' | null;
  pirId?: string | null;
  noSize?: boolean | null;
  noSort?: boolean | null;
  intervalInclude?: boolean | null;
  relCount?: boolean | null;
  first?: number | null;
  types?: string[] | null;
  search?: string | null;
  filters?: FilterGroup | null;
  noFiltersChecking?: boolean;
  noRegardingOfFilterIdsCheck?: boolean;
  startDate?: any;
  endDate?: any;
  dateAttribute?: string | null;
  includeAuthorities?: boolean | null;
};
const elQueryBodyBuilder = async (context: AuthContext, user: AuthUser, options: QueryBodyBuilderOpts) => {
  const {
    ids = [],
    after,
    orderBy = null,
    pirId = null,
    orderMode = 'asc',
    noSize = false,
    noSort = false,
    intervalInclude = false,
    relCount = false,
    first = ES_DEFAULT_PAGINATION,
    types = null,
    search = null,
    filters,
    noFiltersChecking,
    startDate = null,
    endDate = null,
    dateAttribute = null,
    includeAuthorities = false,
    noRegardingOfFilterIdsCheck = false,
  } = options;
  const elFindByIdsToMap = async (c: AuthContext, u: AuthUser, i: string[], o: any) => {
    return elFindByIds<BasicStoreObject>(c, u, i, { ...o, toMap: true }) as Promise<Record<string, BasicStoreObject>>;
  };
  const convertedFilters = await checkAndConvertFilters(context, user, filters, user.id, elFindByIdsToMap, { noFiltersChecking });
  const searchAfter = after ? cursorToOffset(after) : undefined;
  let ordering: any[] = [];
  // Handle marking restrictions
  const markingRestrictions = await buildDataRestrictions(context, user, { includeAuthorities });
  const accessMust = markingRestrictions.must;
  const accessMustNot = markingRestrictions.must_not;
  const mustFilters = [];
  // Add special keys to filters
  const specialFiltersContent: any = [];
  if (ids.length > 0 || startDate || endDate || (types !== null && types.length > 0)) {
    if (ids.length > 0) {
      specialFiltersContent.push({ key: IDS_FILTER, values: ids });
    }
    if (startDate) {
      specialFiltersContent.push({ key: dateAttribute || 'created_at', values: [startDate], operator: intervalInclude ? 'gte' : 'gt' });
    }
    if (endDate) {
      specialFiltersContent.push({ key: dateAttribute || 'created_at', values: [endDate], operator: intervalInclude ? 'lte' : 'lt' });
    }
    if (types !== null && types.length > 0) {
      specialFiltersContent.push({ key: TYPE_FILTER, values: R.flatten(types) });
    }
  }
  const completeFilters = specialFiltersContent.length > 0 ? {
    mode: FilterMode.And,
    filters: specialFiltersContent,
    filterGroups: isFilterGroupNotEmpty(convertedFilters) ? [convertedFilters as FilterGroup] : [],
  } : convertedFilters;
  // Handle filters
  if (completeFilters && isFilterGroupNotEmpty(completeFilters)) {
    const finalFilters = await completeSpecialFilterKeys(context, user, completeFilters, { noRegardingOfFilterIdsCheck });
    const { subQuery: filtersSubQuery } = buildSubQueryForFilterGroup(context, user, finalFilters);
    if (filtersSubQuery) {
      mustFilters.push(filtersSubQuery);
    }
  }
  // Handle search
  const orderConfiguration = isEmptyField(orderBy) ? [] : orderBy;
  const orderCriterion = Array.isArray(orderConfiguration) ? orderConfiguration : [orderConfiguration];
  let scoreSearchOrder = orderMode;
  if (search !== null && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search, options);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    mustFilters.push(bool);
    // When using a search, force a score ordering if nothing specified
    if (orderCriterion.length === 0) {
      orderCriterion.unshift('_score');
      scoreSearchOrder = 'desc';
    }
  }
  // Handle orders
  const runtimeMappings: any = {};
  if (isNotEmptyField(orderCriterion)) {
    for (let index = 0; index < orderCriterion.length; index += 1) {
      const orderCriteria = orderCriterion[index];
      if (orderCriteria === '_score') {
        ordering = R.append({ [orderCriteria]: scoreSearchOrder }, ordering);
      } else {
        const sortingForCriteria = await buildElasticSortingForAttributeCriteria(context, user, orderCriteria, orderMode, pirId);
        ordering = R.append(sortingForCriteria, ordering);
      }
    }
    // Add standard_id if not specify to ensure ordering uniqueness
    if (!orderCriterion.includes('standard_id')) {
      ordering.push({ 'standard_id.keyword': 'asc' });
    }
    // Build runtime mappings
    const runtime = RUNTIME_ATTRIBUTES[orderBy as string];
    if (isNotEmptyField(runtime)) {
      const source = await runtime.getSource();
      const params = await runtime.getParams(context, user);
      runtimeMappings[runtime.field] = {
        type: runtime.type,
        script: { source, params },
      };
    }
  } else { // If not ordering criteria, order by standard_id
    ordering.push({ 'standard_id.keyword': 'asc' });
  }
  // Handle draft
  const draftMust = buildDraftFilter(context, user, options);
  // Build query
  const body: any = {
    query: {
      bool: {
        must: [...accessMust, ...mustFilters, ...draftMust],
        must_not: accessMustNot,
      },
    },
  };
  if (relCount) {
    body.script_fields = {
      script_field_denormalization_count: REL_COUNT_SCRIPT_FIELD,
    };
  }
  if (!noSize) {
    body.size = first;
  }
  if (!noSort) {
    body.sort = ordering;
  }
  // Add extra configuration
  if (isNotEmptyField(runtimeMappings)) {
    const isRuntimeSortFeatureEnable = isRuntimeSortEnable();
    if (!isRuntimeSortFeatureEnable) {
      throw UnsupportedError('Runtime mapping is only possible with elastic >=7.12', { order: orderBy });
    }
    body.runtime_mappings = runtimeMappings;
  }
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  return body;
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

const tagFiltersForPostFiltering = (filters: FilterGroup | undefined | null) => {
  const taggedFilters: (Filter & { postFilteringTag: string })[] = filters
    ? extractFiltersFromGroup(filters, [INSTANCE_REGARDING_OF, INSTANCE_DYNAMIC_REGARDING_OF])
        .filter((filter) => isEmptyField(filter.operator) || filter.operator === 'eq')
        .map((filter, i) => {
          const taggedFilter = filter as Filter & { postFilteringTag: string };
          taggedFilter.postFilteringTag = `${i}`;
          return taggedFilter;
        })
    : [];

  if (taggedFilters) {
    return async <T extends BasicStoreBase> (context: AuthContext, user: AuthUser, elementsIds: string[]) => {
      const postFilters: { tag: string; postFilter: (element: T) => boolean }[] = [];
      for (let i = 0; i < taggedFilters.length; i++) {
        const taggedFilter = taggedFilters[i];
        postFilters.push({
          tag: taggedFilter.postFilteringTag,
          postFilter: await buildRegardingOfFilter<T>(context, user, elementsIds, taggedFilter),
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
  const createPostFilter = tagFiltersForPostFiltering(options.filters);
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
    if (!noRegardingOfFilterIdsCheck && finalElements.length > 0 && createPostFilter) {
      // Since filters contains filters requiring post filtering (regardingOf, dynamicRegardingOf), a post-security filtering is needed
      const postFilter = await createPostFilter<T>(context, user, elements.map(({ id }) => id));
      finalElements = elements.filter((element, i) => {
        const dataHit = hits[i];
        const tagsToIgnoreSet = new Set<string>((dataHit.matched_queries ?? []).flatMap((matchedQuery: string) => matchedQuery.split(POST_FILTER_TAG_SEPARATOR)));
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
    throw DatabaseError('Fail to execute engine pagination', { cause: err, root_cause, query, queryArguments: options });
  }
};
type RepaginateOpts<T extends BasicStoreBase> = PaginateOpts & {
  maxSize?: number;
  logForMigration?: boolean;
  callback?: (elements: T[], globalCount: number) => Promise<boolean | undefined>;
};
const elRepaginate = async <T extends BasicStoreBase> (
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
        listing.push(...elements);
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

export const elConnection = async <T extends BasicStoreBase> (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | null | undefined,
  opts: RepaginateOpts<T> = {},
) => {
  const { elements, totalCount } = await elRepaginate<T>(context, user, indexName, true, opts);
  return buildPaginationFromEdges<T>(opts.first, opts.after, elements as BasicNodeEdge<T>[], totalCount);
};

export const elList = async <T extends BasicStoreBase> (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined | null,
  opts: RepaginateOpts<T> = {},
) => {
  const data = await elRepaginate<T>(context, user, indexName, false, opts);
  return data.elements as T[];
};

export const elLoadBy = async <T extends BasicStoreBase> (
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
type HistogramCountOpts = QueryBodyBuilderOpts & {
  interval?: string;
  field?: string;
};
export const elHistogramCount = async (
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined,
  options: HistogramCountOpts = {},
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
  body.aggs = {
    count_over_time: {
      date_histogram: {
        field,
        calendar_interval: interval,
        // time_zone: tzStart,
        format: dateFormat,
        keyed: true,
      },
      aggs: {
        weight: {
          sum: {
            field: 'i_inference_weight',
            missing: 1,
          },
        },
      },
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
    return R.map((b) => ({ date: R.head(b), value: R.last(b).weight.value }), dataToPairs);
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
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  body.size = 0;
  body.aggs = {
    genres: {
      terms: {
        field: buildFieldForQuery(field),
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
type AggregationRelationsCount = {
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
                    aggs: {
                      weight: {
                        sum: {
                          field: 'i_inference_weight',
                          missing: 1,
                        },
                      },
                    },
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
        aggs: {
          weight: {
            sum: {
              field: 'i_inference_weight',
              missing: 1,
            },
          },
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
          return buckets.map((b: any) => ({ label: b.key, value: b.parent.weight.value }));
        }
        // entity_type
        const filteredBuckets = buckets.filter((b: any) => !(isAbstract(pascalize(b.key)) || isAbstract(b.key)));
        return R.map((b) => ({ label: pascalize(b.key), value: b.parent.weight.value }), filteredBuckets);
      }
      const { buckets } = data.aggregations.genres;
      return buckets.map((b: any) => {
        let label = b.key;
        if (typeof label === 'number') {
          label = b.key_as_string;
        } else if (!isIdFields) {
          label = pascalize(b.key);
        }
        return { label, value: b.weight.value };
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
    throw DatabaseError('Aggregations computing list fail', { cause: err, query });
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

const buildRegardingOfFilter = async <T extends BasicStoreBase> (
  context: AuthContext,
  user: AuthUser,
  elementIds: string[],
  filter: Filter,
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
  const relationships = await elList<BasicStoreRelation>(context, user, relationshipIndices, paginateArgs);
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
  must.push(...markingRestrictions.must);
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

export const elBulk = async (args: any) => {
  return elRawBulk(args).then((data) => {
    if (data.errors) {
      const errors = data.items.map((i: any) => i.index?.error || i.update?.error).filter((f: any) => f !== undefined);
      if (errors.filter((err: any) => err.type !== DOCUMENT_MISSING_EXCEPTION).length > 0) {
        throw DatabaseError('Bulk indexing fail', { errors });
      }
    }
    return data;
  });
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
  indexName: string,
  documentId: string,
  documentBody: any,
  retry = ES_RETRY_ON_CONFLICT,
) => {
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  const updateRequest = {
    id: documentId,
    index: indexName,
    retry_on_conflict: retry,
    timeout: BULK_TIMEOUT,
    refresh: true,
    body: documentBody,
  };
  if (engine instanceof ElkClient) {
    return engine.update(updateRequest).catch((err: any) => {
      throw DatabaseError('Update indexing fail', { cause: err, documentId, entityType, ...extendedErrors({ documentBody }) });
    });
  }
  return engine.update(updateRequest).catch((err: any) => {
    throw DatabaseError('Update indexing fail', { cause: err, documentId, entityType, ...extendedErrors({ documentBody }) });
  });
};
export const elReplace = async (
  indexName: string,
  documentId: string,
  documentBody: any,
) => {
  const doc = R.dissoc('_index', documentBody.doc);
  const entries = Object.entries(doc);
  const rawSources = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    // We clean the attribute only if data is null or undefined
    if (val === undefined || val === null) {
      rawSources.push(`ctx._source.remove('${key}')`);
    } else {
      rawSources.push(`ctx._source['${key}'] = params['${key}']`);
    }
  }
  const source = R.join(';', rawSources);
  return elUpdate(indexName, documentId, {
    script: { source, params: doc },
  });
};
export const elDelete = (indexName: string, documentId: string) => {
  const deleteRequest = {
    id: documentId,
    index: indexName,
    timeout: BULK_TIMEOUT,
    refresh: true,
  };
  if (engine instanceof ElkClient) {
    return engine.delete(deleteRequest).catch((err: any) => {
      throw DatabaseError('Deleting indexing fail', { cause: err, documentId });
    });
  }
  return engine.delete(deleteRequest).catch((err: any) => {
    throw DatabaseError('Deleting indexing fail', { cause: err, documentId });
  });
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
    elements.unshift(...preparedElements);
    return true;
  };
  const finalOpts: RepaginateOpts<BasicStoreRelation> = { ...opts, filters, callback, types: [ABSTRACT_BASIC_RELATIONSHIP] };
  await elList<BasicStoreRelation>(context, user, READ_RELATIONSHIPS_INDICES, finalOpts);
  // If relations find, need to recurs to find relations to relations
  if (foundRelations.length > 0) {
    const groups = R.splitEvery(MAX_BULK_OPERATIONS, foundRelations);
    const concurrentFetch = (gIds: string[]) => getRelatedRelations(context, user, gIds, elements, level + 1, cache, opts);
    await BluePromise.map(groups, concurrentFetch, { concurrency: ES_MAX_CONCURRENCY });
  }
};
export const getRelationsToRemove = async <T extends BasicStoreBase> (
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
export const elDeleteInstances = async <T extends BasicStoreBase> (
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
      await elBulk({ refresh: forceRefresh, timeout: BULK_TIMEOUT, body: bodyDelete });
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
        await elBulk({ refresh: forceRefresh, timeout: BULK_TIMEOUT, body: bodyUpdate });
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
  if (engine instanceof ElkClient) {
    return engine.reindex(reindexParams).catch((err) => {
      throw DatabaseError(`Reindexing fail from ${sourceIndex} to ${destIndex}`, { cause: err, body: reindexParams.body });
    });
  }
  return engine.reindex(reindexParams).catch((err) => {
    throw DatabaseError(`Reindexing fail from ${sourceIndex} to ${destIndex}`, { cause: err, body: reindexParams.body });
  });
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
      source: `
        if (ctx._source.containsKey('draft_ids')) { 
          for (int i=ctx._source['draft_ids'].length-1; i>=0; i--) {
            if (!params.allDraftIds.contains(ctx._source['draft_ids'][i])) {
              ctx._source['draft_ids'].remove(i);
            }
          }
          ctx._source['draft_ids'].add('${draftContext}'); 
        } 
        else 
          {ctx._source.draft_ids = ['${draftContext}']}
      `,
      params: { allDraftIds },
    },
  };
  await elUpdate(element._index, element.internal_id, addDraftIdScript);

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
      const resolvedFrom = (from ?? await elLoadById(context, user, fromId, { includeDeletedInDraft: true })) as BasicStoreBase;
      const draftFrom = await loadDraftElement(context, user, resolvedFrom);
      relElement.from = draftFrom;
      relElement.fromId = draftFrom.id;
      const resolvedTo = (to ?? await elLoadById(context, user, toId, { includeDeletedInDraft: true })) as BasicStoreBase;
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
  const deleteDraftCreatedElementsPromise = elDeleteInstances(draftCreatedElements);
  const updateDraftElementsPromise = draftNonCreatedElements.map((draftE) => {
    // TODO we might want to apply the reverse patch to draft updated elements
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_DELETE } };
    return elReplace(draftE._index, draftE._id, { doc: newDraftChange });
  });
  const copiedLiveElements = await Promise.all(copyLiveElementsPromise);
  const allDraftElements = [...copiedLiveElements, ...draftCreatedElements, ...draftNonCreatedElements];

  // 02. Remove all related relations and elements: delete instances created in draft, mark as deletionLink for others
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, allDraftElements, { includeDeletedInDraft: true });
  const liveRelations = relations.filter((f) => !isDraftIndex(f._index));
  const draftCreatedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change?.draft_operation === DRAFT_OPERATION_CREATE);
  const draftNonCreatedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change?.draft_operation !== DRAFT_OPERATION_CREATE);

  const deleteDraftCreatedRelationsPromise = elDeleteInstances(draftCreatedRelations);
  const copyLiveRelationsPromise = liveRelations.map((e) => copyLiveElementToDraft(context, user, e, DRAFT_OPERATION_DELETE_LINKED));
  const updateDraftRelationsPromise = draftNonCreatedRelations.map((draftR) => {
    // TODO we might want to apply the reverse patch to draft updated elements
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_DELETE_LINKED } };
    return elReplace(draftR._index, draftR._id, { doc: newDraftChange });
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
  if (draftContext && elements.some((e) => !isDraftSupportedEntity(e))) throw UnsupportedError('Cannot index unsupported element in draft context');
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
        await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body });
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
      const params: any = { updated_at: now() };
      const sources = targetsElements.map((t) => {
        const field = buildRefRelationKey(t.relation, t.field);
        let script = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
        if (isStixRefUnidirectionalRelationship(t.relation)) {
          // don't try to add unidirectional ref rel if already present (issue#7535)
          script += `for(refId in params['${field}']) { 
          if(!ctx._source['${field}'].contains(refId)) { ctx._source['${field}'].add(refId) }} `;
        } else {
          script += `ctx._source['${field}'].addAll(params['${field}']);`;
        }
        const fromSide = t.elements.find((e: any) => e.side === 'from');
        const toSide = t.elements.find((e: any) => e.side === 'to');
        if (fromSide && isStixRefRelationship(t.relation)) {
          // updated_at and modified only updated for ref relationships
          if (isUpdatedAtObject(fromSide.type)) {
            script += 'ctx._source[\'updated_at\'] = params.updated_at;';
          }
          if (isModifiedObject(fromSide.type)) {
            script += 'ctx._source[\'modified\'] = params.updated_at;';
          }
        }
        // freshness of an entity updated for any relationship
        if ((fromSide && isUpdatedAtObject(fromSide.type)) || (toSide && isUpdatedAtObject(toSide.type))) {
          script += 'ctx._source[\'refreshed_at\'] = params.updated_at;';
        }
        // Add Pir information for in-pir relationships
        if (t.relation === RELATION_IN_PIR) {
          // remove pir_information concerning the pir and add the new pir_information
          script += `
            if (ctx._source.containsKey('pir_information') && ctx._source['pir_information'] != null) {
              ctx._source['pir_information'].removeIf(item -> params.pir_ids.contains(item.pir_id));
              ctx._source['pir_information'].addAll(params.new_pir_information);
            } else { ctx._source['pir_information'] = params.new_pir_information; }
          `;
        }
        return script;
      });
      // Concat sources scripts by adding a ';' between each script to close each final script line
      const source = sources.length > 1 ? R.join(' ', sources) : `${R.head(sources)}`;
      // Construct params
      for (let index = 0; index < targetsElements.length; index += 1) {
        const targetElement = targetsElements[index];
        params[buildRefRelationKey(targetElement.relation, targetElement.field)] = targetElement.elements.map((e: any) => e.id);
      }
      // Add new_pir_information params
      const pirElements = targetsElements.filter((e) => e.relation === RELATION_IN_PIR);
      for (let index = 0; index < pirElements.length; index += 1) {
        const pirElement = pirElements[index];
        params.new_pir_information = pirElement.elements
          .map((e: any) => ({
            pir_id: e.id,
            pir_score: e.pir_score,
            last_pir_score_date: params.updated_at,
          }));
        params.pir_ids = pirElement.elements.map((e: any) => e.id);
      }
      return { ...entity, id: entityId, data: { script: { source, params } } };
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
          const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
          await Promise.all([bulkPromise]);
        }
      }
    }
    return transformedElements.length;
  };
  return telemetry(context, user, `INSERT ${indexingType}`, {
    [SEMATTRS_DB_NAME]: 'search_engine',
    [SEMATTRS_DB_OPERATION]: 'insert',
  }, elIndexElementsFn);
};

export const elUpdateRelationConnections = async (elements: any[]) => {
  if (elements.length > 0) {
    const source = 'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); '
      + 'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
    const bodyUpdate = elements.flatMap((doc) => [
      { update: { _index: doc._index, _id: doc._id ?? doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
      { script: { source, params: { id: doc.toReplace, changes: doc.data } } },
    ]);
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    await Promise.all([bulkPromise]);
  }
};
export const elUpdateEntityConnections = async (elements: any[]) => {
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
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
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
  await elDeleteInstances(relations, opts);
  // 03/ Remove all elements
  logApp.debug('[SEARCH] Deleting elements', { size: elements.length });
  await elDeleteInstances(elements, opts);
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
  const replacePromise = elReplace(instanceToUse._index, instanceToUse._id ?? instanceToUse.internal_id, { doc: dataToReplace });
  // If entity with a name, must update connections
  let connectionPromise = Promise.resolve();
  if (esData.name && isStixObject(instanceToUse.entity_type)) {
    connectionPromise = elUpdateConnectionsOfElement(instance.internal_id, { name: extractEntityRepresentativeName(esData) });
  }
  return Promise.all([replacePromise, connectionPromise]);
};

export const getStats = (indices = READ_PLATFORM_INDICES) => {
  if (engine instanceof ElkClient) {
    return engine.indices
      .stats({ index: indices }) //
      .then((result) => oebp(result)._all.primaries);
  }
  return engine.indices
    .stats({ index: indices }) //
    .then((result) => oebp(result)._all.primaries);
};

export const isEngineAlive = async () => {
  const context = executionContext('healthcheck');
  const options = { types: [ENTITY_TYPE_MIGRATION_STATUS], connectionFormat: false };
  const migrations = await elPaginate(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, options) as BasicStoreBase[];
  if (migrations.length === 0) {
    throw DatabaseError('Invalid database content, missing migration schema');
  }
};
