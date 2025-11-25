/* eslint-disable no-underscore-dangle */
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
/* eslint-disable import/no-unresolved */
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
  WRITE_PLATFORM_INDICES
} from './utils';
import conf, { booleanConf, extendedErrors, loadCert, logApp, logMigration } from '../config/conf';
import {
  ComplexSearchError,
  ConfigurationError,
  DatabaseError,
  EngineShardsError,
  ForbiddenAccess,
  FunctionalError,
  LockTimeoutError,
  ResourceNotFoundError,
  TYPE_LOCK_ERROR,
  UnsupportedError
} from '../config/errors';
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
  STIX_REF_RELATIONSHIP_TYPES
} from '../schema/stixRefRelationship';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_OBJECT,
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
  RULE_PREFIX
} from '../schema/general';
import { isModifiedObject, isUpdatedAtObject, } from '../schema/fieldDataAdapter';
import { generateInternalType, getParentTypes, keepMostRestrictiveTypes } from '../schema/schemaUtils';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_ALIASES,
  ATTRIBUTE_ALIASES_OPENCTI,
  ATTRIBUTE_DESCRIPTION,
  ATTRIBUTE_DESCRIPTION_OPENCTI,
  ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  isStixDomainObject,
  STIX_ORGANIZATIONS_RESTRICTED,
  STIX_ORGANIZATIONS_UNRESTRICTED
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
  isUserHasCapability,
  MEMBER_ACCESS_ALL,
  PIRAPI,
  SYSTEM_USER,
  userFilterStoreElements
} from '../utils/access';
import { isSingleRelationsRef, } from '../schema/stixEmbeddedRelationship';
import { now, runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_MARKING_DEFINITION, isStixMetaObject } from '../schema/stixMetaObject';
import { getEntitiesListFromCache, getEntityFromCache } from './cache';
import { refang } from '../utils/refang';
import { ENTITY_TYPE_MIGRATION_STATUS, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS, ENTITY_TYPE_USER, isInternalObject } from '../schema/internalObject';
import { meterManager, telemetry } from '../config/tracing';
import {
  isBooleanAttribute,
  isDateAttribute,
  isDateNumericOrBooleanAttribute,
  isNumericAttribute,
  isObjectAttribute,
  isObjectFlatAttribute,
  schemaAttributesDefinition,
  validateDataBeforeIndexing
} from '../schema/schema-attributes';
import { convertTypeToStixType } from './stix-2-1-converter';
import { extractEntityRepresentativeName, extractRepresentative } from './entity-representative';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { addFilter, checkAndConvertFilters, extractFiltersFromGroup, isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import {
  ALIAS_FILTER,
  BULK_SEARCH_KEYWORDS_FILTER,
  BULK_SEARCH_KEYWORDS_FILTER_KEYS,
  COMPUTED_RELIABILITY_FILTER,
  ID_FILTER,
  IDS_FILTER,
  INSTANCE_DYNAMIC_REGARDING_OF,
  INSTANCE_REGARDING_OF,
  INSTANCE_REGARDING_OF_DIRECTION_FORCED,
  INSTANCE_REGARDING_OF_DIRECTION_REVERSE,
  INSTANCE_RELATION_FILTER,
  INSTANCE_RELATION_TYPES_FILTER,
  IS_INFERRED_FILTER,
  isComplexConversionFilterKey,
  LAST_PIR_SCORE_DATE_FILTER_PREFIX,
  PIR_SCORE_FILTER_PREFIX,
  RELATION_DYNAMIC_FILTER,
  RELATION_DYNAMIC_FROM_FILTER,
  RELATION_DYNAMIC_TO_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_ROLE_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_TO_FILTER,
  RELATION_TO_ROLE_FILTER,
  RELATION_TO_SIGHTING_FILTER,
  RELATION_TO_TYPES_FILTER,
  RELATION_TYPE_FILTER,
  SOURCE_RELIABILITY_FILTER,
  TYPE_FILTER,
  USER_SERVICE_ACCOUNT_FILTER,
  WORKFLOW_FILTER,
  X_OPENCTI_WORKFLOW_ID
} from '../utils/filtering/filtering-constants';
import { FilterMode, FilterOperator } from '../generated/graphql';
import {
  authorizedMembers,
  baseType,
  booleanMapping,
  dateMapping,
  entityType as entityTypeAttribute,
  iAliasedIds,
  id as idAttribute,
  internalId,
  longStringFormats,
  numericMapping,
  shortMapping,
  shortStringFormats,
  standardId,
  textMapping,
  xOpenctiStixIds
} from '../schema/attribute-definition';
import { connections as connectionsAttribute } from '../modules/attributes/basicRelationship-registrationAttributes';
import { schemaTypesDefinition } from '../schema/schema-types';
import { INTERNAL_RELATIONSHIPS, isInternalRelationship, RELATION_IN_PIR, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { rule_definitions } from '../rules/rules-definition';
import { buildElasticSortingForAttributeCriteria } from '../utils/sorting';
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
import { RELATION_SAMPLE } from '../modules/malwareAnalysis/malwareAnalysis-types';
import { getPirWithAccessCheck } from '../modules/pir/pir-checkPirAccess';
import { asyncFilter, asyncMap, uniqAsyncMap } from '../utils/data-processing';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { isMetricsName } from '../modules/metrics/metrics-utils';
import { doYield } from '../utils/eventloop-utils';
import { RELATION_COVERED } from '../modules/securityCoverage/securityCoverage-types';

const ELK_ENGINE = 'elk';
const OPENSEARCH_ENGINE = 'opensearch';
export const ES_MAX_CONCURRENCY = conf.get('elasticsearch:max_concurrency');
export const ES_DEFAULT_WILDCARD_PREFIX = booleanConf('elasticsearch:search_wildcard_prefix', false);
export const ES_DEFAULT_FUZZY = booleanConf('elasticsearch:search_fuzzy', false);
export const ES_INIT_MAPPING_MIGRATION = conf.get('elasticsearch:internal_init_mapping_migration') || 'off'; // off / old / standard
export const ES_IS_OLD_MAPPING = ES_INIT_MAPPING_MIGRATION === 'old';
export const ES_IS_INIT_MIGRATION = ES_INIT_MAPPING_MIGRATION === 'standard' || ES_IS_OLD_MAPPING;
export const ES_MINIMUM_FIXED_PAGINATION = 20; // When really low pagination is better by default
export const ES_DEFAULT_PAGINATION = conf.get('elasticsearch:default_pagination_result') || 500;
export const ES_MAX_PAGINATION = conf.get('elasticsearch:max_pagination_result') || 5000;
export const MAX_BULK_OPERATIONS = conf.get('elasticsearch:max_bulk_operations') || 5000;
export const MAX_RUNTIME_RESOLUTION_SIZE = conf.get('elasticsearch:max_runtime_resolutions') || 5000;
export const MAX_RELATED_CONTAINER_RESOLUTION = conf.get('elasticsearch:max_container_resolutions') || 1000;
export const MAX_RELATED_CONTAINER_OBJECT_RESOLUTION = conf.get('elasticsearch:max_container_object_resolutions') || 100000;
export const ES_INDEX_PATTERN_SUFFIX = conf.get('elasticsearch:index_creation_pattern');
const ES_MAX_RESULT_WINDOW = conf.get('elasticsearch:max_result_window') || 100000;
const ES_INDEX_SHARD_NUMBER = conf.get('elasticsearch:number_of_shards');
const ES_INDEX_REPLICA_NUMBER = conf.get('elasticsearch:number_of_replicas');

const ES_PRIMARY_SHARD_SIZE = conf.get('elasticsearch:max_primary_shard_size') || '50gb';
const ES_MAX_DOCS = conf.get('elasticsearch:max_docs') || 75000000;

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
export const isSpecialNonImpactedCases = (relationshipType, fromType, toType, side) => {
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
export const isImpactedTypeAndSide = (type, fromType, toType, side) => {
  if (isSpecialNonImpactedCases(type, fromType, toType, side)) {
    return false;
  }
  return !UNIMPACTED_ENTITIES_ROLE.includes(`${type}_${side}`);
};
export const isImpactedRole = (type, fromType, toType, role) => {
  if (isSpecialNonImpactedCases(type, fromType, toType, role.split('_').at(1))) {
    return false;
  }
  return !UNIMPACTED_ENTITIES_ROLE.includes(role);
};

let engine;
let isRuntimeSortingEnable = false;
let attachmentProcessorEnabled = false;

export const isAttachmentProcessorEnabled = () => {
  return attachmentProcessorEnabled === true;
};

// The OpenSearch/ELK Body Parser (oebp)
// Starting ELK8+, response are no longer inside a body envelop
// Query wrapping is still accepted in ELK8
const oebp = (queryResult) => {
  if (engine instanceof ElkClient) {
    return queryResult;
  }
  return queryResult.body;
};

// Look for the engine version with OpenSearch client
export const searchEngineVersion = async () => {
  const searchInfo = await engine.info()
    .then((info) => oebp(info).version)
    .catch(
      /* v8 ignore next */ (e) => {
        throw ConfigurationError('Search engine seems down', { cause: e });
      }
    );
  const searchPlatform = searchInfo.distribution || ELK_ENGINE; // openSearch or elasticSearch
  const searchVersion = searchInfo.number;
  return { platform: searchPlatform, version: searchVersion };
};

export const isEngineAlive = async () => {
  const context = executionContext('healthcheck');
  const options = { types: [ENTITY_TYPE_MIGRATION_STATUS], connectionFormat: false };
  const migrations = await elPaginate(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, options);
  if (migrations.length === 0) {
    throw DatabaseError('Invalid database content, missing migration schema');
  }
};

export const searchEngineInit = async () => {
  // Build the engine configuration
  const ca = conf.get('elasticsearch:ssl:ca')
    ? loadCert(conf.get('elasticsearch:ssl:ca'))
    : conf.get('elasticsearch:ssl:ca_plain') || null;
  const region = conf.get('opensearch:region');
  const searchConfiguration = {
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
    ...(region ? AwsSigv4Signer({
      region,
      service: conf.get('opensearch:service') || 'es',
      getCredentials: () => {
        const credentialsProvider = defaultProvider({
          roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity({ region })
        });
        return credentialsProvider();
      }
    }) : {})
  };
  searchConfiguration.auth = await enrichWithRemoteCredentials('elasticsearch', searchConfiguration.auth);
  // Select the correct engine
  let engineVersion;
  let enginePlatform;
  const engineSelector = conf.get('elasticsearch:engine_selector') || 'auto';
  const engineCheck = booleanConf('elasticsearch:engine_check', true);
  const elasticSearchClient = new ElkClient(searchConfiguration);
  const openSearchClient = new OpenClient(searchConfiguration);
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
export const isRuntimeSortEnable = () => isRuntimeSortingEnable;

export const elRawSearch = (context, user, types, query) => {
  // Add signal to prevent unwanted warning
  // Waiting for https://github.com/elastic/elastic-transport-js/issues/63
  const elRawSearchFn = async () => engine.search(query, { signal: new AbortController().signal }).then((r) => {
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

export const elRawGet = (args) => engine.get(args).then((r) => oebp(r));
export const elRawIndex = (args) => engine.index(args).then((r) => oebp(r));
export const elRawDelete = (args) => engine.delete(args).then((r) => oebp(r));
export const elRawDeleteByQuery = (query) => engine.deleteByQuery(query).then((r) => oebp(r));
export const elRawBulk = (args) => engine.bulk(args).then((r) => oebp(r));
export const elRawUpdateByQuery = (query) => engine.updateByQuery(query).then((r) => oebp(r));
export const elRawReindexByQuery = (query) => engine.reindex(query).then((r) => oebp(r));

const elOperationForMigration = (operation) => {
  const elGetTask = (taskId) => engine.tasks.get({ task_id: taskId }).then((r) => oebp(r));

  return async (message, index, body) => {
    logMigration.info(`${message} > started`);
    // Execute the update by query in async mode
    const queryAsync = await operation({
      ...(index ? { index } : {}),
      refresh: true,
      wait_for_completion: false,
      body
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

export const buildDataRestrictions = async (context, user, opts = {}) => {
  const must = [];
  // eslint-disable-next-line camelcase
  const must_not = [];
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
      const allMarkings = await getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
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
          [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: mustNotHaveOneOf
        }
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
    const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
    // We want to exclude a set of entities from organization restrictions while forcing restrictions for another set of entities
    const excludedEntityMatches = {
      bool: {
        must: [
          {
            bool: { must_not: [{ terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_RESTRICTED } }] }
          },
          {
            bool: {
              should: [
                { terms: { 'parent_types.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } },
                { terms: { 'entity_type.keyword': STIX_ORGANIZATIONS_UNRESTRICTED } }
              ],
              minimum_should_match: 1
            }
          }
        ]
      }
    };
    if (settings.platform_organization) {
      if (context.user_inside_platform_organization) {
        // Data are visible independently of the organizations
        // Nothing to restrict.
      } else {
        // Data with Empty granted_refs are not visible
        // Data with granted_refs users that participate to at least one
        const should = [excludedEntityMatches];
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

const buildUserMemberAccessFilter = (user, opts) => {
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
                source: `doc['${authorizedMembers.name}.groups_restriction_ids.keyword'].length`
              }
            }
          }
        }
      ]
    }
  };
  const authorizedFilters = [
    { bool: { must: [authorizedMembersIdsTerms, groupRestrictionCondition] } }
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
        bool: { should: bypassAuthorizedMembers ? [] : authorizedFilters }
      }
    }
  };
  shouldConditions.push(nestedQuery);
  return [{ bool: { should: shouldConditions } }];
};

export const elIndexExists = async (indexName) => {
  const existIndex = await engine.indices.exists({ index: indexName });
  return existIndex === true || oebp(existIndex) === true || existIndex.body === true;
};
export const elIndexGetAlias = async (indexName) => {
  const indexAlias = await engine.indices.getAlias({ index: indexName });
  return oebp(indexAlias);
};
export const elPlatformIndices = async () => {
  const listIndices = await engine.cat.indices({ index: `${ES_INDEX_PREFIX}*`, format: 'JSON' });
  return oebp(listIndices);
};
export const elPlatformMapping = async (index) => {
  const mapping = await engine.indices.getMapping({ index });
  return oebp(mapping)[index].mappings.properties;
};
export const elIndexSetting = async (index) => {
  const dataIndexSettings = await engine.indices.getSettings({ index });
  const { settings } = oebp(dataIndexSettings)[index];
  const rollover_alias = engine instanceof ElkClient ? settings.index.lifecycle?.rollover_alias
    : settings.index.plugins?.index_state_management?.rollover_alias;
  return { settings, rollover_alias };
};
export const elPlatformTemplates = async () => {
  const listTemplates = await engine.cat.templates({ name: `${ES_INDEX_PREFIX}*`, format: 'JSON' });
  return oebp(listTemplates);
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
                  max_docs: ES_MAX_DOCS
                },
                set_priority: {
                  priority: 100
                }
              }
            }
          }
        }
      }
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
                    min_doc_count: ES_MAX_DOCS
                  }
                }],
              transitions: []
            }],
          ism_template: {
            index_patterns: [`${ES_INDEX_PREFIX}*`],
            priority: 100
          }
        }
      }
    }).catch((e) => {
      throw DatabaseError('Creating lifecycle policy fail', { cause: e });
    });
  }
};
const updateCoreSettings = async () => {
  await engine.cluster.putComponentTemplate({
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
                type: 'custom',
                filter: ['lowercase', 'asciifolding'],
              },
            },
          },
        },
      },
    },
  }).catch((e) => {
    throw DatabaseError('Creating component template fail', { cause: e });
  });
};

// Engine mapping generation on attributes definition
const attributeMappingGenerator = (entityAttribute) => {
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
    const properties = {};
    for (let i = 0; i < entityAttribute.mappings.length; i += 1) {
      const mapping = entityAttribute.mappings[i];
      properties[mapping.name] = attributeMappingGenerator(mapping);
    }
    const config = { dynamic: 'strict', properties };
    // Add nested option if needed
    if (entityAttribute.format === 'nested') {
      config.type = 'nested';
    }
    return config;
  }
  throw UnsupportedError('Cant generated mapping', { type: entityAttribute.type });
};
const ruleMappingGenerator = () => {
  const schemaProperties = {};
  for (let attrIndex = 0; attrIndex < rule_definitions.length; attrIndex += 1) {
    const rule = rule_definitions[attrIndex];
    schemaProperties[`i_rule_${rule.id}`] = {
      dynamic: 'strict',
      properties: {
        explanation: shortMapping,
        dependencies: shortMapping,
        hash: shortMapping,
        data: { type: engine instanceof ElkClient ? 'flattened' : 'flat_object' },
      }
    };
  }
  return schemaProperties;
};
const denormalizeRelationsMappingGenerator = () => {
  const databaseRelationshipsName = [
    STIX_SIGHTING_RELATIONSHIP,
    ...STIX_CORE_RELATIONSHIPS,
    ...INTERNAL_RELATIONSHIPS,
    ...schemaTypesDefinition.get(ABSTRACT_STIX_REF_RELATIONSHIP)
  ];
  const schemaProperties = {};
  for (let attrIndex = 0; attrIndex < databaseRelationshipsName.length; attrIndex += 1) {
    const relName = databaseRelationshipsName[attrIndex];
    schemaProperties[`rel_${relName}`] = {
      dynamic: 'strict',
      properties: {
        internal_id: shortMapping,
        inferred_id: shortMapping,
      }
    };
  }
  return schemaProperties;
};
const attributesMappingGenerator = () => {
  const entityAttributes = schemaAttributesDefinition.getAllAttributes();
  const schemaProperties = {};
  for (let attrIndex = 0; attrIndex < entityAttributes.length; attrIndex += 1) {
    const entityAttribute = entityAttributes[attrIndex];
    schemaProperties[entityAttribute.name] = attributeMappingGenerator(entityAttribute);
  }
  return schemaProperties;
};

export const engineMappingGenerator = () => {
  return { ...attributesMappingGenerator(), ...ruleMappingGenerator(), ...denormalizeRelationsMappingGenerator() };
};
const computeIndexSettings = (rolloverAlias) => {
  if (engine instanceof ElkClient) {
    // Rollover alias can be undefined for platform initialized <= 5.8
    const cycle = rolloverAlias ? {
      lifecycle: {
        name: `${ES_INDEX_PREFIX}-ilm-policy`,
        rollover_alias: rolloverAlias,
      }
    } : {};
    return {
      index: {
        mapping: {
          total_fields: {
            limit: ES_MAX_MAPPINGS,
          }
        },
        ...cycle
      }
    };
  }
  // Rollover alias can be undefined for platform initialized <= 5.8
  const cycle = rolloverAlias ? {
    plugins: {
      index_state_management: {
        rollover_alias: rolloverAlias,
      }
    }
  } : {};
  return {
    mapping: {
      total_fields: {
        limit: ES_MAX_MAPPINGS,
      }
    },
    ...cycle
  };
};

// Only useful for option ES_INIT_RETRO_MAPPING_MIGRATION
// This mode let the platform initialize old mapping protection before direct stop
// Its only useful when old platform needs to be reindex
const getRetroCompatibleMappings = () => {
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
    }
  };
};

const updateIndexTemplate = async (name, mapping_properties) => {
  // compute pattern to be retro compatible for platform < 5.9
  // Before 5.9, only one pattern for all indices
  const index_pattern = name === `${ES_INDEX_PREFIX}-index-template` ? `${ES_INDEX_PREFIX}*` : `${name}*`;
  return await engine.indices.putIndexTemplate({
    name,
    create: false,
    body: {
      index_patterns: [index_pattern],
      template: {
        settings: computeIndexSettings(name),
        mappings: ES_IS_OLD_MAPPING ? {
          properties: getRetroCompatibleMappings()
        } : {
          // Global option to prevent elastic to try any magic
          dynamic: 'strict',
          date_detection: false,
          numeric_detection: false,
          properties: mapping_properties,
        }
      },
      composed_of: [`${ES_INDEX_PREFIX}-core-settings`],
      version: 3,
      _meta: {
        description: 'To generate opencti expected index mappings',
      },
    },
  }).catch((e) => {
    throw DatabaseError('Creating index template fail', { cause: e });
  });
};

const elCreateIndexTemplate = async (index, mappingProperties) => {
  // Compat with platform initiated prior 5.9.X
  const isPriorVersionExist = await engine.indices.existsIndexTemplate({ name: `${ES_INDEX_PREFIX}-index-template` })
    .then((r) => oebp(r));
  if (isPriorVersionExist) {
    return null;
  }
  // Create / update template
  const componentTemplateExist = await engine.cluster.existsComponentTemplate({ name: `${ES_INDEX_PREFIX}-core-settings` });
  if (!componentTemplateExist) {
    await updateCoreSettings();
  }
  return updateIndexTemplate(index, mappingProperties);
};
const sortMappingsKeys = (o) => (Object(o) !== o || Array.isArray(o) ? o
  : Object.keys(o).sort().reduce((a, k) => ({ ...a, [k]: sortMappingsKeys(o[k]) }), {}));
export const elUpdateIndicesMappings = async () => {
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
    await engine.indices.putSettings({ index, body: platformSettings }).catch((e) => {
      throw DatabaseError('Updating index settings fail', { index, cause: e });
    });

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
      await engine.indices.putMapping({ index, body }).catch((e) => {
        throw DatabaseError('Updating index mapping fail', { index, cause: e });
      });
    }
  }
};
export const elConfigureAttachmentProcessor = async () => {
  let success = true;
  if (engine instanceof ElkClient) {
    await engine.ingest.putPipeline({
      id: 'attachment',
      description: 'Extract attachment information',
      processors: [
        {
          attachment: {
            field: 'file_data',
            remove_binary: true
          }
        }
      ]
    }).catch((e) => {
      logApp.error('Engine attachment processor configuration fail', { cause: e });
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
              field: 'file_data'
            }
          },
          {
            remove: {
              field: 'file_data'
            }
          }
        ]
      }
    }).catch((e) => {
      logApp.error('Engine attachment processor configuration fail', { cause: e });
      success = false;
    });
  }
  return success;
};

export const elDeleteIndex = async (index) => {
  const indexesToRemove = await elIndexGetAlias(index);
  try {
    const response = await engine.indices.delete({ index: Object.keys(indexesToRemove) });
    logApp.info(`Index '${indexesToRemove}' deleted successfully.`, response);
  } catch (error) {
    logApp.error('Error deleting indexes:', error);
  }
};
export const elCreateIndex = async (index, mappingProperties) => {
  await elCreateIndexTemplate(index, mappingProperties);
  const indexName = `${index}${ES_INDEX_PATTERN_SUFFIX}`;
  const isExist = await engine.indices.exists({ index: indexName }).then((r) => oebp(r));
  if (!isExist) {
    return engine.indices.create({ index: indexName, body: { aliases: { [index]: {} } } });
  }
  return null;
};
export const elCreateIndices = async (indexesToCreate = WRITE_PLATFORM_INDICES) => {
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

export const elDeleteIndices = async (indexesToDelete) => {
  return Promise.all(
    indexesToDelete.map((index) => {
      return engine.indices.delete({ index })
        .then((response) => oebp(response))
        .catch((err) => {
          /* v8 ignore next */
          if (err.meta.body && err.meta.body.error.type !== 'index_not_found_exception') {
            logApp.error('Indices deletion fail', { cause: err });
          }
        });
    })
  );
};

const getRuntimeUsers = async (context, user) => {
  const users = await getEntitiesListFromCache(context, user, ENTITY_TYPE_USER);
  return R.mergeAll(users.map((i) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
};
const getRuntimeMarkings = async (context, user) => {
  const identities = await getEntitiesListFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.definition })));
};
const getRuntimeEntities = async (context, user, entityType) => {
  const elements = await elPaginate(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types: [entityType],
    first: MAX_RUNTIME_RESOLUTION_SIZE,
    bypassSizeLimit: true, // ensure that max runtime prevent on ES_MAX_PAGINATION
    connectionFormat: false,
  });
  return R.mergeAll(elements.map((i) => ({ [i.internal_id]: i.name })));
};

export const RUNTIME_ATTRIBUTES = {
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
    getParams: async (context, user) => getRuntimeEntities(context, user, ENTITY_TYPE_IDENTITY)
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
    getParams: async (context, user) => getRuntimeUsers(context, user),
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
    getParams: async (context, user) => getRuntimeEntities(context, user, ENTITY_TYPE_LOCATION_COUNTRY)
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
    getParams: async (context, user) => getRuntimeEntities(context, user, ENTITY_TYPE_LOCATION_COUNTRY)
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
    getParams: async (context, user) => getRuntimeUsers(context, user),
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
    getParams: async (context, user) => getRuntimeMarkings(context, user),
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
    getParams: async (context, user) => getRuntimeEntities(context, user, ENTITY_TYPE_KILL_CHAIN_PHASE),
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
    getParams: async (context, user) => getRuntimeUsers(context, user),
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
    getParams: async (context, user) => getRuntimeUsers(context, user),
  },
};

// region relation reconstruction
const elBuildRelation = (type, connection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: connection.types.find((connectionType) => !isAbstract(connectionType)),
  };
};
const elMergeRelation = (concept, fromConnection, toConnection) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('Reconstruction of the relation fail', concept.internal_id);
  }
  const from = elBuildRelation('from', fromConnection);
  from.source_ref = `${convertTypeToStixType(from.fromType)}--temporary`;
  const to = elBuildRelation('to', toConnection);
  to.target_ref = `${convertTypeToStixType(to.toType)}--temporary`;
  return R.mergeAll([concept, from, to]);
};
export const elRebuildRelation = (concept) => {
  if (concept.base_type === BASE_TYPE_RELATION) {
    const { connections } = concept;
    const entityType = concept.entity_type;
    const fromConnection = R.find((connection) => connection.role === `${entityType}_from`, connections);
    const toConnection = R.find((connection) => connection.role === `${entityType}_to`, connections);
    const relation = elMergeRelation(concept, fromConnection, toConnection);
    relation.relationship_type = relation.entity_type;
    return R.dissoc('connections', relation);
  }
  return concept;
};
const elDataConverter = (esHit) => {
  const elementData = esHit._source;
  const data = {
    _index: esHit._index,
    _id: esHit._id,
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
    ...(isNotEmptyField(esHit.fields) ? esHit.fields : {})
  };
  const entries = Object.entries(data);
  const ruleInferences = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions = Object.values(val);
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
  return data;
};
// endregion

export const elConvertHitsToMap = async (elements, opts = {}) => {
  const { mapWithAllIds = false } = opts;
  const convertedHitsMap = {};
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

export const elConvertHits = async (data) => asyncMap(data, (hit) => elDataConverter(hit));

const withInferencesEntities = (indices, withInferences) => {
  return withInferences ? [READ_INDEX_INFERRED_ENTITIES, ...indices] : indices;
};
const withInferencesRels = (indices, withInferences) => {
  return withInferences ? [READ_INDEX_INFERRED_RELATIONSHIPS, ...indices] : indices;
};
export const computeQueryIndices = (indices, typeOrTypes, withInferences = true) => {
  const types = (Array.isArray(typeOrTypes) || isEmptyField(typeOrTypes)) ? typeOrTypes : [typeOrTypes];
  // If indices are explicitly defined, just rely on the definition
  if (isEmptyField(indices)) {
    // If not and have no clue about the expected types, ask for all indices.
    // Worst case scenario that need to be avoided.
    if (isEmptyField(types)) {
      return withInferences ? READ_DATA_INDICES : READ_DATA_INDICES_WITHOUT_INFERRED;
    }
    // If types are defined we need to infer from them the correct indices
    return R.uniq(types.map((findType) => {
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
        `
  }
};

const findElementsDuplicateIds = (elements) => {
  const duplicatedIds = new Set();
  const elementIds = new Set();
  const checkCurrentIds = (id) => {
    if (!id) return;
    if (elementIds.has(id) && !duplicatedIds.has(id)) {
      duplicatedIds.add(id);
    } else {
      elementIds.add(id);
    }
  };
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    const { [internalId.name]: internal_id, [standardId.name]: standard_id, [xOpenctiStixIds.name]: otherStixIds, [iAliasedIds.name]: aliasIds } = element;
    checkCurrentIds(internal_id);
    checkCurrentIds(standard_id);
    otherStixIds?.map((id) => checkCurrentIds(id));
    aliasIds?.map((id) => checkCurrentIds(id));
  }
  return Array.from(duplicatedIds);
};

const ids_attributes = [internalId.name, standardId.name, xOpenctiStixIds.name, iAliasedIds.name];

// elFindByIds is not defined to use ordering or sorting (ordering is forced by creation date)
// It's a way to load a bunch of ids and use in list or map
export const elFindByIds = async (context, user, ids, opts = {}) => {
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
  const types = (Array.isArray(type) || isEmptyField(type)) ? type : [type];
  const processIds = R.filter((id) => isNotEmptyField(id), idsArray);
  if (processIds.length === 0) {
    return toMap ? {} : [];
  }
  const queryIndices = computeQueryIndices(indices, types);
  const computedIndices = getIndicesToQuery(context, user, queryIndices);
  const hits = [];
  // Leave room in split size compared to max pagination to minimize data loss risk in case of duplicated ids in database
  const splitSize = Math.max(ES_MAX_PAGINATION / 2, ES_DEFAULT_PAGINATION);
  const groupIds = R.splitEvery(splitSize, processIds);
  for (let index = 0; index < groupIds.length; index += 1) {
    const mustTerms = [];
    const workingIds = groupIds[index];
    const idsTermsPerType = [];
    const elementTypes = [...ids_attributes];
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
            { terms: { 'parent_types.keyword': types } }
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
    const body = {
      query: {
        bool: {
          // Put everything under filter to prevent score computation
          // Search without score when no sort is applied is faster
          filter: [{
            bool: {
              must: [...mustTerms, ...draftMust],
              must_not: markingRestrictions.must_not,
            },
          }]
        }
      },
    };
    if (relCount) {
      body.script_fields = {
        script_field_denormalization_count: REL_COUNT_SCRIPT_FIELD
      };
    }
    const _source = { excludes: [] };
    if (withoutRels) _source.excludes.push(`${REL_INDEX_PREFIX}*`);
    if (baseData) _source.includes = [...BASE_FIELDS, ...baseFields];
    const query = {
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
    const searchType = `${ids} (${types ? types.join(', ') : 'Any'})`;
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
      const convertedHits = await elConvertHits(elements);
      hits.push(...convertedHits);
    }
  }
  if (toMap) {
    return elConvertHitsToMap(hits, { mapWithAllIds });
  }
  return hits;
};
export const elLoadById = async (context, user, id, opts = {}) => {
  const hits = await elFindByIds(context, user, id, { ...opts, withoutRels: false });
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
export const elBatchIds = async (context, user, elements) => {
  const ids = elements.map((e) => e.id);
  const types = elements.map((e) => e.type);
  const hits = await elFindByIds(context, user, ids, { type: types, includeDeletedInDraft: true });
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
};
export const elBatchIdsWithRelCount = async (context, user, elements) => {
  const ids = elements.map((e) => e.id);
  const types = elements.map((e) => e.type);
  const opts = { type: types, includeDeletedInDraft: true, relCount: true, baseData: true };
  const hits = await elFindByIds(context, user, ids, opts);
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
};

// region elastic common loader.
export const specialElasticCharsEscape = (query) => {
  return query.replace(/([/+|\-*()^~={}[\]:?!"\\])/g, '\\$1');
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

function processSearch(search, args) {
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
    querySearch
  };
}

export const elGenerateFullTextSearchShould = (search, args = {}) => {
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
    ]).flat()
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

export const elGenerateFieldTextSearchShould = (search, arrayKeys, args = {}) => {
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
      }
    ]).flat()
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
      }
    ]);
  }

  return shouldSearch;
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

const buildFieldForQuery = (field) => {
  return isDateNumericOrBooleanAttribute(field) || field === '_id' || isObjectFlatAttribute(field)
    ? field
    : `${field}.keyword`;
};
export const buildLocalMustFilter = (validFilter) => {
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
            field: nestedFieldKey
          }
        });
      } else if (nestedOperator === 'not_nil') {
        nestedShould.push({
          exists: {
            field: nestedFieldKey
          }
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
        // eslint-disable-next-line no-lonely-if
        if (nestedOperator === FilterOperator.Within) {
          nestedShould.push({
            range: {
              [nestedFieldKey]: { gte: nestedValues[0], lte: nestedValues[1] }
            }
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
                }
              });
            } else if (RANGE_OPERATORS.includes(nestedOperator)) {
              nestedShould.push({
                range: {
                  [nestedFieldKey]: { [nestedOperator]: nestedSearchValue }
                }
              });
            } else { // nestedOperator = 'eq'
              nestedShould.push({
                multi_match: {
                  fields: buildFieldForQuery(nestedFieldKey),
                  query: nestedSearchValue.toString(),
                }
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
    let valueFiltering = { // classic filters: field doesn't exist
      bool: {
        must_not: {
          exists: {
            field: headKey
          }
        }
      }
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must_not: {
              wildcard: {
                [headKey]: '*'
              }
            },
          }
        };
      } else { // string filters: nil <-> (field doesn't exist) OR (field = empty string)
        valueFiltering = {
          bool: {
            should: [
              {
                bool: {
                  must_not: {
                    exists: {
                      field: headKey
                    }
                  }
                }
              },
              {
                term: {
                  [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                },
              },
            ],
            minimum_should_match: 1,
          }
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
                    field: headKey
                  }
                }
              }
            },
            { range: { [headKey]: { lte: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { gte: '5138-11-16T09:46:40.000Z' } } }
          ],
          minimum_should_match: 1,
        }
      };
    }
    valuesFiltering.push(valueFiltering);
  } else if (operator === 'not_nil') {
    const filterDefinition = schemaAttributesDefinition.getAttributeByName(headKey);
    let valueFiltering = { // classic filters: field exists
      exists: {
        field: headKey
      }
    };
    if (filterDefinition?.type === 'string') {
      if (filterDefinition?.format === 'text') { // text filters: use wildcard
        valueFiltering = {
          bool: {
            must: {
              wildcard: {
                [headKey]: '*'
              }
            },
          }
        };
      } else { // other filters: not_nil <-> (field exists) AND (field != empty string)
        valueFiltering = {
          bool: {
            must: [
              {
                exists: {
                  field: headKey
                }
              },
              {
                bool: {
                  must_not: {
                    term: {
                      [headKey === '_id' ? headKey : `${headKey}.keyword`]: { value: '' },
                    },
                  },
                }
              }
            ],
          }
        };
      }
    } else if (filterDefinition?.type === 'date') { // date filters: not_nil <-> (field exists) AND (date > epoch) AND (date < 5138)
      valueFiltering = {
        bool: {
          must: [
            {
              exists: {
                field: headKey
              }
            },
            { range: { [headKey]: { gt: '1970-01-01T01:00:00.000Z' } } },
            { range: { [headKey]: { lt: '5138-11-16T09:46:40.000Z' } } }
          ],
        }
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
        && arrayKeys.every((k) => (!k.includes('*') && (k.endsWith(ID_INTERNAL) || k.endsWith(ID_INFERRED))) || ids_attributes.includes(k));
      if (isTermsQuery) {
        if (operator === 'eq') {
          for (let i = 0; i < arrayKeys.length; i += 1) {
            valuesFiltering.push({
              terms: { [`${arrayKeys[i]}.keyword`]: values }
            });
          }
        } else {
          valuesFiltering.push({
            bool: {
              must_not: arrayKeys.map((k) => ({
                terms: { [`${k}.keyword`]: values }
              })),
            }
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
                script: values[i].toString()
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
                [headKey]: { [operator]: values[i] }
              }
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
            must_not: [o]
          }
        })),
        minimum_should_match: localFilterMode === 'or' ? 1 : noValuesFiltering.length,
      },
    };
  }
  throw UnsupportedError('Invalid filter configuration', validFilter);
};

const buildSubQueryForFilterGroup = (context, user, inputFilters) => {
  const { mode = 'and', filters = [], filterGroups = [] } = inputFilters;
  const localMustFilters = [];
  // Handle filterGroups
  for (let index = 0; index < filterGroups.length; index += 1) {
    const group = filterGroups[index];
    if (isFilterGroupNotEmpty(group)) {
      const subQuery = buildSubQueryForFilterGroup(context, user, group);
      if (subQuery) { // can be null
        localMustFilters.push(subQuery);
      }
    }
  }
  // Handle filters
  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index];
    const isValidFilter = filter?.values || filter?.nested?.length > 0;
    if (isValidFilter) {
      const localMustFilter = buildLocalMustFilter(filter);
      localMustFilters.push(localMustFilter);
    }
  }
  if (localMustFilters.length > 0) {
    return {
      bool: {
        should: localMustFilters,
        minimum_should_match: mode === 'or' ? 1 : localMustFilters.length,
      }
    };
  }
  return null;
};

// If filter key = entity_type, we should also handle parent_types
// Example: filter = {mode: 'or', operator: 'eq', key: ['entity_type'], values: ['Report', 'Stix-Cyber-Observable']}
// we check parent_types because otherwise we would never match Stix-Cyber-Observable which is an abstract parent type
const adaptFilterToEntityTypeFilterKey = (filter) => {
  const { key, mode = 'or', operator = 'eq' } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  // at this point arrayKeys === ['entity_type']

  // we'll build these new filters or filterGroup, depending on the situation
  let newFilter;
  let newFilterGroup;

  if (operator === 'nil' || operator === 'not_nil') { // nil and not_nil operators must have a single key
    newFilterGroup = {
      mode: 'and',
      filters: [
        filter,
        {
          ...filter,
          key: 'parent_types',
        }
      ],
      filterGroups: [],
    };
    return { newFilter, newFilterGroup };
  }

  // In case where filter values is an empty array
  if (filter.values.length === 0) {
    return { newFilter, newFilterGroup };
  }

  // at this point, operator !== nil and operator !== not_nil
  if (mode === 'or') {
    // in elastic, having several keys is an implicit 'or' between the keys, so we can just add the key in the list
    // and we will search in both entity_types and parent_types
    newFilter = { ...filter, key: arrayKeys.concat(['parent_types']) };
  }

  if (mode === 'and') {
    let { values } = filter;
    if (operator === 'eq') {
      // 'and'+'eq' => keep only the most restrictive entity types
      // because in elastic entity_type is a unique value (not an abstract type)
      // for example [Report, Container] => [Report]
      // for example [Report, Stix-Cyber-Observable] => [Report, Stix-Cyber-Observable]
      values = keepMostRestrictiveTypes(filter.values);
    }

    // we must split the keys in different filters to get different elastic matches, so we construct a filterGroup
    // - if the operator is 'eq', it means we have to check equality against the type
    // and all parent types, so it's a filterGroup with 'or' operator
    // - if the operator is 'not_eq', it means we have to check that there is no match in type
    // and all parent types, so it's a filterGroup with 'and' operator
    newFilterGroup = {
      mode: operator === 'eq' ? 'or' : 'and',
      filters: [
        { ...filter, key: ['entity_type'], values },
        { ...filter, key: ['parent_types'], values }
      ],
      filterGroups: [],
    };
  }

  // depending on the operator (or/and), only one of newFilter and newFilterGroup is defined
  return { newFilter, newFilterGroup };
};

export const adaptFilterToIdsFilterKey = (filter) => {
  const { key, mode = 'or', operator = 'eq' } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys[0] !== IDS_FILTER || arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  if (mode === 'and') {
    throw UnsupportedError('Unsupported filter: \'And\' operator between values of a filter with key = \'ids\' is not supported');
  }
  // at this point arrayKey === ['ids'], and mode is always 'or'

  // we'll build these new filters or filterGroup, depending on the situation
  let newFilterGroup;

  const idsArray = [...ids_attributes]; // the keys to handle additionally

  if (operator === 'nil' || operator === 'not_nil') { // nil and not_nil operators must have a single key
    const filters = idsArray.map((idKey) => { return { ...filter, key: idKey }; });
    newFilterGroup = {
      mode: 'and',
      filters,
      filterGroups: [],
    };
    return { newFilterGroup };
  }

  // at this point, operator !== nil and operator !== not_nil
  // we replace the key "ids" by the list of ids attribute (internal_id, standard_id, ...)
  const newFilter = { ...filter, key: idsArray };

  // depending on the operator, only one of newFilter and newFilterGroup is defined
  return { newFilter, newFilterGroup };
};
const adaptFilterToSourceReliabilityFilterKey = async (context, user, filter) => {
  const { key, mode = 'or', operator = 'eq', values } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys[0] !== SOURCE_RELIABILITY_FILTER || arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  // at this point arrayKey === ['source_reliability']

  let newFilter;
  let newFilterGroup;

  // in case we want to filter by source reliability (reliability of author)
  // we need to find all authors filtered by reliability and filter on these authors
  const authorTypes = [
    ENTITY_TYPE_IDENTITY_INDIVIDUAL,
    ENTITY_TYPE_IDENTITY_ORGANIZATION,
    ENTITY_TYPE_IDENTITY_SYSTEM
  ];
  const reliabilityFilter = {
    mode: 'and',
    filters: [{ key: ['x_opencti_reliability'], operator, values, mode }],
    filterGroups: [],
  };
  const opts = { types: authorTypes, filters: reliabilityFilter };
  const authors = await elList(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, opts); // the authors with reliability matching the filter
  // we construct a new filter that matches against the creator internal_id respecting the filtering
  const authorIds = authors.length > 0 ? authors.map((author) => author.internal_id) : ['<no-author-matching-filter>'];
  if (operator === 'nil' || operator === 'not_eq') {
    // the entities we want:
    // (don't have an author) OR (have an author that doesn't have a reliability if operator = 'nil' / doesn't have the right reliability if operator = 'not_eq')
    newFilterGroup = {
      mode: 'or',
      filters: [
        {
          key: ['rel_created-by.internal_id'],
          values: authorIds, // here these authors have no reliability (if operator = 'nil') or not the right one (if operator = 'not_eq')
          mode: 'or',
          operator: 'eq',
        },
        {
          key: ['rel_created-by.internal_id'],
          values: [],
          mode: 'or',
          operator: 'nil',
        },
      ],
      filterGroups: [],
    };
  } else {
    // the entities we want have an author that respect the reliability filtering (= an author of the authorIds list)
    newFilter = {
      key: ['rel_created-by.internal_id'],
      values: authorIds,
      mode: 'or',
      operator: 'eq',
    };
  }

  return { newFilter, newFilterGroup };
};

// fromOrToId and elementWithTargetTypes filters
// are composed of a condition on fromId/fromType and a condition on toId/toType of a relationship
const adaptFilterToFromOrToFilterKeys = (filter) => {
  const { key, operator = 'eq', mode = 'or', values } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  let nestedKey;
  if (arrayKeys[0] === INSTANCE_RELATION_TYPES_FILTER) {
    nestedKey = 'types';
  } else if (arrayKeys[0] === INSTANCE_RELATION_FILTER) {
    nestedKey = 'internal_id';
  } else {
    throw UnsupportedError('A related relations filter with this key is not supported', { key: arrayKeys[0] });
  }

  let newFilterGroup;
  // define mode for the filter group
  let globalMode = 'or';
  if (operator === 'eq' || operator === 'not_nil') {
    // relatedType = malware <-> fromType = malware OR toType = malware
    // relatedType is not empty <-> fromType is not empty OR toType is not empty
    globalMode = 'or';
  } else if (operator === 'not_eq' || operator === 'nil') {
    // relatedType != malware <-> fromType != malware AND toType != malware
    // relatedType is empty <-> fromType is empty AND toType is empty
    globalMode = 'and';
  } else {
    throw Error(`${INSTANCE_RELATION_TYPES_FILTER} filter only support 'eq', 'not_eq', 'nil' and 'not_nil' operators, not ${operator}.`);
  }
  // define the filter group
  if (operator === 'eq' || operator === 'not_eq') {
    const filterGroupsForValues = values.map((val) => {
      const nestedFrom = [
        { key: nestedKey, operator, values: [val] },
        { key: 'role', operator: 'wildcard', values: ['*_from'] }
      ];
      const nestedTo = [
        { key: nestedKey, operator, values: [val] },
        { key: 'role', operator: 'wildcard', values: ['*_to'] }
      ];
      return {
        mode: globalMode,
        filters: [{ key: 'connections', nested: nestedFrom, mode }, { key: 'connections', nested: nestedTo, mode }],
        filterGroups: [],
      };
    });
    newFilterGroup = {
      mode,
      filters: [],
      filterGroups: filterGroupsForValues,
    };
  } else if (operator === 'nil' || operator === 'not_nil') {
    const nestedFrom = [
      { key: nestedKey, operator, values: [] },
      { key: 'role', operator: 'wildcard', values: ['*_from'] }
    ];
    const nestedTo = [
      { key: nestedKey, operator, values: [] },
      { key: 'role', operator: 'wildcard', values: ['*_to'] }
    ];
    const innerFilters = [{ key: 'connections', nested: nestedFrom, mode }, { key: 'connections', nested: nestedTo, mode }];
    newFilterGroup = {
      mode: globalMode,
      filters: innerFilters,
      filterGroups: [],
    };
  }
  return { newFilter: undefined, newFilterGroup };
};

const adaptFilterToPirFilterKeys = async (context, user, filterKey, filter) => {
  // the key should be of format: pir_score.PIR_ID
  const splittedKey = filterKey.split('.');
  if (splittedKey.length !== 2) {
    throw FunctionalError('The filter key should be followed by a dot and the Pir ID', { filterKey });
  }
  const pirKey = splittedKey[0];
  const pirId = splittedKey[1];
  // check the user has access to the PIR
  await getPirWithAccessCheck(context, user, pirId);
  // push the nested pir_score filter associated to the given PIR ID
  const newFilter = {
    key: ['pir_information'],
    values: [],
    nested: [
      { ...filter, key: pirKey },
      { key: 'pir_id', values: [pirId], operator: FilterOperator.Eq },
    ]
  };
  return { newFilter, newFilterGroup: undefined };
};

const adaptFilterForMetricsFilterKeys = async (filter) => {
  const newFilter = {
    key: ['metrics'],
    mode: 'and',
    nested: [
      { key: 'name', values: [filter.key], operator: 'eq' },
      { key: 'value', values: filter.values, operator: filter.operator, mode: filter.mode },
    ]
  };
  return { newFilter, newFilterGroup: undefined };
};

const adaptFilterToComputedReliabilityFilterKey = async (context, user, filter) => {
  const { key, operator = 'eq' } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys[0] !== COMPUTED_RELIABILITY_FILTER || arrayKeys.length > 1) {
    throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
  }
  if (!['eq', 'not_eq', 'nil', 'not_nil'].includes(operator)) {
    throw UnsupportedError('This operator is not supported for this filter key', { keys: arrayKeys, operator });
  }
  // at this point arrayKey === ['computed_reliability']

  let newFilterGroup;
  let newFilter;

  const { newFilter: sourceReliabilityFilter, newFilterGroup: sourceReliabilityFilterGroup } = await adaptFilterToSourceReliabilityFilterKey(
    context,
    user,
    { ...filter, key: SOURCE_RELIABILITY_FILTER }
  );
  const isConditionAdditional = operator === 'not_eq' || operator === 'nil'; // if we have one of these operators, the condition on reliability and the condition on source reliability should be both respected
  // else, (the condition on reliability should be respected) OR (reliability is empty and the condition should be respected on source_reliability)

  if (!isConditionAdditional) {
    // if !isConditionalAdditional: computed reliability filter = (reliability filter) OR (reliability is empty AND source_reliability filter)
    // // example: computed reliability filter = (reliability = A) OR (reliability is empty AND source_reliability = A)
    newFilterGroup = sourceReliabilityFilter ? {
      mode: 'or',
      filters: [{
        ...filter,
        key: ['x_opencti_reliability'],
      }],
      filterGroups: [{
        mode: 'and',
        filters: [
          {
            key: ['x_opencti_reliability'],
            values: [],
            operator: 'nil',
            mode: 'or',
          },
          sourceReliabilityFilter,
        ],
        filterGroups: [],
      }],
    } : {
      mode: 'or',
      filters: [{
        ...filter,
        key: ['x_opencti_reliability'],
      }],
      filterGroups: [{
        mode: 'and',
        filters: [
          {
            key: ['x_opencti_reliability'],
            values: [],
            operator: 'nil',
            mode: 'or',
          }
        ],
        filterGroups: [sourceReliabilityFilterGroup],
      }],
    };
  } else {
    // if isConditionalAdditional: computed reliability filter = (reliability filter) AND (source_reliability filter)
    // // example: computed reliability filter = (reliability != A) AND (source_reliability != A)
    newFilterGroup = sourceReliabilityFilter ? {
      mode: 'and',
      filters: [
        {
          ...filter,
          key: ['x_opencti_reliability'],
        },
        sourceReliabilityFilter
      ],
      filterGroups: [],
    } : {
      mode: 'and',
      filters: [{
        ...filter,
        key: ['x_opencti_reliability'],
      }],
      filterGroups: [sourceReliabilityFilterGroup],
    };
  }

  return { newFilter, newFilterGroup };
};

// workflow_id filter values can be both status ids and status templates ids
const adaptFilterToWorkflowFilterKey = async (context, user, filter) => {
  const { key, mode = 'or', operator = 'eq', values } = filter;
  const arrayKeys = Array.isArray(key) ? key : [key];
  if (arrayKeys.length > 1) {
    throw UnsupportedError(`A filter with these multiple keys is not supported : ${arrayKeys}`);
  }
  if (![WORKFLOW_FILTER, X_OPENCTI_WORKFLOW_ID].includes(arrayKeys[0])) {
    throw UnsupportedError('The key is not correct', { keys: arrayKeys });
  }
  let newFilterGroup;
  let newFilter;
  if (operator === 'nil' || operator === 'not_nil') { // no status template <-> no status // at least a status template <-> at least a status
    newFilter = {
      ...filter,
      key: ['x_opencti_workflow_id'], // we just have to change the key
    };
  } else if (operator === 'eq' || operator === 'not_eq') {
    const statuses = await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS);
    const filters = [];
    for (let i = 0; i < values.length; i += 1) {
      const filterValue = values[i];
      // fetch the statuses associated to the filter value
      // (keep the statuses with their id corresponding to the filter value, or with their template id corresponding to the filter value)
      const associatedStatuses = statuses.filter((status) => (filterValue === status.id || filterValue === status.template_id));
      // we construct a new filter that matches against the status internal_id with a template id in the filters values
      // !!! it works to do the mode/operator filter on the status (and not on the template)
      // because a status can only have a single template and because the operators are full-match operators (eq/not_eq) !!!
      const associatedStatuseIds = associatedStatuses.length > 0 ? associatedStatuses.map((status) => status.internal_id) : ['<no-status-matching-filter>'];
      filters.push({
        key: ['x_opencti_workflow_id'],
        values: associatedStatuseIds,
        mode: operator === 'eq'
          ? 'or' // at least one associated status should match
          : 'and', // all the associated status of the value shouldn't match
        operator,
      });
    }
    newFilterGroup = {
      mode,
      filters,
      filerGroups: [],
    };
  } else {
    throw UnsupportedError('The operators supported for a filter with key=workflow_id is not supported.', { operator });
  }
  return { newFilter, newFilterGroup };
};

const adaptFilterValueToIsInferredFilter = (value, operator = 'eq') => {
  const equivalentBooleanValueIsTrue = value === 'true';
  const wildcardOperator = (operator === 'eq' && equivalentBooleanValueIsTrue)
  || (operator === 'not_eq' && !equivalentBooleanValueIsTrue)
    ? 'wildcard'
    : 'not_wildcard';
  return {
    key: 'i_rule_*',
    values: ['*'],
    operator: wildcardOperator,
  };
};

/**
 * Complete the filter if needed for several special filter keys
 * Some keys need this preprocessing before building the query:
 * - regardingOf: we need to handle the relationship_type and the element id involved in the relationship
 * - ids: we will match the ids in filter against internal id, standard id, stix ids
 * - entity_type / relationship_type: we need to handle parent types
 * - workflow_id: handle both status and status template of the entity status
 * - source_reliability: created_by (author) can be an individual, organization or a system
 * - fromOrToId, fromId, toId, fromTypes, toTypes: for relationship, we need to create nested filters
 */
const completeSpecialFilterKeys = async (context, user, inputFilters) => {
  const { filters = [], filterGroups = [] } = inputFilters;
  const finalFilters = [];
  const finalFilterGroups = [];
  for (let index = 0; index < filterGroups.length; index += 1) {
    const filterGroup = filterGroups[index];
    const newFilterGroup = await completeSpecialFilterKeys(context, user, filterGroup);
    finalFilterGroups.push(newFilterGroup);
  }
  for (let index = 0; index < filters.length; index += 1) {
    const filter = filters[index];
    const { key } = filter;
    const arrayKeys = Array.isArray(key) ? key : [key];
    if (arrayKeys.some((filterKey) => isComplexConversionFilterKey(filterKey))) {
      if (arrayKeys.length > 1) {
        throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
      }
      const filterKey = arrayKeys[0];
      if (filterKey === INSTANCE_REGARDING_OF || filterKey === INSTANCE_DYNAMIC_REGARDING_OF) {
        const regardingFilters = [];
        const idParameter = filter.values.find((i) => i.key === ID_FILTER);
        const typeParameter = filter.values.find((i) => i.key === RELATION_TYPE_FILTER);
        const dynamicParameter = filter.values.find((i) => i.key === RELATION_DYNAMIC_FILTER);
        // Check parameters
        if (!idParameter && !dynamicParameter && !typeParameter) {
          throw UnsupportedError('Id or dynamic or relationship type are needed for this filtering key', { key: filterKey });
        }
        if (dynamicParameter && !typeParameter?.values?.length) {
          throw UnsupportedError('Relationship type is needed for dynamic in regards of filtering', { key: filterKey, type: typeParameter });
        }
        // Check operator
        if (filter.operator && filter.operator !== 'eq' && filter.operator !== 'not_eq') {
          throw UnsupportedError('regardingOf only support equality restriction');
        }
        // Check for PIR has it required
        if (typeParameter) {
          const isPirRelatedType = (typeParameter.values ?? []).includes(RELATION_IN_PIR);
          if (isPirRelatedType && !isUserHasCapability(user, PIRAPI)) {
            throw ForbiddenAccess('You are not allowed to use PIR filtering');
          }
        }
        let ids = idParameter?.values ?? [];
        // Limit the number of possible ids in the regardingOf
        if (ids.length > ES_MAX_PAGINATION) {
          throw UnsupportedError('Too much ids specified', { size: ids.length, max: ES_MAX_PAGINATION });
        }
        if (ids.length > 0) {
          // Keep ids the user has access to
          const filteredEntities = await elFindByIds(context, user, ids, { baseData: true });
          // If no type specified, we also need to check if the user have the correct capability for Pirs
          if (!typeParameter && !isUserHasCapability(user, PIRAPI)) {
            const isIncludingPir = (await uniqAsyncMap(filteredEntities, (value) => value.entity_type))
              .includes(ENTITY_TYPE_PIR);
            if (isIncludingPir) {
              throw ForbiddenAccess('You are not allowed to use PIR filtering');
            }
          }
          ids = filteredEntities.map((n) => n.id);
          if (ids.length === 0) { // If no id available, reject the query
            throw ResourceNotFoundError('Specified ids not found or restricted');
          }
        }
        // Check dynamic
        const dynamicFilter = dynamicParameter?.values ?? [];
        if (isNotEmptyField(dynamicFilter)) {
          const computedIndices = computeQueryIndices([], [ABSTRACT_STIX_OBJECT]);
          const relatedEntities = await elPaginate(context, user, computedIndices, {
            connectionFormat: false,
            first: ES_MAX_PAGINATION,
            baseData: true,
            filters: addFilter(dynamicFilter[0], TYPE_FILTER, [ABSTRACT_STIX_CORE_OBJECT]),
          });
          if (relatedEntities.length > 0) {
            const relatedIds = relatedEntities.map((n) => n.id);
            ids.push(...relatedIds);
          } else {
            ids.push('<invalid id>'); // To force empty result in the query result
          }
        }
        const types = typeParameter?.values;
        // Construct and push the final regarding of filter
        const mode = (filter.operator === 'eq' || isEmptyField(filter.operator)) ? FilterMode.Or : FilterMode.And;
        if (isEmptyField(ids)) {
          const keys = isEmptyField(types) ? buildRefRelationKey('*', '*')
            : types.map((t) => buildRefRelationKey(t, '*'));
          keys.forEach((relKey) => {
            regardingFilters.push({ key: [relKey], operator: filter.operator, values: ['EXISTS'] });
          });
        } else {
          const keys = isEmptyField(types)
            ? buildRefRelationKey('*', '*')
            : types.flatMap((t) => [buildRefRelationKey(t, ID_INTERNAL), buildRefRelationKey(t, ID_INFERRED)]);
          regardingFilters.push({ key: keys, operator: filter.operator, mode, values: ids });
        }
        finalFilterGroups.push({ mode, filters: regardingFilters, filterGroups: [] });
      }
      if (filterKey === IDS_FILTER) {
        // the special filter key 'ids' take all the ids into account
        const { newFilter, newFilterGroup } = adaptFilterToIdsFilterKey(filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === TYPE_FILTER || filterKey === RELATION_TYPE_FILTER) {
        // add parent_types checking (in case the given value in type is an abstract type)
        const { newFilter, newFilterGroup } = adaptFilterToEntityTypeFilterKey(filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === WORKFLOW_FILTER || filterKey === X_OPENCTI_WORKFLOW_ID) {
        // in case we want to filter by status template (template of a workflow status) or status
        // we need to find all statuses filtered by status template and filter on these statuses
        const { newFilter, newFilterGroup } = await adaptFilterToWorkflowFilterKey(context, user, filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === COMPUTED_RELIABILITY_FILTER) {
        // filter by computed reliability (reliability, or reliability of author if no reliability)
        const { newFilter, newFilterGroup } = await adaptFilterToComputedReliabilityFilterKey(context, user, filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === SOURCE_RELIABILITY_FILTER) {
        // in case we want to filter by source reliability (reliability of author)
        // we need to find all authors filtered by reliability and filter on these authors
        const { newFilter, newFilterGroup } = await adaptFilterToSourceReliabilityFilterKey(context, user, filter);
        if (newFilter) {
          finalFilters.push(newFilter);
        }
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === INSTANCE_RELATION_FILTER) {
        const { newFilterGroup } = adaptFilterToFromOrToFilterKeys(filter);
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === RELATION_FROM_FILTER || filterKey === RELATION_DYNAMIC_FROM_FILTER
          || filterKey === RELATION_TO_FILTER || filterKey === RELATION_DYNAMIC_TO_FILTER
          || filterKey === RELATION_TO_SIGHTING_FILTER) {
        const isDynamic = filterKey === RELATION_DYNAMIC_FROM_FILTER || filterKey === RELATION_DYNAMIC_TO_FILTER;
        const dynamicIds = [];
        if (isDynamic) {
          const computedIndices = computeQueryIndices([], [ABSTRACT_STIX_OBJECT]);
          const targetEntities = await elPaginate(context, user, computedIndices, {
            connectionFormat: false,
            first: ES_MAX_PAGINATION,
            bypassSizeLimit: true, // ensure that max runtime prevent on ES_MAX_PAGINATION
            baseData: true,
            filters: addFilter(filter.values[0], TYPE_FILTER, [ABSTRACT_STIX_CORE_OBJECT]),
          });
          if (targetEntities.length > 0) {
            const relatedIds = targetEntities.map((n) => n.id);
            dynamicIds.push(...relatedIds);
          }
        }

        const side = filterKey === RELATION_FROM_FILTER || filterKey === RELATION_DYNAMIC_FROM_FILTER ? 'from' : 'to';
        const nested = [
          { key: 'internal_id', operator: filter.operator, values: isDynamic ? dynamicIds : filter.values },
          { key: 'role', operator: 'wildcard', values: [`*_${side}`] }
        ];
        finalFilters.push({ key: 'connections', nested, mode: filter.mode });
      }
      if (filterKey === RELATION_FROM_TYPES_FILTER || filterKey === RELATION_TO_TYPES_FILTER) {
        const side = filterKey === RELATION_FROM_TYPES_FILTER ? 'from' : 'to';
        const nested = [
          { key: 'types', operator: filter.operator, values: filter.values },
          { key: 'role', operator: 'wildcard', values: [`*_${side}`] }
        ];
        finalFilters.push({ key: 'connections', nested, mode: filter.mode });
      }
      if (filterKey === INSTANCE_RELATION_TYPES_FILTER) {
        const { newFilterGroup } = adaptFilterToFromOrToFilterKeys(filter);
        if (newFilterGroup) {
          finalFilterGroups.push(newFilterGroup);
        }
      }
      if (filterKey === RELATION_FROM_ROLE_FILTER || filterKey === RELATION_TO_ROLE_FILTER) {
        const side = filterKey === RELATION_FROM_ROLE_FILTER ? 'from' : 'to';
        // Retro compatibility for buildAggregationRelationFilter that use fromRole depending on isTo attribute
        const values = filter.values.map((r) => (!r.endsWith('_from') && !r.endsWith('_to') ? `${r}_${side}` : r));
        const nested = [{ key: 'role', operator: filter.operator, values }];
        finalFilters.push({ key: 'connections', nested, mode: filter.mode });
      }
      if (filterKey === 'authorized_members.id' || filterKey === 'restricted_members.id') {
        const nested = [{ key: 'id', operator: filter.operator, values: filter.values }];
        finalFilters.push({ key: authorizedMembers.name, nested, mode: filter.mode });
      }
      if (filterKey === ALIAS_FILTER) {
        finalFilterGroups.push({
          mode: filter.operator === 'nil' || (filter.operator.startsWith('not_') && filter.operator !== 'not_nil')
            ? 'and'
            : 'or',
          filters: [
            { ...filter, key: [ATTRIBUTE_ALIASES] },
            { ...filter, key: [ATTRIBUTE_ALIASES_OPENCTI] },
          ],
          filterGroups: [],
        });
      }
      if (filterKey === IS_INFERRED_FILTER) {
        // an entity/relationship is inferred <=> a field i_rule_XX is defined, indicating the inferred rule that created the element (ex: i_rule_location_targets)
        if (filter.values.length === 1) {
          const value = filter.values[0];
          finalFilters.push(adaptFilterValueToIsInferredFilter(value, filter.operator));
        } else {
          finalFilterGroups.push({
            mode: filter.mode,
            filters: filter.values.map((v) => adaptFilterValueToIsInferredFilter(v, filter.operator)),
            filterGroups: [],
          });
        }
      }
      if (filterKey.startsWith(PIR_SCORE_FILTER_PREFIX) || filterKey.startsWith(LAST_PIR_SCORE_DATE_FILTER_PREFIX)) {
        const { newFilter } = await adaptFilterToPirFilterKeys(context, user, filterKey, filter);
        finalFilters.push(newFilter);
      }
      if (filterKey === USER_SERVICE_ACCOUNT_FILTER) {
        const { operator, mode, values } = filter;
        if (values.includes('false') && values.includes('true') && mode === FilterMode.And) {
          if (operator === FilterOperator.Eq) {
            finalFilters.push(filter); // nothing to modify
          } else if (operator === FilterOperator.NotEq) {
            const newFilterGroup = {
              mode: 'and',
              filters: [{
                key: USER_SERVICE_ACCOUNT_FILTER,
                values: [],
                operator: FilterOperator.NotNil,
              },
              filter],
              filterGroups: [],
            };
            finalFilterGroups.push(newFilterGroup);
          }
        } else if ((values.includes('false') && operator === FilterOperator.Eq)
        || (values.includes('true') && operator === FilterOperator.NotEq)) {
          // if user_service_account = false, return also users with with null user_service_account
          const newFilterGroup = {
            mode: 'or',
            filters: [{
              key: USER_SERVICE_ACCOUNT_FILTER,
              values: [],
              operator: FilterOperator.Nil,
            },
            filter],
            filterGroups: [],
          };
          finalFilterGroups.push(newFilterGroup);
        } else {
          finalFilters.push(filter); // nothing to modify
        }
      }

      if (filterKey === BULK_SEARCH_KEYWORDS_FILTER) {
        const newFilter = {
          ...filter,
          key: BULK_SEARCH_KEYWORDS_FILTER_KEYS,
        };
        finalFilters.push(newFilter);
      }

      if (isMetricsName(filterKey)) {
        const { newFilter } = await adaptFilterForMetricsFilterKeys(filter);
        finalFilters.push(newFilter);
      }
    } else if (arrayKeys.some((filterKey) => isObjectAttribute(filterKey)) && !arrayKeys.some((filterKey) => filterKey === 'connections')) {
      if (arrayKeys.length > 1) {
        throw UnsupportedError('A filter with these multiple keys is not supported', { keys: arrayKeys });
      }
      const definition = schemaAttributesDefinition.getAttributeByName(key[0]);
      if (definition.format === 'standard') {
        finalFilterGroups.push({
          mode: filter.mode,
          filters: filter.values.map((v) => {
            const filterKeys = Array.isArray(v.key) ? v.key : [v.key];
            return { ...v, key: filterKeys.map((k) => `${k}.${v.key}`) };
          }),
          filterGroups: []
        });
      } else if (definition.format === 'nested') {
        finalFilters.push({ key, operator: filter.operator, nested: filter.values, mode: filter.mode });
      } else {
        throw UnsupportedError('Object attribute format is not filterable', { format: definition.format });
      }
    } else {
      // not a special case, leave the filter unchanged
      // Of special case but in a multi keys filter but is currently not supported
      finalFilters.push(filter);
    }
  }
  return {
    ...inputFilters,
    filters: finalFilters,
    filterGroups: finalFilterGroups,
  };
};
const elQueryBodyBuilder = async (context, user, options) => {
  // eslint-disable-next-line no-use-before-define
  const { ids = [], after, orderBy = null, pirId = null, orderMode = 'asc', noSize = false, noSort = false, intervalInclude = false } = options;
  const { relCount = false } = options;
  const first = options.first ?? ES_DEFAULT_PAGINATION;
  const { types = null, search = null } = options;
  const filters = await checkAndConvertFilters(context, user, options.filters, user.id, elFindByIds, { noFiltersChecking: options.noFiltersChecking });
  const { startDate = null, endDate = null, dateAttribute = null } = options;
  const searchAfter = after ? cursorToOffset(after) : undefined;
  let ordering = [];
  const { includeAuthorities = false } = options;
  // Handle marking restrictions
  const markingRestrictions = await buildDataRestrictions(context, user, { includeAuthorities });
  const accessMust = markingRestrictions.must;
  const accessMustNot = markingRestrictions.must_not;
  const mustFilters = [];
  // Add special keys to filters
  const specialFiltersContent = [];
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
    filterGroups: isFilterGroupNotEmpty(filters) ? [filters] : [],
  } : filters;
  // Handle filters
  if (isFilterGroupNotEmpty(completeFilters)) {
    const finalFilters = await completeSpecialFilterKeys(context, user, completeFilters);
    const filtersSubQuery = buildSubQueryForFilterGroup(context, user, finalFilters);
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
  const runtimeMappings = {};
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
    const runtime = RUNTIME_ATTRIBUTES[orderBy];
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
  const body = {
    query: {
      bool: {
        must: [...accessMust, ...mustFilters, ...draftMust],
        must_not: accessMustNot,
      },
    },
  };
  if (relCount) {
    body.script_fields = {
      script_field_denormalization_count: REL_COUNT_SCRIPT_FIELD
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
export const elRawCount = async (query) => {
  return engine.count(query)
    .then((data) => {
      return oebp(data).count;
    });
};
export const elCount = async (context, user, indexName, options = {}) => {
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  const query = { index: getIndicesToQuery(context, user, indexName), body };
  logApp.debug('[SEARCH] elCount', { query });
  return elRawCount(query);
};
export const elHistogramCount = async (context, user, indexName, options = {}) => {
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
export const elAggregationCount = async (context, user, indexName, options = {}) => {
  const { field, types = null, weightField = 'i_inference_weight', normalizeLabel = true, convertEntityTypeLabel = false } = options;
  const isIdFields = field.endsWith('internal_id') || field.endsWith('.id');
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
      return buckets.map((b) => {
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

const extractNestedQueriesFromBool = (boolQueryArray, nestedPath = 'connections') => {
  let result = [];
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
const buildAggregationRelationFilters = async (context, user, aggregationFilters) => {
  const aggBody = await elQueryBodyBuilder(context, user, { ...aggregationFilters, noSize: true, noSort: true });
  return {
    bool: {
      must: extractNestedQueriesFromBool(aggBody.query.bool.must ?? []),
      must_not: extractNestedQueriesFromBool(aggBody.query.bool.must_not ?? []),
    },
  };
};
export const elAggregationRelationsCount = async (context, user, indexName, options = {}) => {
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
    null
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
          field: isBooleanAttribute(field)
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
          return buckets.map((b) => ({ label: b.key, value: b.parent.weight.value }));
        }
        // entity_type
        const filteredBuckets = buckets.filter((b) => !(isAbstract(pascalize(b.key)) || isAbstract(b.key)));
        return R.map((b) => ({ label: pascalize(b.key), value: b.parent.weight.value }), filteredBuckets);
      }
      const { buckets } = data.aggregations.genres;
      return buckets.map((b) => {
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

export const elAggregationNestedTermsWithFilter = async (context, user, indexName, aggregation, opts = {}) => {
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
            }
          },
        },
      }
    }
  };
  const query = {
    index: getIndicesToQuery(context, user, indexName),
    body,
  };
  logApp.debug('[SEARCH] elAggregationNestedTermsWithFilter', { query });
  return elRawSearch(context, user, types, query)
    .then((data) => {
      const aggBucketsResult = data.aggregations?.nestedAgg?.filterAggs?.termsAgg?.buckets ?? [];
      return aggBucketsResult.map((b) => {
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

export const elAggregationsList = async (context, user, indexName, aggregations, opts = {}) => {
  const { types = [], resolveToRepresentative = true, postResolveFilter } = opts;
  const queryAggs = {};
  aggregations.forEach((agg) => {
    queryAggs[agg.name] = {
      terms: {
        field: agg.field,
        size: 500, // Aggregate on top 500 should get all needed results
      }
    };
  });
  const body = {
    aggs: queryAggs,
    size: 0 // No limit on the search
  };
  if (types.length) {
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
  const aggsValues = R.uniq(R.flatten(aggsMap.map((agg) => data.aggregations[agg].buckets?.map((b) => b.key))));
  if (resolveToRepresentative) {
    const baseFields = ['internal_id', 'name', 'entity_type']; // Needs to take elements required to fill extractEntityRepresentative function
    let aggsElements = await elFindByIds(context, user, aggsValues, { baseData: !postResolveFilter, baseFields }); // If post filter is required, we need to retrieve all fields
    if (postResolveFilter) {
      aggsElements = await postResolveFilter(aggsElements);
    }
    const aggsElementsCache = R.mergeAll(aggsElements.map((element) => ({ [element.internal_id]: extractEntityRepresentativeName(element) })));
    return aggsMap.map((agg) => {
      const values = data.aggregations[agg].buckets?.map((b) => ({ label: aggsElementsCache[b.key], value: b.key }))?.filter((v) => !!v.label);
      return { name: agg, values };
    });
  }
  return aggsMap.map((agg) => {
    const values = data.aggregations[agg].buckets?.map((b) => ({ label: b.key, value: b.key }));
    return { name: agg, values };
  });
};

const buildRegardingOfFilter = async (context, user, elements, filters) => {
  // First check if there is an "in regards of" filter
  // If its case we need to ensure elements are filtered according to denormalization rights.
  if (isNotEmptyField(filters)) {
    const extractedFilters = extractFiltersFromGroup(filters, [INSTANCE_REGARDING_OF, INSTANCE_DYNAMIC_REGARDING_OF])
      .filter((filter) => isEmptyField(filter.operator) || filter.operator === 'eq');
    if (extractedFilters.length > 0) {
      const targetValidatedIds = new Set();
      const sideIdManualInferred = new Map();
      for (let i = 0; i < extractedFilters.length; i += 1) {
        const { values } = extractedFilters[i];
        const ids = values.filter((v) => v.key === ID_FILTER).map((f) => f.values).flat();
        const types = values.filter((v) => v.key === RELATION_TYPE_FILTER).map((f) => f.values).flat();
        const directionForced = R.head(values.filter((v) => v.key === INSTANCE_REGARDING_OF_DIRECTION_FORCED).map((f) => f.values).flat()) ?? false;
        const directionReverse = R.head(values.filter((v) => v.key === INSTANCE_REGARDING_OF_DIRECTION_REVERSE).map((f) => f.values).flat()) ?? false;
        // resolve all relationships that target the id values, forcing the type is available
        const paginateArgs = { baseData: true, types };
        const elementIds = elements.map(({ id }) => id);
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
          paginateArgs.filters = { mode: 'and', filters: directedFilters, filterGroups: [] };
        } else {
          // If no direction is setup, create the filter group for both directions
          const filterTo = [{ key: ['fromId'], values: elementIds }];
          const filterFrom = [{ key: ['toId'], values: elementIds }];
          if (ids.length > 0) { // Ids can be empty if nothing configured by the user
            filterTo.push({ key: ['toId'], values: ids });
            filterFrom.push({ key: ['fromId'], values: ids });
          }
          paginateArgs.filters = {
            mode: 'or',
            filters: [],
            filterGroups: [
              { mode: 'and', filterGroups: [], filters: filterTo },
              { mode: 'and', filterGroups: [], filters: filterFrom }]
          };
        }
        const relationships = await elList(context, user, READ_RELATIONSHIPS_INDICES, paginateArgs);
        // compute side ids
        const addTypeSide = (sideId, sideType) => {
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
      }
      return (element) => {
        const accepted = targetValidatedIds.has(element.id);
        if (accepted) {
          // eslint-disable-next-line no-param-reassign
          element.regardingOfTypes = sideIdManualInferred.get(element.id);
        }
        return accepted;
      };
    }
  }
  return undefined;
};

const buildSearchResult = (elements, first, searchAfter, globalCount, filterCount, connectionFormat) => {
  if (connectionFormat) {
    const nodeHits = elements.map((n) => ({ node: n, sort: n.sort, types: n.regardingOfTypes }));
    return buildPagination(first, searchAfter, nodeHits, globalCount, filterCount);
  }
  return elements;
};

export const elPaginate = async (context, user, indexName, options = {}) => {
  const {
    baseData = false,
    baseFields = [],
    bypassSizeLimit = false,
    withoutRels = true,
    types = null,
    withResultMeta = false,
    first = ES_DEFAULT_PAGINATION,
    filters,
    connectionFormat = true,
  } = options;
  const body = await elQueryBodyBuilder(context, user, options);
  if (body.size > ES_MAX_PAGINATION && !bypassSizeLimit) {
    logApp.info('[SEARCH] Pagination limited to max result config', { size: body.size, max: ES_MAX_PAGINATION });
    body.size = ES_MAX_PAGINATION;
  }
  const _source = { excludes: [] };
  if (withoutRels) _source.excludes.push(`${REL_INDEX_PREFIX}*`);
  if (baseData) _source.includes = [...BASE_FIELDS, ...baseFields];
  const query = {
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
    const data = await elRawSearch(context, user, types !== null ? types : 'Any', query);
    const globalCount = data.hits.total.value;
    const elements = await elConvertHits(data.hits.hits);
    // If filters contains an "in regards of" filter a post-security filtering is needed
    const regardingOfFilter = elements.length === 0 ? undefined : await buildRegardingOfFilter(context, user, elements, filters);
    const filteredElements = regardingOfFilter ? await asyncFilter(elements, regardingOfFilter) : elements;
    const filterCount = elements.length - filteredElements.length;
    const result = buildSearchResult(filteredElements, first, body.search_after, globalCount, filterCount, connectionFormat);
    if (withResultMeta) {
      const lastProcessedSort = R.last(elements)?.sort;
      const endCursor = lastProcessedSort ? offsetToCursor(lastProcessedSort) : null;
      return { elements: result, endCursor, total: globalCount, filterCount };
    }
    return result;
  } catch (err) {
    const root_cause = err.meta?.body?.error?.caused_by?.type;
    if (root_cause === TOO_MANY_CLAUSES) throw ComplexSearchError();
    throw DatabaseError('Fail to execute engine pagination', { cause: err, root_cause, query, queryArguments: options });
  }
};

const elRepaginate = async (context, user, indexName, connectionFormat, opts = {}) => {
  const {
    first = ES_DEFAULT_PAGINATION,
    maxSize = undefined,
    logForMigration = false,
    callback
  } = opts;
  let batch = 0;
  let emitSize = 0;
  let globalHitsCount = 0;
  let totalFilteredCount = 0;
  let hasNextPage = true;
  let continueProcess = true;
  let searchAfter = opts.after;
  const listing = [];
  while (continueProcess && (maxSize === undefined || emitSize < maxSize) && hasNextPage) {
    // Force options to get connection format and manage search after and metadata
    const paginateOpts = { ...opts, first, after: searchAfter, connectionFormat: true, withResultMeta: true };
    const { elements: page, filterCount, total, endCursor } = await elPaginate(context, user, indexName, paginateOpts);

    // when first === maxSize only one iteration is necessary except in case of post filtering
    if (first === maxSize && batch > 10) {
      logApp.warn('[PERFORMANCE] Expensive post filtering detected', { batch, opts });
    }
    if (logForMigration) {
      logMigration.info('Migrating loading batch...', { batch });
    }

    if (page.edges.length > 0) {
      const edgeToPublish = maxSize !== undefined ? page.edges.slice(0, maxSize - emitSize) : page.edges;
      const elements = connectionFormat ? edgeToPublish : await asyncMap(edgeToPublish, (edge) => edge.node);
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

export const elConnection = async (context, user, indexName, opts = {}) => {
  const { elements, totalCount } = await elRepaginate(context, user, indexName, true, opts);
  return buildPaginationFromEdges(opts.first, opts.after, elements, totalCount);
};

export const elList = async (context, user, indexName, opts = {}) => {
  const data = await elRepaginate(context, user, indexName, false, opts);
  return data.elements;
};

export const elLoadBy = async (context, user, field, value, type = null, indices = READ_DATA_INDICES) => {
  const filters = {
    mode: 'and',
    filters: [{ key: field, values: [value] }],
    filterGroups: [],
  };
  const opts = { filters, connectionFormat: false, types: type ? [type] : [] };
  const hits = await elPaginate(context, user, indices, opts);
  if (hits.length > 1) {
    throw UnsupportedError('Id loading expected only one response', { size: hits.length });
  }
  return R.head(hits);
};
export const elAttributeValues = async (context, user, field, opts = {}) => {
  const { orderMode = 'asc', search } = opts;
  const first = opts.first ?? ES_DEFAULT_PAGINATION;
  const markingRestrictions = await buildDataRestrictions(context, user);
  const must = [];
  if (isNotEmptyField(search) && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search);
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
  const values = (buckets ?? []).map((n) => n.key).filter((val) => (search ? val.includes(search.toLowerCase()) : true));
  const nodeElements = values.map((val) => ({ node: { id: val, key: field, value: val } }));
  return buildPagination(0, null, nodeElements, nodeElements.length);
};
// endregion

export const elBulk = async (args) => {
  return elRawBulk(args).then((data) => {
    if (data.errors) {
      const errors = data.items.map((i) => i.index?.error || i.update?.error).filter((f) => f !== undefined);
      if (errors.filter((err) => err.type !== DOCUMENT_MISSING_EXCEPTION).length > 0) {
        throw DatabaseError('Bulk indexing fail', { errors });
      }
    }
    return data;
  });
};
/* v8 ignore next */
export const elIndex = async (indexName, documentBody, opts = {}) => {
  const { refresh = true, pipeline } = opts;
  const documentId = documentBody.internal_id;
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  logApp.debug(`[SEARCH] index > ${entityType} ${documentId} in ${indexName}`, { documentBody });
  let indexParams = {
    index: indexName,
    id: documentBody.internal_id,
    refresh,
    timeout: '60m',
    body: R.dissoc('_index', documentBody),
  };
  if (pipeline) {
    indexParams = { ...indexParams, pipeline };
  }
  await engine.index(indexParams).catch((err) => {
    throw DatabaseError('Simple indexing fail', { cause: err, documentId, entityType, ...extendedErrors({ documentBody }) });
  });
  return documentBody;
};
/* v8 ignore next */
export const elUpdate = (indexName, documentId, documentBody, retry = ES_RETRY_ON_CONFLICT) => {
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  return engine.update({
    id: documentId,
    index: indexName,
    retry_on_conflict: retry,
    timeout: BULK_TIMEOUT,
    refresh: true,
    body: documentBody,
  }).catch((err) => {
    throw DatabaseError('Update indexing fail', { cause: err, documentId, entityType, ...extendedErrors({ documentBody }) });
  });
};
export const elReplace = (indexName, documentId, documentBody) => {
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
export const elDelete = (indexName, documentId) => {
  return engine.delete({
    id: documentId,
    index: indexName,
    timeout: BULK_TIMEOUT,
    refresh: true,
  }).catch((err) => {
    throw DatabaseError('Deleting indexing fail', { cause: err, documentId });
  });
};

const getRelatedRelations = async (context, user, targetIds, elements, level, cache, opts = {}) => {
  const fromOrToIds = Array.isArray(targetIds) ? targetIds : [targetIds];
  const filtersContent = [{
    key: 'connections',
    nested: [{ key: 'internal_id', values: fromOrToIds }],
  }];
  const filters = {
    mode: 'and',
    filters: filtersContent,
    filterGroups: [],
  };
  const foundRelations = [];
  const callback = async (hits) => {
    const preparedElements = [];
    hits.forEach((hit) => {
      if (!cache.has(hit.internal_id)) {
        foundRelations.push(hit.internal_id);
        cache.set(hit.internal_id, '');
      }
      preparedElements.push({ ...hit, level });
    });
    elements.unshift(...preparedElements);
  };
  const finalOpts = { ...opts, filters, callback, types: [ABSTRACT_BASIC_RELATIONSHIP] };
  await elList(context, user, READ_RELATIONSHIPS_INDICES, finalOpts);
  // If relations find, need to recurs to find relations to relations
  if (foundRelations.length > 0) {
    const groups = R.splitEvery(MAX_BULK_OPERATIONS, foundRelations);
    const concurrentFetch = (gIds) => getRelatedRelations(context, user, gIds, elements, level + 1, cache, opts);
    await BluePromise.map(groups, concurrentFetch, { concurrency: ES_MAX_CONCURRENCY });
  }
};
export const getRelationsToRemove = async (context, user, elements, opts = {}) => {
  const relationsToRemoveMap = new Map();
  const relationsToRemove = [];
  const ids = elements.map((e) => e.internal_id);
  await getRelatedRelations(context, user, ids, relationsToRemove, 0, relationsToRemoveMap, opts);
  return { relations: R.flatten(relationsToRemove), relationsToRemoveMap };
};
export const elDeleteInstances = async (instances, opts = {}) => {
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
export const elRemoveRelationConnection = async (context, user, elementsImpact, opts = {}) => {
  const { forceRefresh = true } = opts;
  const impacts = Object.entries(elementsImpact);
  if (impacts.length > 0) {
    const idsToResolve = impacts.map(([k]) => k);
    const dataIds = await elFindByIds(context, user, idsToResolve, { baseData: true, baseFields: ['pir_information'] });
    // Build cache for rest of execution
    const elIdsCache = {};
    const indexCache = {};
    const pirInformationCache = {};
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
          const updates = [];
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

export const computeDeleteElementsImpacts = async (cleanupRelations, toBeRemovedIds, relationsToRemoveMap) => {
  // Update all rel connections that will remain
  const elementsImpact = {};
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

export const elReindexElements = async (context, user, ids, sourceIndex, destIndex, opts = {}) => {
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
            values: ids
          }
        }
      },
      dest: {
        index: destIndex
      },
      script: { // remove old fields that are not mapped anymore but can be present in DB
        params: { changes: sourceUpdate, replaceId: !!dbId, newId: dbId },
        source,
      },
    },
    refresh: true
  };
  return engine.reindex(reindexParams).catch((err) => {
    throw DatabaseError(`Reindexing fail from ${sourceIndex} to ${destIndex}`, { cause: err, body: reindexParams.body });
  });
};

export const elRemoveDraftIdFromElements = async (context, user, draftId, elementsIds) => {
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
            'id.keyword': elementsIds
          }
        },
      },
    }).catch((err) => {
      throw DatabaseError('Revert live entities indexing fail', { cause: err });
    });
  }
};

const elCopyRelationsTargetsToDraft = async (context, user, elements) => {
  const draftContext = getDraftContext(context, user);
  if (!draftContext) {
    return;
  }
  for (let i = 0; i < elements.length; i += 1) {
    const e = elements[i];
    if (e.base_type === BASE_TYPE_RELATION) {
      const { from, fromId, to, toId } = e;
      const resolvedFrom = from ?? await elLoadById(context, user, fromId, { includeDeletedInDraft: true });
      const draftFrom = await loadDraftElement(context, user, resolvedFrom);
      e.from = draftFrom;
      e.fromId = draftFrom.id;
      const resolvedTo = to ?? await elLoadById(context, user, toId, { includeDeletedInDraft: true });
      const draftTo = await loadDraftElement(context, user, resolvedTo);
      e.to = draftTo;
      e.toId = draftTo.id;
    }
  }
};

export const elMarkElementsAsDraftDelete = async (context, user, elements) => {
  if (elements.some((e) => !isDraftSupportedEntity(e))) throw UnsupportedError('Cannot delete unsupported element in draft context', { elements });

  // 01. Remove all elements that are draft creations, mark as delete for others
  const liveElements = elements.filter((f) => !isDraftIndex(f._index));
  const draftCreatedElements = elements.filter((f) => isDraftIndex(f._index) && f.draft_change.draft_operation === DRAFT_OPERATION_CREATE);
  const draftNonCreatedElements = elements.filter((f) => isDraftIndex(f._index) && f.draft_change.draft_operation !== DRAFT_OPERATION_CREATE);

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
  const draftCreatedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change.draft_operation === DRAFT_OPERATION_CREATE);
  const draftNonCreatedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change.draft_operation !== DRAFT_OPERATION_CREATE);

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
  const basicCleanup = elements.filter((f) => isBasicRelationship(f.entity_type));
  // Update all rel connections that will remain
  const cleanupRelations = relations.concat(basicCleanup);
  const toBeRemovedIds = elements.map((e) => e.internal_id);
  const elementsImpact = await computeDeleteElementsImpacts(cleanupRelations, toBeRemovedIds, relationsToRemoveMap);
  await elRemoveRelationConnection(context, user, elementsImpact);
};

export const elDeleteElements = async (context, user, elements, opts = {}) => {
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
  const basicCleanup = elements.filter((f) => isBasicRelationship(f.entity_type));
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
    const reindexPromises = [];
    [...idsByIndex.keys()].forEach((sourceIndex) => {
      const ids = idsByIndex.get(sourceIndex);
      reindexPromises.push(elReindexElements(context, user, ids, sourceIndex, INDEX_DELETED_OBJECTS));
    });
    await Promise.all(reindexPromises);
    await createDeleteOperationElement(context, user, elements[0], entitiesToDelete);
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

const createDeleteOperationElement = async (context, user, mainElement, deletedElements) => {
  // We currently only handle deleteOperations of 1 element
  const deleteOperationDeletedElements = deletedElements.map((e) => ({ id: e.internal_id, source_index: e._index }));
  const deleteOperationInput = {
    entity_type: ENTITY_TYPE_DELETE_OPERATION,
    main_entity_type: mainElement.entity_type,
    main_entity_id: mainElement.internal_id,
    main_entity_name: extractRepresentative(mainElement).main ?? mainElement.internal_id,
    deleted_elements: deleteOperationDeletedElements,
    confidence: mainElement.confidence ?? 100,
    objectMarking: mainElement.objectMarking ?? [], // we retrieve resolved objectMarking if it exists
    objectOrganization: mainElement.objectOrganization ?? [], // we retrieve resolved objectOrganization if it exists
  };
  const { element, relations } = await buildEntityData(context, user, deleteOperationInput, ENTITY_TYPE_DELETE_OPERATION);

  await elIndexElements(context, user, ENTITY_TYPE_DELETE_OPERATION, [element, ...(relations ?? [])]);
};

// TODO: get rid of this function and let elastic fail queries, so we can fix all of them by using the right type of data
export const prepareElementForIndexing = async (element) => {
  const thing = {};
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
const prepareRelation = (thing) => {
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
const prepareEntity = (thing) => {
  return R.pipe(R.dissoc(INTERNAL_TO_FIELD), R.dissoc(INTERNAL_FROM_FIELD))(thing);
};
const prepareIndexingElement = async (thing) => {
  if (thing.base_type === BASE_TYPE_RELATION) {
    const relation = prepareRelation(thing);
    return prepareElementForIndexing(relation);
  }
  const entity = prepareEntity(thing);
  return prepareElementForIndexing(entity);
};
const prepareIndexing = async (context, user, elements) => {
  const draftContext = getDraftContext(context, user);
  const preparedElements = [];
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    if (draftContext) {
      // If we are in a draft, relations from and to need to be elements that are also in draft.
      if (element.base_type === BASE_TYPE_RELATION) {
        const { from, to } = element;
        if (!elements.some((e) => e.internal_id === from.internal_id)) {
          const draftFrom = await loadDraftElement(context, user, from);
          element.from = draftFrom;
          element.fromId = draftFrom.id;
        } else {
          element.from._index = INDEX_DRAFT_OBJECTS;
        }
        if (!elements.some((e) => e.internal_id === to.internal_id)) {
          const draftTo = await loadDraftElement(context, user, to);
          element.to = draftTo;
          element.toId = draftTo.id;
        } else {
          element.to._index = INDEX_DRAFT_OBJECTS;
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
export const elListExistingDraftWorkspaces = async (context, user) => {
  const listArgs = {
    filters: { mode: FilterMode.And, filters: [{ key: ['entity_type'], values: [ENTITY_TYPE_DRAFT_WORKSPACE] }], filterGroups: [] }
  };
  return elList(context, user, READ_INDEX_INTERNAL_OBJECTS, listArgs);
};
// Creates a copy of a live element in the draft index with the current draft context
export const copyLiveElementToDraft = async (context, user, element, draftOperation = DRAFT_OPERATION_UPDATE_LINKED) => {
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
      params: { allDraftIds }
    }
  };
  await elUpdate(element._index, element.internal_id, addDraftIdScript);

  return updatedElement;
};
// Gets the version of the element in current draft context if it exists
// If it doesn't exist, creates a copy of live element to draft context then returns it
const draftCopyLockPrefix = 'draft_copy';
export const loadDraftElement = async (context, user, element) => {
  if (isDraftIndex(element._index) || !isDraftSupportedEntity(element)) return element;

  let lock;
  const currentDraft = getDraftContext(context, user);
  const lockKey = `${draftCopyLockPrefix}_${currentDraft}_${element.internal_id}`;
  try {
    lock = await lockResources([lockKey]);
    const loadedElement = await elLoadById(context, user, element.internal_id);
    if (loadedElement && isDraftIndex(loadedElement._index)) return loadedElement;

    return await copyLiveElementToDraft(context, user, element);
  } catch (e) {
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
const validateElementsToIndex = (context, user, elements) => {
  const draftContext = getDraftContext(context, user);
  // If any element to index is not supported in draft, raise exception
  if (draftContext && elements.some((e) => !isDraftSupportedEntity(e))) throw UnsupportedError('Cannot index unsupported element in draft context');
};
export const elIndexElements = async (context, user, indexingType, elements) => {
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
    const cache = {};
    const impactedEntities = R.pipe(
      R.filter((e) => e.base_type === BASE_TYPE_RELATION),
      R.map((e) => {
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
            const { pir_score } = e;
            impacts.push({ refField, from: e.fromId, relationshipType, to: e.to, type: e.from.entity_type, side: 'from', pir_score });
          } else {
            impacts.push({ refField, from: e.fromId, relationshipType, to: e.to, type: e.from.entity_type, side: 'from' });
          }
        }
        if (isImpactedRole(relationshipType, fromType, toType, toRole)) {
          impacts.push({ refField, from: e.toId, relationshipType, to: e.from, type: e.to.entity_type, side: 'to' });
        }
        return impacts;
      }),
      R.flatten,
      R.groupBy((i) => i.from)
    )(elements);
    const elementsToUpdate = Object.keys(impactedEntities).map((entityId) => {
      const entity = cache[entityId];
      const targets = impactedEntities[entityId];
      // Build document fields to update ( per relation type )
      const targetsByRelation = R.groupBy((i) => `${i.relationshipType}|${i.refField}`, targets);
      const targetsElements = Object.keys(targetsByRelation).map((relTypeAndField) => {
        const [relType, refField] = relTypeAndField.split('|');
        const data = targetsByRelation[relTypeAndField];
        const resolvedData = data.map((d) => {
          return { id: d.to.internal_id, side: d.side, type: d.type, pir_score: d.pir_score };
        });
        return { relation: relType, field: refField, elements: resolvedData };
      });
      // Create params and scripted update
      const params = { updated_at: now() };
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
        const fromSide = t.elements.find((e) => e.side === 'from');

        const toSide = t.elements.find((e) => e.side === 'to');
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
        params[buildRefRelationKey(targetElement.relation, targetElement.field)] = targetElement.elements.map((e) => e.id);
      }
      // Add new_pir_information params
      const pirElements = targetsElements.filter((e) => e.relation === RELATION_IN_PIR);
      for (let index = 0; index < pirElements.length; index += 1) {
        const pirElement = pirElements[index];
        params.new_pir_information = pirElement.elements
          .map((e) => ({
            pir_id: e.id,
            pir_score: e.pir_score,
            last_pir_score_date: params.updated_at,
          }));
        params.pir_ids = pirElement.elements.map((e) => e.id);
      }
      return { ...entity, id: entityId, data: { script: { source, params } } };
    });
    // bulk update elements (denormalized relations)
    if (elementsToUpdate.length > 0) {
      const groupsOfElementsToUpdate = R.splitEvery(MAX_BULK_OPERATIONS, elementsToUpdate);
      for (let i = 0; i < groupsOfElementsToUpdate.length; i += 1) {
        const elementsBulk = groupsOfElementsToUpdate[i];
        const bodyUpdate = elementsBulk.flatMap((doc) => [
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

export const elUpdateRelationConnections = async (elements) => {
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
export const elUpdateEntityConnections = async (elements) => {
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
    const addMultipleFormat = (doc) => {
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
              to: addMultipleFormat(doc)
            },
          },
        },
      ];
    });
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
  }
};

const elUpdateConnectionsOfElement = async (documentId, documentBody) => {
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

const getInstanceToUpdate = async (context, user, instance) => {
  const draftContext = getDraftContext(context, user);
  // We still want to be able to update internal entities in draft, but we don't want to copy them to draft index
  if (draftContext && isDraftSupportedEntity(instance)) {
    return await loadDraftElement(context, user, instance);
  }
  return instance;
};
export const elUpdateElement = async (context, user, instance) => {
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
  return engine.indices
    .stats({ index: indices }) //
    .then((result) => oebp(result)._all.primaries);
};
