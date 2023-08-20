/* eslint-disable no-underscore-dangle */
import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import semver from 'semver';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import {
  buildPagination,
  cursorToOffset,
  ES_INDEX_PREFIX,
  extractEntityRepresentative,
  isInferredIndex,
  isNotEmptyField,
  offsetToCursor,
  pascalize,
  READ_DATA_INDICES,
  READ_ENTITIES_INDICES,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_PLATFORM_INDICES,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  waitInSec,
  WRITE_PLATFORM_INDICES,
} from './utils';
import conf, { booleanConf, loadCert, logApp } from '../config/conf';
import {
  ConfigurationError,
  DatabaseError,
  EngineShardsError,
  FunctionalError,
  UnsupportedError
} from '../config/errors';
import {
  isStixRefRelationship,
  RELATION_CREATED_BY,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING, RELATION_OBJECT_PARTICIPANT,
} from '../schema/stixRefRelationship';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  buildRefRelationSearchKey,
  ENTITY_TYPE_IDENTITY,
  ID_INFERRED,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INTERNAL_IDS_ALIASES,
  isAbstract,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
} from '../schema/general';
import { isModifiedObject, isUpdatedAtObject, } from '../schema/fieldDataAdapter';
import { getParentTypes } from '../schema/schemaUtils';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_DESCRIPTION,
  ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  isStixObjectAliased,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import { isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationshipExceptRef } from '../schema/stixRelationship';
import { RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { INTERNAL_FROM_FIELD, INTERNAL_TO_FIELD } from '../schema/identifier';
import {
  BYPASS,
  computeUserMemberAccessIds,
  INTERNAL_USERS,
  isBypassUser,
  MEMBER_ACCESS_ALL,
} from '../utils/access';
import { isSingleRelationsRef, } from '../schema/stixEmbeddedRelationship';
import { now, runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEntityFromCache } from './cache';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { telemetry } from '../config/tracing';
import { isBooleanAttribute, isDateAttribute, isDateNumericOrBooleanAttribute } from '../schema/schema-attributes';
import { convertTypeToStixType } from './stix-converter';

const ELK_ENGINE = 'elk';
const OPENSEARCH_ENGINE = 'opensearch';
export const ES_MAX_CONCURRENCY = conf.get('elasticsearch:max_concurrency');
export const ES_IGNORE_THROTTLED = conf.get('elasticsearch:search_ignore_throttled');
export const ES_MAX_PAGINATION = conf.get('elasticsearch:max_pagination_result');
const ES_INDEX_PATTERN_SUFFIX = conf.get('elasticsearch:index_creation_pattern');
const ES_MAX_RESULT_WINDOW = conf.get('elasticsearch:max_result_window') || 100000;
const ES_MAX_SHARDS_FAILURE = conf.get('elasticsearch:max_shards_failure') || 0;
const ES_INDEX_SHARD_NUMBER = conf.get('elasticsearch:number_of_shards');
const ES_INDEX_REPLICA_NUMBER = conf.get('elasticsearch:number_of_replicas');

const ES_PRIMARY_SHARD_SIZE = conf.get('elasticsearch:max_primary_shard_size') || '50gb';
const ES_MAX_AGE = conf.get('elasticsearch:max_age') || '365d';
const ES_MAX_DOCS = conf.get('elasticsearch:max_docs') || 75000000;

const ES_RETRY_ON_CONFLICT = 5;
export const MAX_TERMS_SPLIT = 65000; // By default, Elasticsearch limits the terms query to a maximum of 65,536 terms. You can change this limit using the index.
export const MAX_BULK_OPERATIONS = 250;
export const BULK_TIMEOUT = '5m';
const MAX_AGGREGATION_SIZE = 100;
const MAX_JS_PARAMS = 65536; // Too prevent Maximum call stack size exceeded
const MAX_SEARCH_AGGREGATION_SIZE = 10000;
const MAX_SEARCH_SIZE = 5000;
export const ROLE_FROM = 'from';
export const ROLE_TO = 'to';
const NO_MAPPING_FOUND_ERROR = 'No mapping found';
const NO_SUCH_INDEX_ERROR = 'no such index';
const UNIMPACTED_ENTITIES_ROLE = [
  `${RELATION_CREATED_BY}_${ROLE_TO}`,
  `${RELATION_OBJECT_MARKING}_${ROLE_TO}`,
  `${RELATION_OBJECT_ASSIGNEE}_${ROLE_TO}`,
  `${RELATION_OBJECT_PARTICIPANT}_${ROLE_TO}`,
  `${RELATION_GRANTED_TO}_${ROLE_TO}`,
  `${RELATION_OBJECT_LABEL}_${ROLE_TO}`,
  `${RELATION_KILL_CHAIN_PHASE}_${ROLE_TO}`,
  // RELATION_OBJECT
  // RELATION_EXTERNAL_REFERENCE
  `${RELATION_INDICATES}_${ROLE_TO}`,
];
export const isImpactedTypeAndSide = (type, side) => {
  return !UNIMPACTED_ENTITIES_ROLE.includes(`${type}_${side}`);
};
export const isImpactedRole = (role) => !UNIMPACTED_ENTITIES_ROLE.includes(role);

const ca = conf.get('elasticsearch:ssl:ca')
  ? loadCert(conf.get('elasticsearch:ssl:ca'))
  : conf.get('elasticsearch:ssl:ca_plain') || null;

const searchConfiguration = {
  node: conf.get('elasticsearch:url'),
  proxy: conf.get('elasticsearch:proxy') || null,
  auth: {
    username: conf.get('elasticsearch:username') || null,
    password: conf.get('elasticsearch:password') || null,
    apiKey: conf.get('elasticsearch:api_key') || null,
  },
  maxRetries: conf.get('elasticsearch:max_retries') || 3,
  requestTimeout: conf.get('elasticsearch:request_timeout') || 30000,
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

const elasticSearchClient = new ElkClient(searchConfiguration);
const openSearchClient = new OpenClient(searchConfiguration);
let isRuntimeSortingEnable = false;
let engine = openSearchClient;

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
      /* istanbul ignore next */ (e) => {
        throw ConfigurationError('[SEARCH] Search engine seems down', { error: e.message });
      }
    );
  const searchPlatform = searchInfo.distribution || ELK_ENGINE; // openSearch or elasticSearch
  const searchVersion = searchInfo.number;
  const localEngine = searchPlatform === ELK_ENGINE ? elasticSearchClient : openSearchClient;
  return { platform: searchPlatform, version: searchVersion, engine: localEngine };
};

export const searchEngineInit = async () => {
  // Select the correct engine
  const engineSelector = conf.get('elasticsearch:engine_selector') || 'auto';
  let engineVersion;
  let enginePlatform;
  if (engineSelector === ELK_ENGINE) {
    logApp.info(`[SEARCH] Engine ${ELK_ENGINE} client selected by configuration`);
    engine = elasticSearchClient;
    const searchVersion = await searchEngineVersion();
    if (searchVersion.platform !== ELK_ENGINE) {
      throw ConfigurationError(`[SEARCH] Invalid Search engine selector, configured to ${engineSelector}, detected to ${searchVersion.platform}`);
    }
    enginePlatform = ELK_ENGINE;
    engineVersion = searchVersion.version;
  } else if (engineSelector === OPENSEARCH_ENGINE) {
    logApp.info(`[SEARCH] Engine ${OPENSEARCH_ENGINE} client selected by configuration`);
    engine = openSearchClient;
    const searchVersion = await searchEngineVersion();
    if (searchVersion.platform !== OPENSEARCH_ENGINE) {
      throw ConfigurationError(`[SEARCH] Invalid Search engine selector, configured to ${engineSelector}, detected to ${searchVersion.platform}`);
    }
    enginePlatform = OPENSEARCH_ENGINE;
    engineVersion = searchVersion.version;
  } else {
    logApp.info(`[SEARCH] Engine client not specified, trying to discover it with ${OPENSEARCH_ENGINE} client`);
    engine = openSearchClient;
    const searchVersion = await searchEngineVersion();
    enginePlatform = searchVersion.platform;
    logApp.info(`[SEARCH] Engine detected to ${enginePlatform}`);
    engine = searchVersion.engine;
    engineVersion = searchVersion.version;
  }
  // Setup the platform runtime field option
  isRuntimeSortingEnable = enginePlatform === ELK_ENGINE && semver.satisfies(engineVersion, '>=7.12.x');
  const runtimeStatus = isRuntimeSortingEnable ? 'enabled' : 'disabled';
  logApp.info(`[SEARCH] ${enginePlatform} (${engineVersion}) client selected / runtime sorting ${runtimeStatus}`);
  // Everything is fine, return true
  return true;
};
export const isRuntimeSortEnable = () => isRuntimeSortingEnable;

export const elRawSearch = (context, user, types, query) => {
  const elRawSearchFn = async () => engine.search(query).then((r) => {
    const parsedSearch = oebp(r);
    // If some shards fail
    if (parsedSearch._shards.failed > 0) {
      // We need to filter "No mapping found" errors that are not real problematic shard problems
      // As we do not define all mappings and let elastic create it dynamically at first creation
      // This failure is transient until the first creation of some data
      const failures = (parsedSearch._shards.failures ?? [])
        .filter((f) => !f.reason?.reason.includes(NO_MAPPING_FOUND_ERROR));
      if (failures.length > ES_MAX_SHARDS_FAILURE) {
        // We do not support response with shards failure.
        // Result must be always accurate to prevent data duplication and unwanted behaviors
        // If any shard fail during query, engine throw a lock exception with shards information
        throw EngineShardsError({ shards: parsedSearch._shards });
      } else if (failures.length > 0) {
        // At least log the situation
        const message = `[SEARCH] Search meet ${failures.length} shards failure, please check your configuration`;
        logApp.error(message, { shards: parsedSearch._shards });
      }
    }
    // Return result of the search if everything goes well
    return parsedSearch;
  });
  return telemetry(context, user, `SELECT ${Array.isArray(types) ? types.join(', ') : (types || 'None')}`, {
    [SemanticAttributes.DB_NAME]: 'search_engine',
    [SemanticAttributes.DB_OPERATION]: 'read',
    [SemanticAttributes.DB_STATEMENT]: JSON.stringify(query),
  }, elRawSearchFn);
};
export const elRawDeleteByQuery = (query) => engine.deleteByQuery(query).then((r) => oebp(r));
export const elRawBulk = (args) => engine.bulk(args).then((r) => oebp(r));
export const elRawUpdateByQuery = (query) => engine.updateByQuery(query).then((r) => oebp(r));
const elGetTask = (taskId) => engine.tasks.get({ task_id: taskId }).then((r) => oebp(r));
export const elUpdateByQueryForMigration = async (message, index, body) => {
  logApp.info(`${message} > started`);
  // Execute the update by query in async mode
  const queryAsync = await elRawUpdateByQuery({
    index,
    refresh: true,
    wait_for_completion: false,
    body
  }).catch((err) => {
    throw DatabaseError(`${message} > elastic error (migration)`, { error: err });
  });
  logApp.info(`${message} > elastic running task ${queryAsync.task}`);
  // Wait 10 seconds for task to initialize
  await waitInSec(10);
  // Monitor the task until completion
  let taskStatus = await elGetTask(queryAsync.task);
  while (!taskStatus.completed) {
    const { total, updated } = taskStatus.task.status;
    logApp.info(`${message} > in progress - ${updated}/${total}`);
    await waitInSec(5);
    taskStatus = await elGetTask(queryAsync.task);
  }
  const timeSec = Math.round(taskStatus.task.running_time_in_nanos / 1e9);
  logApp.info(`${message} > done in ${timeSec} seconds`);
};

const buildDataRestrictions = async (context, user, opts = {}) => {
  const must = [];
  // eslint-disable-next-line camelcase
  const must_not = [];
  // If internal users of the system, we cancel rights checking
  if (INTERNAL_USERS[user.id]) {
    return { must, must_not };
  }
  // check user access
  must.push(...buildUserMemberAccessFilter(user, opts?.includeAuthorities));
  // If user have bypass, no need to check restrictions
  if (!isBypassUser(user)) {
    // region Handle marking restrictions
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Markings should be grouped by types for restriction
      const userGroupedMarkings = R.groupBy((m) => m.definition_type, user.allowed_marking);
      const allGroupedMarkings = R.groupBy((m) => m.definition_type, user.all_marking);
      const markingGroups = Object.keys(allGroupedMarkings);
      const mustNotHaveOneOf = [];
      for (let index = 0; index < markingGroups.length; index += 1) {
        const markingGroup = markingGroups[index];
        const markingsForGroup = allGroupedMarkings[markingGroup].map((i) => i.internal_id);
        const userMarkingsForGroup = (userGroupedMarkings[markingGroup] || []).map((i) => i.internal_id);
        // Get all markings the user has no access for this group
        const res = markingsForGroup.filter((m) => !userMarkingsForGroup.includes(m));
        if (res.length > 0) {
          mustNotHaveOneOf.push(res);
        }
      }
      // If use have marking, he can access to data with no marking && data with according marking
      const mustNotMarkingTerms = [];
      for (let i = 0; i < mustNotHaveOneOf.length; i += 1) {
        const markings = mustNotHaveOneOf[i];
        const should = markings.map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: m } }));
        mustNotMarkingTerms.push({
          bool: {
            should,
            minimum_should_match: 1,
          },
        });
      }
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
    const excludedEntityMatches = STIX_ORGANIZATIONS_UNRESTRICTED
      .map((t) => [{ match: { 'parent_types.keyword': t } }, { match_phrase: { 'entity_type.keyword': t } }])
      .flat();
    if (settings.platform_organization) {
      if (user.inside_platform_organization) {
        // Data are visible independently of the organizations
        // Nothing to restrict.
      } else {
        // Data with Empty granted_refs are not visible
        // Data with granted_refs users that participate to at least one
        const should = [...excludedEntityMatches];
        const shouldOrgs = user.allowed_organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        should.push(...shouldOrgs);
        // User individual or data created by this individual must be accessible
        if (user.individual_id) {
          should.push({ match: { 'internal_id.keyword': user.individual_id } });
          should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
        }
        // Finally build the bool should search
        must.push({ bool: { should, minimum_should_match: 1 } });
      }
    } else {
      // Data with Empty granted_refs are granted to everyone
      const should = [...excludedEntityMatches];
      should.push({ bool: { must_not: [{ exists: { field: buildRefRelationSearchKey(RELATION_GRANTED_TO) } }] } });
      // Data with granted_refs users that participate to at least one
      if (user.allowed_organizations.length > 0) {
        const shouldOrgs = user.allowed_organizations
          .map((m) => ({ match: { [buildRefRelationSearchKey(RELATION_GRANTED_TO)]: m.internal_id } }));
        should.push(...shouldOrgs);
      }
      // User individual or data created by this individual must be accessible
      if (user.individual_id) {
        should.push({ match: { 'internal_id.keyword': user.individual_id } });
        should.push({ match: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: user.individual_id } });
      }
      // Finally build the bool should search
      must.push({ bool: { should, minimum_should_match: 1 } });
    }
    // endregion
  }
  return { must, must_not };
};

export const buildUserMemberAccessFilter = (user, includeAuthorities = false) => {
  const capabilities = user.capabilities.map((c) => c.name);
  if (includeAuthorities && capabilities.includes(BYPASS)) {
    return [];
  }
  const userAccessIds = computeUserMemberAccessIds(user);
  // if access_users exists, it should have the user access ids
  const authorizedFilters = [
    { bool: { must_not: { exists: { field: 'authorized_members' } } } },
    { terms: { 'authorized_members.id.keyword': [MEMBER_ACCESS_ALL, ...userAccessIds] } },
  ];
  if (includeAuthorities) {
    const roleIds = user.roles.map((r) => r.id);
    const owners = [...userAccessIds, ...capabilities, ...roleIds];
    authorizedFilters.push({ terms: { 'authorized_authorities.keyword': owners } });
  }
  return [{ bool: { should: authorizedFilters } }];
};

export const elIndexExists = async (indexName) => {
  const existIndex = await engine.indices.exists({ index: indexName });
  return oebp(existIndex) === true;
};
export const elPlatformIndices = async () => {
  const listIndices = await engine.cat.indices({ index: `${ES_INDEX_PREFIX}*`, format: 'JSON' });
  return oebp(listIndices);
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
                  max_age: ES_MAX_AGE,
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
      throw DatabaseError('[SEARCH] Error creating lifecycle policy', { error: e });
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
                    min_index_age: ES_MAX_AGE,
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
      } }).catch((e) => {
      throw DatabaseError('[SEARCH] Error creating lifecycle policy', { error: e });
    });
  }
};
const elCreateCoreSettings = async () => {
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
    throw DatabaseError('[SEARCH] Error creating component template', { error: e });
  });
};
const elCreateIndexTemplate = async (index) => {
  let settings;
  if (engine instanceof ElkClient) {
    settings = {
      index: {
        lifecycle: {
          name: `${ES_INDEX_PREFIX}-ilm-policy`,
          rollover_alias: index,
        }
      }
    };
  } else {
    settings = {
      plugins: {
        index_state_management: {
          rollover_alias: index,
        }
      }
    };
  }
  await engine.indices.putIndexTemplate({
    name: index,
    create: false,
    body: {
      index_patterns: [`${index}*`],
      template: {
        settings,
        mappings: {
          dynamic_templates: [
            {
              integers: {
                match_mapping_type: 'long',
                mapping: {
                  type: 'integer',
                },
              },
            },
            {
              strings: {
                match_mapping_type: 'string',
                mapping: {
                  type: 'text',
                  fields: {
                    keyword: {
                      type: 'keyword',
                      normalizer: 'string_normalizer',
                      ignore_above: 512,
                    },
                  },
                },
              },
            },
          ],
          properties: {
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
          },
        },
      },
      composed_of: [`${ES_INDEX_PREFIX}-core-settings`],
      version: 3,
      _meta: {
        description: 'To generate opencti expected index mappings',
      },
    },
  }).catch((e) => {
    throw DatabaseError('[SEARCH] Error creating index template', { error: e });
  });
};
export const elCreateIndices = async (indexesToCreate = WRITE_PLATFORM_INDICES) => {
  await elCreateCoreSettings();
  await elCreateLifecyclePolicy();
  const createdIndices = [];
  for (let i = 0; i < indexesToCreate.length; i += 1) {
    const index = indexesToCreate[i];
    await elCreateIndexTemplate(index);
    const indexName = `${index}${ES_INDEX_PATTERN_SUFFIX}`;
    const isExist = await engine.indices.exists({ index: indexName }).then((r) => oebp(r));
    if (!isExist) {
      const createdIndex = await engine.indices.create({ index: indexName, body: { aliases: { [index]: {} } } });
      createdIndices.push(oebp(createdIndex));
    }
  }
  return createdIndices;
};
export const elDeleteIndices = async (indexesToDelete) => {
  return Promise.all(
    indexesToDelete.map((index) => {
      return engine.indices.delete({ index })
        .then((response) => oebp(response))
        .catch((err) => {
          /* istanbul ignore next */
          if (err.meta.body && err.meta.body.error.type !== 'index_not_found_exception') {
            logApp.error('[SEARCH] Delete indices fail', { error: err });
          }
        });
    })
  );
};

export const RUNTIME_ATTRIBUTES = {
  observable_value: {
    field: 'observable_value.keyword',
    type: 'keyword',
    getSource: async () => runtimeFieldObservableValueScript(),
    getParams: async () => {
    },
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
    getParams: async (context, user) => {
      // eslint-disable-next-line no-use-before-define
      const identities = await elPaginate(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
        types: [ENTITY_TYPE_IDENTITY],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.name })));
    },
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
    getParams: async (context, user) => {
      // eslint-disable-next-line no-use-before-define
      const users = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_USER],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(users.map((i) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
    },
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
    getParams: async (context, user) => {
      // eslint-disable-next-line no-use-before-define
      const identities = await elPaginate(context, user, READ_ENTITIES_INDICES, {
        types: [ENTITY_TYPE_MARKING_DEFINITION],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.definition })));
    },
  },
  assigneeTo: {
    field: 'assigneeTo.keyword',
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
    getParams: async (context, user) => {
      // eslint-disable-next-line no-use-before-define
      const users = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_USER],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(users.map((i) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
    },
  },
  participant: {
    field: 'participant.keyword',
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
    getParams: async (context, user) => {
      // eslint-disable-next-line no-use-before-define
      const users = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
        types: [ENTITY_TYPE_USER],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(users.map((i) => ({ [i.internal_id]: i.name.replace(/[&/\\#,+[\]()$~%.'":*?<>{}]/g, '') })));
    },
  },
};

// region relation reconstruction
const elBuildRelation = (type, connection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: R.head(connection.types),
  };
};
const elMergeRelation = (concept, fromConnection, toConnection) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('[SEARCH] Something failed in reconstruction of the relation', concept.internal_id);
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
const elDataConverter = (esHit, withoutRels = false) => {
  const elementData = esHit._source;
  const data = {
    _index: esHit._index,
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
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
      if (withoutRels) {
        delete data[key];
      } else {
        const rel = key.substring(REL_INDEX_PREFIX.length);
        const [relType] = rel.split('.');
        data[relType] = isSingleRelationsRef(data.entity_type, relType) ? R.head(val) : [...(data[relType] ?? []), ...val];
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

export const elFindByFromAndTo = async (context, user, fromId, toId, relationshipType) => {
  const mustTerms = [];
  const markingRestrictions = await buildDataRestrictions(context, user);
  mustTerms.push(...markingRestrictions.must);
  mustTerms.push({
    nested: {
      path: 'connections',
      query: {
        bool: {
          must: [{ match_phrase: { 'connections.internal_id.keyword': fromId } }],
        },
      },
    },
  });
  mustTerms.push({
    nested: {
      path: 'connections',
      query: {
        bool: {
          must: [{ match_phrase: { 'connections.internal_id.keyword': toId } }],
        },
      },
    },
  });
  mustTerms.push({
    bool: {
      should: [
        { match_phrase: { 'entity_type.keyword': relationshipType } },
        { match_phrase: { 'parent_types.keyword': relationshipType } },
      ],
      minimum_should_match: 1,
    },
  });
  const query = {
    index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    size: MAX_SEARCH_SIZE,
    ignore_throttled: ES_IGNORE_THROTTLED,
    body: {
      query: {
        bool: {
          must: mustTerms,
          must_not: markingRestrictions.must_not,
        },
      },
    },
  };
  const data = await elRawSearch(context, user, relationshipType, query).catch((e) => {
    throw DatabaseError('[SEARCH] Find by from and to fail', { error: e, query });
  });
  const hits = [];
  for (let index = 0; index < data.hits.hits.length; index += 1) {
    const hit = data.hits.hits[index];
    hits.push(elDataConverter(hit));
  }
  return hits;
};

export const elFindByIds = async (context, user, ids, opts = {}) => {
  const { indices = READ_DATA_INDICES, baseData = false, baseFields = BASE_FIELDS } = opts;
  const { withoutRels = false, toMap = false, type = null, forceAliases = false } = opts;
  const idsArray = Array.isArray(ids) ? ids : [ids];
  const types = (Array.isArray(type) || !type) ? type : [type];
  const processIds = R.filter((id) => isNotEmptyField(id), idsArray);
  if (processIds.length === 0) {
    return toMap ? {} : [];
  }
  const hits = {};
  const groupIds = R.splitEvery(MAX_TERMS_SPLIT, idsArray);
  for (let index = 0; index < groupIds.length; index += 1) {
    const mustTerms = [];
    const workingIds = groupIds[index];
    const idsTermsPerType = [];
    const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
    if ((types || []).some((typeElement) => isStixObjectAliased(typeElement)) || forceAliases) {
      elementTypes.push(INTERNAL_IDS_ALIASES);
    }
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
      const typesShould = types.map((typeShould) => (
        [
          { match_phrase: { 'entity_type.keyword': typeShould } },
          { match_phrase: { 'parent_types.keyword': typeShould } }
        ]
      )).flat();
      const shouldType = {
        bool: {
          should: typesShould,
          minimum_should_match: 1,
        },
      };
      mustTerms.push(shouldType);
    }
    const restrictionOptions = { includeAuthorities: true }; // By default include authorized through capabilities
    // If an admin ask for a specific element, there is no need to ask him to explicitly extends his visibility to doing it.
    const markingRestrictions = await buildDataRestrictions(context, user, restrictionOptions);
    mustTerms.push(...markingRestrictions.must);
    const body = {
      query: {
        bool: {
          must: mustTerms,
          must_not: markingRestrictions.must_not,
        },
      },
    };
    if (opts.orderBy) {
      const orderCriteria = opts.orderBy;
      const isDateOrNumber = isDateNumericOrBooleanAttribute(orderCriteria);
      const orderKey = isDateOrNumber || orderCriteria.startsWith('_') ? orderCriteria : `${orderCriteria}.keyword`;
      body.sort = [{ [orderKey]: (opts.orderMode ?? 'asc') }];
    }
    const query = {
      index: indices,
      size: MAX_SEARCH_SIZE,
      ignore_throttled: ES_IGNORE_THROTTLED,
      _source: baseData ? baseFields : true,
      body,
    };
    logApp.debug('[SEARCH] elInternalLoadById', { query });
    const searchType = `${ids} (${types ? types.join(', ') : 'Any'})`;
    const data = await elRawSearch(context, user, searchType, query).catch((err) => {
      throw DatabaseError('[SEARCH] Error loading ids', { error: err, query });
    });
    for (let j = 0; j < data.hits.hits.length; j += 1) {
      const hit = data.hits.hits[j];
      const element = elDataConverter(hit, withoutRels);
      hits[element.internal_id] = element;
    }
  }
  return toMap ? hits : Object.values(hits);
};

export const elLoadById = async (context, user, id, opts = {}) => {
  const hits = await elFindByIds(context, user, id, opts);
  /* istanbul ignore if */
  if (hits.length > 1) {
    const errorMeta = { id, hits: hits.length };
    throw DatabaseError('[SEARCH] Expect only one response', errorMeta);
  }
  return R.head(hits);
};
export const elBatchIds = async (context, user, ids) => {
  const hits = await elFindByIds(context, user, ids);
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
};

// region elastic common loader.
export const specialElasticCharsEscape = (query) => {
  return query.replace(/([/+|\-*()~={}[\]:?\\])/g, '\\$1');
};

const BASE_SEARCH_CONNECTIONS = [
  // Pounds for connections search
  `connections.${ATTRIBUTE_NAME}^5`,
  // Add all other attributes
  'connections.*',
];
const BASE_SEARCH_ATTRIBUTES = [
  // Pounds for attributes search
  `${ATTRIBUTE_NAME}^5`,
  `${ATTRIBUTE_DESCRIPTION}^2`,
  `${ATTRIBUTE_ABSTRACT}^5`,
  `${ATTRIBUTE_EXPLANATION}^5`,
  // Add all other attributes
  '*',
];
export const elGenerateFullTextSearchShould = (search, args = {}) => {
  const { useWildcardPrefix = false, useWildcardSuffix = true } = args;
  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(search).trim();
  } catch (e) {
    decodedSearch = search.trim();
  }
  let remainingSearch = decodedSearch;
  const exactSearch = (decodedSearch.match(/"[^"]+"/g) || []) //
    .filter((e) => isNotEmptyField(e.replace(/"/g, '').trim()));
  for (let index = 0; index < exactSearch.length; index += 1) {
    remainingSearch = remainingSearch.replace(exactSearch[index], '');
  }
  const querySearch = [];

  const partialSearch = remainingSearch.replace(/"/g, '').trim().split(' ');

  for (let searchIndex = 0; searchIndex < partialSearch.length; searchIndex += 1) {
    const partialElement = partialSearch[searchIndex];
    const cleanElement = specialElasticCharsEscape(partialElement);
    if (isNotEmptyField(cleanElement)) {
      querySearch.push(`${useWildcardPrefix ? '*' : ''}${cleanElement}${useWildcardSuffix ? '*' : ''}`);
    }
  }
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

const BASE_FIELDS = ['_index', 'internal_id', 'standard_id', 'sort', 'base_type', 'entity_type',
  'connections', 'first_seen', 'last_seen', 'start_time', 'stop_time'];
const elQueryBodyBuilder = async (context, user, options) => {
  // eslint-disable-next-line no-use-before-define
  const { ids = [], first = 200, after, orderBy = null, orderMode = 'asc', noSize = false, noSort = false, intervalInclude = false } = options;
  const { types = null, filters = [], filterMode = 'and', search = null } = options;
  const { startDate = null, endDate = null, dateAttribute = null } = options;
  const dateFilter = [];
  const searchAfter = after ? cursorToOffset(after) : undefined;
  let ordering = [];
  const { includeAuthorities = false } = options;
  const markingRestrictions = await buildDataRestrictions(context, user, { includeAuthorities });
  const accessMust = markingRestrictions.must;
  const accessMustNot = markingRestrictions.must_not;
  const mustFilters = [];
  if (ids.length > 0) {
    const idsTermsPerType = [];
    const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
    for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
      const elementType = elementTypes[indexType];
      const terms = { [`${elementType}.keyword`]: ids };
      idsTermsPerType.push({ terms });
    }
    mustFilters.push({ bool: { should: idsTermsPerType, minimum_should_match: 1 } });
  }
  if (startDate && endDate) {
    dateFilter.push({
      range: {
        [dateAttribute || 'created_at']: {
          format: 'strict_date_optional_time',
          [intervalInclude ? 'gte' : 'gt']: startDate,
          [intervalInclude ? 'lte' : 'lt']: endDate,
        },
      },
    });
  } else if (startDate) {
    dateFilter.push({
      range: {
        [dateAttribute || 'created_at']: {
          format: 'strict_date_optional_time',
          [intervalInclude ? 'gte' : 'gt']: startDate,
        },
      },
    });
  } else if (endDate) {
    dateFilter.push({
      range: {
        [dateAttribute || 'created_at']: {
          format: 'strict_date_optional_time',
          [intervalInclude ? 'lte' : 'lt']: endDate,
        },
      },
    });
  }
  mustFilters.push(...dateFilter);
  if (types !== null && types.length > 0) {
    const should = R.flatten(
      types.map((typeValue) => {
        return [
          { match_phrase: { 'entity_type.keyword': typeValue } },
          { match_phrase: { 'parent_types.keyword': typeValue } },
        ];
      })
    );
    mustFilters.push({ bool: { should, minimum_should_match: 1 } });
  }
  const validFilters = R.filter((f) => f?.values?.length > 0 || f?.nested?.length > 0, filters || []);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const noValuesFiltering = [];
      const { key, values, nested, operator = 'eq', filterMode: localFilterMode = 'or' } = validFilters[index];
      const arrayKeys = Array.isArray(key) ? key : [key];
      // in case we want to filter by source reliability (reliability of author)
      // we need to find all authors filtered by reliability and filter on these authors
      const sourceReliabilityFilter = arrayKeys.find((k) => k === 'source_reliability');
      if (sourceReliabilityFilter) {
        const authorTypes = [
          ENTITY_TYPE_IDENTITY_INDIVIDUAL,
          ENTITY_TYPE_IDENTITY_ORGANIZATION,
          ENTITY_TYPE_IDENTITY_SYSTEM
        ];
        const reliabilityFilter = { key: ['x_opencti_reliability'], operator, values, localFilterMode };
        const opts = { types: authorTypes, connectionFormat: false, filters: [reliabilityFilter] };
        const authors = await elList(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
        if (authors.length > 0) {
          arrayKeys.splice(0, 1);
          arrayKeys.push('rel_created-by.internal_id');
          values.splice(0, values.length);
          authors.forEach((author) => values.push(author.internal_id));
        }
      }
      // In case of entity_type filters, we also look by default in the parent_types property.
      const validKeys = R.uniq(arrayKeys.includes('entity_type') ? [...arrayKeys, 'parent_types'] : arrayKeys);
      // TODO IF KEY is PART OF Rule we need to add extra fields search
      // TODO Add connections like filters to have native fromId, toId filters handling.
      // See opencti-front\src\private\components\events\StixSightingRelationships.tsx
      if (nested) {
        if (validKeys.length > 1) {
          throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
        }
        const nestedMust = [];
        const nestedMustNot = [];
        for (let nestIndex = 0; nestIndex < nested.length; nestIndex += 1) {
          const nestedElement = nested[nestIndex];
          const parentKey = validKeys.at(0);
          const { key: nestedKey, values: nestedValues, operator: nestedOperator = 'eq' } = nestedElement;
          const nestedShould = [];
          for (let i = 0; i < nestedValues.length; i += 1) {
            const nestedFieldKey = `${parentKey}.${nestedKey}`;
            const nestedSearchValues = nestedValues[i].toString();
            if (nestedOperator === 'wildcard') {
              nestedShould.push({ query_string: { query: `${nestedSearchValues}`, fields: [nestedFieldKey] } });
            } else if (nestedOperator === 'not_eq') {
              nestedMustNot.push({ match_phrase: { [nestedFieldKey]: nestedSearchValues } });
            } else {
              nestedShould.push({ match_phrase: { [nestedFieldKey]: nestedSearchValues } });
            }
          }
          const should = {
            bool: {
              should: nestedShould,
              minimum_should_match: localFilterMode === 'or' ? 1 : nestedShould.length,
            },
          };
          nestedMust.push(should);
        }
        const nestedQuery = {
          path: R.head(validKeys),
          query: {
            bool: {
              must: nestedMust,
              must_not: nestedMustNot,
            },
          },
        };
        mustFilters.push({ nested: nestedQuery });
      } else {
        for (let i = 0; i < values.length; i += 1) {
          if (values[i] === null) {
            if (validKeys.length > 1) {
              throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
            }
            if (operator === 'eq') {
              valuesFiltering.push({
                bool: {
                  must_not: {
                    exists: {
                      field: R.head(validKeys)
                    }
                  }
                }
              });
            } else if (operator === 'not_eq') {
              valuesFiltering.push({ exists: { field: R.head(validKeys) } });
            }
          } else if (values[i] === 'EXISTS') {
            if (validKeys.length > 1) {
              throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
            }
            valuesFiltering.push({ exists: { field: R.head(validKeys) } });
          } else if (operator === 'eq') {
            valuesFiltering.push({
              multi_match: {
                fields: validKeys.map((k) => `${isDateNumericOrBooleanAttribute(k) ? k : `${k}.keyword`}`),
                query: values[i].toString(),
              },
            });
          } else if (operator === 'not_eq') {
            noValuesFiltering.push({
              multi_match: {
                fields: validKeys.map((k) => `${isDateNumericOrBooleanAttribute(k) ? k : `${k}.keyword`}`),
                query: values[i].toString(),
              },
            });
          } else if (operator === 'match') {
            valuesFiltering.push({
              multi_match: {
                fields: validKeys,
                query: values[i].toString(),
              },
            });
          } else if (operator === 'wildcard') {
            valuesFiltering.push({
              query_string: {
                query: `"${values[i].toString()}"`,
                fields: validKeys,
              },
            });
          } else if (operator === 'script') {
            valuesFiltering.push({
              script: {
                script: values[i].toString()
              },
            });
          } else {
            if (validKeys.length > 1) {
              throw UnsupportedError('[SEARCH] Must have only one field', validKeys);
            }
            valuesFiltering.push({ range: { [R.head(validKeys)]: { [operator]: values[i] } } });
          }
        }
        if (valuesFiltering.length > 0) {
          mustFilters.push(
            {
              bool: {
                should: valuesFiltering,
                minimum_should_match: localFilterMode === 'or' ? 1 : valuesFiltering.length,
              },
            },
          );
        }
        if (noValuesFiltering.length > 0) {
          mustFilters.push(
            {
              bool: {
                should: noValuesFiltering.map((o) => ({
                  bool: {
                    must_not: [o]
                  }
                })),
                minimum_should_match: localFilterMode === 'or' ? 1 : noValuesFiltering.length,
              },
            }
          );
        }
      }
    }
  }
  if (search !== null && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search, options);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    mustFilters.push(bool);
  }
  // Handle orders
  const runtimeMappings = {};
  if (isNotEmptyField(orderBy)) {
    const orderCriterion = Array.isArray(orderBy) ? orderBy : [orderBy];
    for (let index = 0; index < orderCriterion.length; index += 1) {
      const orderCriteria = orderCriterion[index];
      const isDateOrNumber = isDateNumericOrBooleanAttribute(orderCriteria);
      const orderKeyword = isDateOrNumber || orderCriteria.startsWith('_') ? orderCriteria : `${orderCriteria}.keyword`;
      if (orderKeyword === '_score') {
        ordering = R.append({ [orderKeyword]: orderMode }, ordering);
      } else {
        const order = { [orderKeyword]: { order: orderMode, missing: '_last' } };
        ordering = R.append(order, ordering);
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
  } else { // If not ordering criteria, order by _score and standard_id
    ordering.push({ _score: 'desc' });
    ordering.push({ 'standard_id.keyword': 'asc' });
  }
  // Build query
  const querySize = first || 10;
  let mustFiltersWithOperator = mustFilters;
  if (filterMode === 'or') {
    mustFiltersWithOperator = [{ bool: { should: mustFilters, minimum_should_match: 1 } }];
  }
  const body = {
    query: {
      bool: {
        must: [...accessMust, ...mustFiltersWithOperator],
        must_not: accessMustNot,
      },
    },
  };
  if (!noSize) {
    body.size = querySize;
  }
  if (!noSort) {
    body.sort = ordering;
  }
  // Add extra configuration
  if (isNotEmptyField(runtimeMappings)) {
    const isRuntimeSortFeatureEnable = isRuntimeSortEnable();
    if (!isRuntimeSortFeatureEnable) {
      throw UnsupportedError(`[SEARCH] Sorting of field ${orderBy} is only possible with elastic >=7.12`);
    }
    body.runtime_mappings = runtimeMappings;
  }
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  return body;
};
export const elCount = async (context, user, indexName, options = {}) => {
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  const query = { index: indexName, body };
  logApp.debug('[SEARCH] elCount', { query });
  return engine.count(query)
    .then((data) => {
      return oebp(data).count;
    });
};
export const elHistogramCount = async (context, user, indexName, options = {}) => {
  const { interval, field, types = null } = options;
  const body = await elQueryBodyBuilder(context, user, { ...options, dateAttribute: field, noSize: true, noSort: true, intervalInclude: true });
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
      dateFormat = 'yyyy-MM-dd hh:ii:ss';
      break;
    default:
      throw FunctionalError('[SEARCH] Unsupported interval, please choose between year, quarter, month, week, day or hour', interval);
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
    index: indexName,
    ignore_throttled: ES_IGNORE_THROTTLED,
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
  const { field, types = null } = options;
  const isIdFields = field.endsWith('internal_id');
  const body = await elQueryBodyBuilder(context, user, { ...options, noSize: true, noSort: true });
  body.size = MAX_SEARCH_AGGREGATION_SIZE;
  body.aggs = {
    genres: {
      terms: {
        field: isBooleanAttribute(field) ? field : `${field}.keyword`,
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
  const query = {
    index: indexName,
    body,
  };
  logApp.debug('[SEARCH] aggregationCount', { query });
  return elRawSearch(context, user, types, query)
    .then((data) => {
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
    .catch((err) => {
      throw DatabaseError('[SEARCH] Aggregation fail', { error: err, query });
    });
};
// field can be "entity_type" or "internal_id"
const buildAggregationRelationFilters = async (context, user, aggregationFilters) => {
  const aggBody = await elQueryBodyBuilder(context, user, { ...aggregationFilters, noSize: true, noSort: true });
  return {
    bool: {
      must: (aggBody.query.bool.must ?? []).filter((m) => m.nested).map((m) => m.nested.query),
      must_not: (aggBody.query.bool.must_not ?? []).filter((m) => m.nested).map((m) => m.nested.query)
    },
  };
};
export const elAggregationRelationsCount = async (context, user, indexName, options = {}) => {
  const { types = [], field = null, searchOptions, aggregationOptions } = options;
  if (!R.includes(field, ['entity_type', 'internal_id', null])) {
    throw FunctionalError('[SEARCH] Unsupported field', field);
  }
  const body = await elQueryBodyBuilder(context, user, { ...searchOptions, noSize: true, noSort: true });
  const aggregationFilters = await buildAggregationRelationFilters(context, user, aggregationOptions);
  body.size = MAX_SEARCH_AGGREGATION_SIZE;
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
  const query = { index: indexName, ignore_throttled: ES_IGNORE_THROTTLED, body };
  logApp.debug('[SEARCH] aggregationRelationsCount', { query });
  return elRawSearch(context, user, types, query)
    .then(async (data) => {
      const { buckets } = data.aggregations.connections.filtered.genres;
      if (field === 'internal_id') {
        return buckets.map((b) => ({ label: b.key, value: b.parent.weight.value }));
      }
      // entity_type
      const filteredBuckets = buckets.filter((b) => !(isAbstract(pascalize(b.key)) || isAbstract(b.key)));
      return R.map((b) => ({ label: pascalize(b.key), value: b.parent.weight.value }), filteredBuckets);
    })
    .catch((e) => {
      throw DatabaseError('[SEARCH] Fail processing AggregationRelationsCount', { error: e });
    });
};

export const elAggregationsList = async (context, user, indexName, aggregations, opts = {}) => {
  const { types = [], resolveToRepresentative = true } = opts;
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
    index: indexName,
    ignore_throttled: ES_IGNORE_THROTTLED,
    track_total_hits: true,
    _source: false,
    body,
  };
  const searchType = `Aggregations (${aggregations.map((agg) => agg.field)?.join(', ')})`;
  const data = await elRawSearch(context, user, searchType, query).catch((err) => {
    throw DatabaseError('[SEARCH] Aggregations list fail', { error: err, query });
  });
  const aggsMap = Object.keys(data.aggregations);
  const aggsValues = R.uniq(R.flatten(aggsMap.map((agg) => data.aggregations[agg].buckets?.map((b) => b.key))));
  if (resolveToRepresentative) {
    const baseFields = ['internal_id', 'name', 'entity_type']; // Needs to take elements required to fill extractEntityRepresentative function
    const aggsElements = await elFindByIds(context, user, aggsValues, { baseData: true, baseFields });
    const aggsElementsCache = R.mergeAll(aggsElements.map((element) => ({ [element.internal_id]: extractEntityRepresentative(element) })));
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

export const elPaginate = async (context, user, indexName, options = {}) => {
  // eslint-disable-next-line no-use-before-define
  const { baseData = false, first = 200 } = options;
  const { types = null, connectionFormat = true } = options;
  const body = await elQueryBodyBuilder(context, user, options);
  if (body.size > ES_MAX_PAGINATION) {
    const message = `[SEARCH] You cannot ask for more than ${ES_MAX_PAGINATION} results. If you need more, please use pagination`;
    throw DatabaseError(message, { body });
  }
  const query = {
    index: indexName,
    ignore_throttled: ES_IGNORE_THROTTLED,
    track_total_hits: true,
    _source: baseData ? BASE_FIELDS : true,
    body,
  };
  logApp.debug('[SEARCH] paginate', { query });
  return elRawSearch(context, user, types !== null ? types : 'Any', query)
    .then((data) => {
      const convertedHits = R.map((n) => elDataConverter(n), data.hits.hits);
      if (connectionFormat) {
        const nodeHits = R.map((n) => ({ node: n, sort: n.sort }), convertedHits);
        return buildPagination(first, body.search_after, nodeHits, data.hits.total.value);
      }
      return convertedHits;
    })
    .catch(
      /* istanbul ignore next */ (err) => {
        // Because we create the mapping at element creation
        // We log the error only if its not a mapping not found error
        let isTechnicalError = true;
        if (isNotEmptyField(err.meta?.body)) {
          const errorCauses = err.meta.body?.error?.root_cause ?? [];
          const invalidMappingCauses = errorCauses.map((r) => r.reason ?? '')
            .filter((r) => R.includes(NO_MAPPING_FOUND_ERROR, r) || R.includes(NO_SUCH_INDEX_ERROR, r));
          const numberOfCauses = errorCauses.length;
          isTechnicalError = numberOfCauses === 0 || numberOfCauses > invalidMappingCauses.length;
        }
        // If uncontrolled error, log and propagate
        if (isTechnicalError) {
          logApp.error('[SEARCH] Paginate fail', { error: err, query });
          throw err;
        } else {
          return connectionFormat ? buildPagination(0, null, [], 0) : [];
        }
      }
    );
};
export const elList = async (context, user, indexName, options = {}) => {
  const { first = MAX_SEARCH_SIZE, infinite = false } = options;
  let hasNextPage = true;
  let continueProcess = true;
  let searchAfter = options.after;
  const listing = [];
  const publish = async (elements) => {
    const { callback } = options;
    if (callback) {
      const callbackResult = await callback(elements);
      continueProcess = callbackResult === true || callbackResult === undefined;
    } else {
      listing.push(...elements);
    }
  };
  while (continueProcess && hasNextPage) {
    // Force options to prevent connection format and manage search after
    const opts = { ...options, first, after: searchAfter, connectionFormat: false };
    const elements = await elPaginate(context, user, indexName, opts);
    if (!infinite && (elements.length === 0 || elements.length < first)) {
      if (elements.length > 0) {
        await publish(elements);
      }
      hasNextPage = false;
    } else if (elements.length > 0) {
      const { sort } = R.last(elements);
      searchAfter = offsetToCursor(sort);
      await publish(elements);
    }
  }
  return listing;
};
export const elLoadBy = async (context, user, field, value, type = null, indices = READ_DATA_INDICES) => {
  const opts = { filters: [{ key: field, values: [value] }], connectionFormat: false, types: type ? [type] : [] };
  const hits = await elPaginate(context, user, indices, opts);
  if (hits.length > 1) throw UnsupportedError(`[SEARCH] Expected only one response, found ${hits.length}`);
  return R.head(hits);
};
export const elAttributeValues = async (context, user, field, opts = {}) => {
  const { first, orderMode = 'asc', search } = opts;
  const markingRestrictions = await buildDataRestrictions(context, user);
  const isDateOrNumber = isDateNumericOrBooleanAttribute(field);
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
          field: isDateOrNumber ? field : `${field}.keyword`,
          size: first ?? MAX_JS_PARAMS,
          order: { _key: orderMode },
        },
      },
    },
  };
  const query = {
    index: [READ_DATA_INDICES],
    ignore_throttled: ES_IGNORE_THROTTLED,
    body,
  };
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
      throw DatabaseError('[SEARCH] Error updating elastic (bulk indexing)', { errors });
    }
    return data;
  });
};
/* istanbul ignore next */
export const elReindex = async (indices) => {
  return Promise.all(
    indices.map((indexMap) => {
      return engine.reindex({
        timeout: '60m',
        body: {
          source: {
            index: indexMap.source,
          },
          dest: {
            index: indexMap.dest,
          },
        },
      });
    })
  );
};
export const elIndex = async (indexName, documentBody, refresh = true) => {
  const internalId = documentBody.internal_id;
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  logApp.debug(`[SEARCH] index > ${entityType} ${internalId} in ${indexName}`, documentBody);
  await engine.index({
    index: indexName,
    id: documentBody.internal_id,
    refresh,
    timeout: '60m',
    body: R.dissoc('_index', documentBody),
  }).catch((err) => {
    throw DatabaseError('[SEARCH] Error updating elastic (index)', { error: err, body: documentBody });
  });
  return documentBody;
};
/* istanbul ignore next */
export const elUpdate = (indexName, documentId, documentBody, retry = ES_RETRY_ON_CONFLICT) => {
  return engine.update({
    id: documentId,
    index: indexName,
    retry_on_conflict: retry,
    timeout: BULK_TIMEOUT,
    refresh: true,
    body: documentBody,
  }).catch((err) => {
    throw DatabaseError('[SEARCH] Error updating elastic (update)', { error: err, documentId, body: documentBody });
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

const getRelatedRelations = async (context, user, targetIds, elements, level, cache) => {
  const elementIds = Array.isArray(targetIds) ? targetIds : [targetIds];
  const filters = [{ nested: [{ key: 'internal_id', values: elementIds }], key: 'connections' }];
  const opts = { filters, connectionFormat: false, types: [ABSTRACT_BASIC_RELATIONSHIP] };
  const hits = await elList(context, user, READ_RELATIONSHIPS_INDICES, opts);
  const groupResults = R.splitEvery(MAX_JS_PARAMS, hits);
  const foundRelations = [];
  for (let index = 0; index < groupResults.length; index += 1) {
    const subRels = groupResults[index];
    elements.unshift(...subRels.map((s) => ({ ...s, level })));
    const internalIds = subRels.map((g) => g.internal_id);
    const resolvedIds = internalIds.filter((f) => !cache[f]);
    foundRelations.push(...resolvedIds);
    resolvedIds.forEach((id) => {
      cache.set(id, '');
    });
  }
  // If relations find, need to recurs to find relations to relations
  if (foundRelations.length > 0) {
    const groups = R.splitEvery(MAX_BULK_OPERATIONS, foundRelations);
    const concurrentFetch = (gIds) => getRelatedRelations(context, user, gIds, elements, level + 1, cache);
    await BluePromise.map(groups, concurrentFetch, { concurrency: ES_MAX_CONCURRENCY });
  }
};
export const getRelationsToRemove = async (context, user, elements) => {
  const relationsToRemoveMap = new Map();
  const relationsToRemove = [];
  const ids = elements.map((e) => e.internal_id);
  await getRelatedRelations(context, user, ids, relationsToRemove, 0, relationsToRemoveMap);
  return { relations: R.flatten(relationsToRemove), relationsToRemoveMap };
};
export const elDeleteInstances = async (instances) => {
  // If nothing to delete, return immediately to prevent elastic to delete everything
  if (instances.length > 0) {
    logApp.debug(`[SEARCH] Deleting ${instances.length} instances`);
    const bodyDelete = instances.flatMap((doc) => {
      return [{ delete: { _index: doc._index, _id: doc.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } }];
    });
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyDelete });
    await Promise.all([bulkPromise]);
  }
};
const elRemoveRelationConnection = async (context, user, relsFromTo) => {
  if (relsFromTo.length > 0) {
    const idsToResolve = R.uniq(
      relsFromTo
        .map(({ relation, isFromCleanup, isToCleanup }) => {
          const ids = [];
          if (isFromCleanup) ids.push(relation.fromId);
          if (isToCleanup) ids.push(relation.toId);
          return ids;
        })
        .flat()
    );
    const dataIds = await elFindByIds(context, user, idsToResolve);
    const indexCache = R.mergeAll(dataIds.map((element) => ({ [element.internal_id]: element._index })));
    const bodyUpdateRaw = relsFromTo.map(({ relation, isFromCleanup, isToCleanup }) => {
      const refField = isStixRefRelationship(relation.entity_type)
      && isInferredIndex(relation._index) ? ID_INFERRED : ID_INTERNAL;
      const type = buildRefRelationKey(relation.entity_type, refField);
      const updates = [];
      const fromIndex = indexCache[relation.fromId];
      if (isFromCleanup && fromIndex) {
        let source = `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`;
        if (isStixRefRelationship(relation.entity_type)) {
          source += 'ctx._source[\'updated_at\'] = params.updated_at;';
        }
        const script = {
          source,
          params: { key: relation.toId, updated_at: now() },
        };
        updates.push([
          { update: { _index: fromIndex, _id: relation.fromId, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
          { script },
        ]);
      }
      // Update to to entity
      const toIndex = indexCache[relation.toId];
      if (isToCleanup && toIndex) {
        const script = {
          source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
          params: { key: relation.fromId, updated_at: now() },
        };
        updates.push([
          { update: { _index: toIndex, _id: relation.toId, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
          { script },
        ]);
      }
      return updates;
    });
    const bodyUpdate = R.flatten(bodyUpdateRaw);
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    await Promise.all([bulkPromise]);
  }
};

export const elDeleteElements = async (context, user, elements, stixLoadById) => {
  if (elements.length === 0) return [];
  const toBeRemovedIds = elements.map((e) => e.internal_id);
  const opts = { concurrency: ES_MAX_CONCURRENCY };
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, user, elements);
  const stixRelations = relations.filter((r) => isStixRelationshipExceptRef(r.relationship_type));
  const dependencyDeletions = await BluePromise.map(stixRelations, (r) => stixLoadById(context, user, r.internal_id), opts);
  // Compute the id that needs to be remove from rel
  const basicCleanup = elements.filter((f) => isBasicRelationship(f.entity_type));
  const cleanupRelations = relations.concat(basicCleanup);
  const relsFromToImpacts = cleanupRelations
    .map((r) => {
      const fromWillNotBeRemoved = !relationsToRemoveMap.has(r.fromId) && !toBeRemovedIds.includes(r.fromId);
      const isFromCleanup = fromWillNotBeRemoved && isImpactedTypeAndSide(r.entity_type, ROLE_FROM);
      const toWillNotBeRemoved = !relationsToRemoveMap.has(r.toId) && !toBeRemovedIds.includes(r.toId);
      const isToCleanup = toWillNotBeRemoved && isImpactedTypeAndSide(r.entity_type, ROLE_TO);
      return { relation: r, isFromCleanup, isToCleanup };
    })
    .filter((r) => r.isFromCleanup || r.isToCleanup);
  // Remove all relations
  let currentRelationsDelete = 0;
  const groupsOfDeletions = R.splitEvery(MAX_BULK_OPERATIONS, relations);
  const concurrentDeletions = async (deletions) => {
    await elDeleteInstances(deletions);
    currentRelationsDelete += deletions.length;
    logApp.debug(`[SEARCH] Deleting related relations ${currentRelationsDelete} / ${relations.length}`);
  };
  await BluePromise.map(groupsOfDeletions, concurrentDeletions, opts);
  // Remove the elements
  await elDeleteInstances(elements);
  // Update all rel connections that will remain
  let currentRelationsCount = 0;
  const groupsOfRelsFromTo = R.splitEvery(MAX_BULK_OPERATIONS, relsFromToImpacts);
  const concurrentRelsFromTo = async (relsToClean) => {
    await elRemoveRelationConnection(context, user, relsToClean);
    currentRelationsCount += relsToClean.length;
    logApp.debug(`[SEARCH] Updating relations for deletion ${currentRelationsCount} / ${relsFromToImpacts.length}`);
  };
  await BluePromise.map(groupsOfRelsFromTo, concurrentRelsFromTo, opts);
  // Return the relations deleted because of the entity deletion
  return dependencyDeletions;
};

export const prepareElementForIndexing = (element) => {
  const thing = {};
  Object.keys(element).forEach((key) => {
    const value = element[key];
    if (Array.isArray(value)) { // Array of Date, objects, string or number
      const filteredArray = value.filter((i) => i);
      thing[key] = filteredArray.length > 0 ? filteredArray.map((f) => {
        if (isDateAttribute(key)) { // Date is an object but natively supported
          return f;
        }
        if (R.is(String, f)) { // For string, trim by default
          return f.trim();
        }
        if (R.is(Object, f) && Object.keys(value).length > 0) { // For complex object, prepare inner elements
          return prepareElementForIndexing(f);
        }
        // For all other types, no transform (list of boolean is not supported)
        return f;
      }) : [];
    } else if (isDateAttribute(key)) { // Date is an object but natively supported
      thing[key] = value;
    } else if (isBooleanAttribute(key)) { // Patch field is string generic so need to be cast to boolean
      thing[key] = typeof value === 'boolean' ? value : value?.toLowerCase() === 'true';
    } else if (R.is(Object, value) && Object.keys(value).length > 0) { // For complex object, prepare inner elements
      thing[key] = prepareElementForIndexing(value);
    } else if (R.is(String, value)) { // For string, trim by default
      thing[key] = value.trim();
    } else { // For all other types (numeric, ...), no transform
      thing[key] = value;
    }
  });
  return thing;
};
const prepareRelation = (thing) => {
  if (thing.fromRole === undefined || thing.toRole === undefined) {
    throw DatabaseError(`[SEARCH] Cant index relation ${thing.internal_id} connections without from or to`, thing);
  }
  const connections = [];
  if (!thing.from || !thing.to) {
    throw DatabaseError(`[SEARCH] Cant index relation ${thing.internal_id}, error resolving dependency IDs`, {
      fromId: thing.fromId,
      toId: thing.toId,
    });
  }
  const { from, to } = thing;
  connections.push({
    internal_id: from.internal_id,
    name: from.name,
    types: [from.entity_type, ...getParentTypes(from.entity_type)],
    role: thing.fromRole,
  });
  connections.push({
    internal_id: to.internal_id,
    name: to.name,
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
    // Dissoc to
    R.dissoc('to'),
    R.dissoc('toId'),
    R.dissoc('toRole')
  )(thing);
};
const prepareEntity = (thing) => {
  return R.pipe(R.dissoc(INTERNAL_TO_FIELD), R.dissoc(INTERNAL_FROM_FIELD))(thing);
};
const prepareIndexing = async (elements) => {
  return Promise.all(
    R.map(async (element) => {
      // Ensure empty list are not indexed
      const thing = prepareElementForIndexing(element);
      // For relation, index a list of connections.
      if (thing.base_type === BASE_TYPE_RELATION) {
        return prepareRelation(thing);
      }
      return prepareEntity(thing);
    }, elements)
  );
};
export const elIndexElements = async (context, user, message, elements) => {
  const elIndexElementsFn = async () => {
    // 00. Relations must be transformed before indexing.
    const transformedElements = await prepareIndexing(elements);
    // 01. Bulk the indexing of row elements
    const body = transformedElements.flatMap((doc) => [
      { index: { _index: doc._index, _id: doc.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
      R.pipe(R.dissoc('_index'))(doc),
    ]);
    if (body.length > 0) {
      await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body });
    }
    // 02. If relation, generate impacts for from and to sides
    const cache = {};
    const impactedEntities = R.pipe(
      R.filter((e) => e.base_type === BASE_TYPE_RELATION),
      R.map((e) => {
        const { fromRole, toRole } = e;
        const impacts = [];
        // We impact target entities of the relation only if not global entities like
        // MarkingDefinition (marking) / KillChainPhase (kill_chain_phase) / Label (tagging)
        cache[e.fromId] = e.from;
        cache[e.toId] = e.to;
        const refField = isStixRefRelationship(e.entity_type) && isInferredIndex(e._index) ? ID_INFERRED : ID_INTERNAL;
        const relationshipType = e.entity_type;
        if (isImpactedRole(fromRole)) {
          impacts.push({ refField, from: e.fromId, relationshipType, to: e.to, type: e.to.entity_type, side: 'from' });
        }
        if (isImpactedRole(toRole)) {
          impacts.push({ refField, from: e.toId, relationshipType, to: e.from, type: e.from.entity_type, side: 'to' });
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
      const targetsElements = R.map((relTypeAndField) => {
        const [relType, refField] = relTypeAndField.split('|');
        const data = targetsByRelation[relTypeAndField];
        const resolvedData = R.map((d) => {
          return { id: d.to.internal_id, side: d.side, type: d.type };
        }, data);
        return { relation: relType, field: refField, elements: resolvedData };
      }, Object.keys(targetsByRelation));
      // Create params and scripted update
      const params = { updated_at: now() };
      const sources = targetsElements.map((t) => {
        const field = buildRefRelationKey(t.relation, t.field);
        let script = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
        script += `ctx._source['${field}'].addAll(params['${field}'])`;
        if (isStixRefRelationship(t.relation)) {
          const fromSide = R.find((e) => e.side === 'from', t.elements);
          if (fromSide && isUpdatedAtObject(fromSide.type)) {
            script += '; ctx._source[\'updated_at\'] = params.updated_at';
          }
          if (fromSide && isModifiedObject(fromSide.type)) {
            script += '; ctx._source[\'modified\'] = params.updated_at';
          }
        }
        return script;
      });
      const source = sources.length > 1 ? R.join(';', sources) : `${R.head(sources)};`;
      for (let index = 0; index < targetsElements.length; index += 1) {
        const targetElement = targetsElements[index];
        params[buildRefRelationKey(targetElement.relation, targetElement.field)] = targetElement.elements.map((e) => e.id);
      }
      return { ...entity, id: entityId, data: { script: { source, params } } };
    });
    const bodyUpdate = elementsToUpdate.flatMap((doc) => [
      { update: { _index: doc._index, _id: doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
      R.dissoc('_index', doc.data),
    ]);
    if (bodyUpdate.length > 0) {
      const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
      await Promise.all([bulkPromise]);
    }
    return transformedElements.length;
  };
  return telemetry(context, user, `INSERT ${message}`, {
    [SemanticAttributes.DB_NAME]: 'search_engine',
    [SemanticAttributes.DB_OPERATION]: 'insert',
  }, elIndexElementsFn);
};

export const elUpdateRelationConnections = async (elements) => {
  if (elements.length > 0) {
    const source = 'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); '
      + 'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
    const bodyUpdate = elements.flatMap((doc) => [
      { update: { _index: doc._index, _id: doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
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
        { update: { _index: doc._index, _id: doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
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

export const elUpdateConnectionsOfElement = async (documentId, documentBody) => {
  const source = 'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); '
    + 'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
  return elRawUpdateByQuery({
    index: READ_RELATIONSHIPS_INDICES,
    refresh: true,
    conflicts: 'proceed',
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
    throw DatabaseError('[SEARCH] Error updating elastic (connections)', { error: err, documentId, body: documentBody });
  });
};
export const elUpdateElement = async (instance) => {
  // Update the element it self
  const esData = prepareElementForIndexing(instance);
  // Set the cache
  const replacePromise = elReplace(instance._index, instance.internal_id, { doc: esData });
  // If entity with a name, must update connections
  let connectionPromise = Promise.resolve();
  if (esData.name && isStixObject(instance.entity_type)) {
    connectionPromise = elUpdateConnectionsOfElement(instance.internal_id, { name: esData.name });
  }
  return Promise.all([replacePromise, connectionPromise]);
};

export const getStats = () => {
  return engine.indices
    .stats({ index: READ_PLATFORM_INDICES }) //
    .then((result) => oebp(result)._all.total);
};
