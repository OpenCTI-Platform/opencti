/* eslint-disable no-underscore-dangle */
import { Client as ElkClient } from '@elastic/elasticsearch';
import { Client as OpenClient } from '@opensearch-project/opensearch';
import { Promise as BluePromise } from 'bluebird';
import * as R from 'ramda';
import semver from 'semver';
import { readFileSync } from 'node:fs';
import {
  buildPagination,
  cursorToOffset,
  ES_INDEX_PREFIX,
  isEmptyField,
  isNotEmptyField,
  offsetToCursor,
  pascalize,
  READ_DATA_INDICES,
  READ_ENTITIES_INDICES,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_PLATFORM_INDICES,
  READ_RELATIONSHIPS_INDICES,
  waitInSec,
  WRITE_PLATFORM_INDICES,
} from './utils';
import conf, { booleanConf, logApp } from '../config/conf';
import { ConfigurationError, DatabaseError, FunctionalError, UnsupportedError } from '../config/errors';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  buildRefRelationSearchKey,
  ENTITY_TYPE_IDENTITY,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INTERNAL_IDS_ALIASES,
  isAbstract,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
} from '../schema/general';
import {
  booleanAttributes,
  dateAttributes,
  isBooleanAttribute,
  isModifiedObject,
  isMultipleAttribute,
  isRuntimeAttribute,
  isUpdatedAtObject,
  numericOrBooleanAttributes,
} from '../schema/fieldDataAdapter';
import { convertEntityTypeToStixType, getParentTypes } from '../schema/schemaUtils';
import {
  ATTRIBUTE_ABSTRACT,
  ATTRIBUTE_DESCRIPTION,
  ATTRIBUTE_EXPLANATION,
  ATTRIBUTE_NAME,
  isStixObjectAliased,
} from '../schema/stixDomainObject';
import { isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationShipExceptMeta } from '../schema/stixRelationship';
import { RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { getInstanceIds, INTERNAL_FROM_FIELD, INTERNAL_TO_FIELD } from '../schema/identifier';
import { BYPASS } from '../utils/access';
import { cacheDel, cacheGet, cachePurge, cacheSet } from './redis';
import { isSingleStixEmbeddedRelationship, } from '../schema/stixEmbeddedRelationship';
import { now, runtimeFieldObservableValueScript } from '../utils/format';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

const ELK_ENGINE = 'elk';
export const ES_MAX_CONCURRENCY = conf.get('elasticsearch:max_concurrency');
export const ES_IGNORE_THROTTLED = conf.get('elasticsearch:search_ignore_throttled');
export const ES_MAX_PAGINATION = conf.get('elasticsearch:max_pagination_result');
const ES_INDEX_PATTERN_SUFFIX = conf.get('elasticsearch:index_creation_pattern');
const ES_MAX_RESULT_WINDOW = conf.get('elasticsearch:max_result_window') || 100000;
const ES_INDEX_SHARD_NUMBER = conf.get('elasticsearch:number_of_shards');
const ES_INDEX_REPLICA_NUMBER = conf.get('elasticsearch:number_of_replicas');

const ES_RETRY_ON_CONFLICT = 5;
export const MAX_SPLIT = 250; // Max number of terms resolutions (ES limitation)
export const BULK_TIMEOUT = '5m';
const MAX_AGGREGATION_SIZE = 100;
const MAX_JS_PARAMS = 65536; // Too prevent Maximum call stack size exceeded
const MAX_SEARCH_AGGREGATION_SIZE = 10000;
const MAX_SEARCH_SIZE = 5000;
export const ROLE_FROM = 'from';
export const ROLE_TO = 'to';
const UNIMPACTED_ENTITIES_ROLE = [
  `${RELATION_CREATED_BY}_${ROLE_TO}`,
  `${RELATION_OBJECT_MARKING}_${ROLE_TO}`,
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
  ? readFileSync(conf.get('elasticsearch:ssl:ca'))
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

const elkClient = new ElkClient(searchConfiguration);
const openClient = new OpenClient(searchConfiguration);
let isRuntimeSortingEnable = false;
let el = openClient;

// Look for the engine version with OpenSearch client
export const searchEngineVersion = () => {
  return openClient
    .info()
    .then((info) => info.body.version)
    .catch(
      /* istanbul ignore next */ () => {
        return 'Disconnected';
      }
    );
};
export const searchEngineInit = async () => {
  // region Check if search engine is accessible
  await openClient
    .info()
    .then((info) => {
      /* istanbul ignore if */
      if (info.meta.connection.status !== 'alive') {
        throw ConfigurationError('ElasticSearch seems down (status not alive)');
      }
    })
    .catch(
      /* istanbul ignore next */ (e) => {
        throw ConfigurationError('ElasticSearch seems down', { error: e.message });
      }
    );
  // endregion
  // Setup the platform runtime field option
  const searchInfo = await searchEngineVersion();
  const searchPlatform = searchInfo.distribution || ELK_ENGINE; // openSearch or elasticSearch
  const searchVersion = searchInfo.number;
  isRuntimeSortingEnable = searchPlatform === ELK_ENGINE && semver.satisfies(searchVersion, '>=7.12.x');
  // Look for the right client to use
  if (searchPlatform === ELK_ENGINE) {
    logApp.info(
      `[SEARCH ENGINE] Elasticsearch (${searchVersion}) client selected / runtime sorting ${
        isRuntimeSortingEnable ? 'enabled' : 'disabled'
      }`
    );
    el = elkClient;
  } else {
    logApp.info(`[SEARCH ENGINE] OpenSearch (${searchVersion}) client selected / runtime sorting disabled`);
    el = openClient;
  }
  // Everything is fine, return true
  return true;
};
export const isRuntimeSortEnable = () => isRuntimeSortingEnable;

// The OpenSearch/ELK Body Parser (oebp)
// Starting ELK8+, response are no longer inside a body envelop
// Query wrapping is still accepted in ELK8
const oebp = (queryResult) => {
  if (el instanceof ElkClient) {
    return queryResult;
  }
  return queryResult.body;
};
export const elRawSearch = (query) => el.search(query).then((r) => oebp(r));
export const elRawDeleteByQuery = (query) => el.deleteByQuery(query).then((r) => oebp(r));
export const elRawUpdateByQuery = (query) => el.updateByQuery(query).then((r) => oebp(r));
const elGetTask = (taskId) => el.tasks.get({ task_id: taskId }).then((r) => oebp(r));
export const elUpdateByQueryForMigration = async (message, index, body) => {
  logApp.info(`${message} started`);
  // Execute the update by query in async mode
  const queryAsync = await elRawUpdateByQuery({ index,
    refresh: true,
    wait_for_completion: false,
    body
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
  // Wait 10 seconds for task to initialize
  await waitInSec(10);
  // Monitor the task until completion
  let taskStatus = await elGetTask(queryAsync.task);
  while (!taskStatus.completed) {
    const { total, updated } = taskStatus.task.status;
    logApp.info(`${message} in progress - ${updated}/${total}`);
    await waitInSec(5);
    taskStatus = await elGetTask(queryAsync.task);
  }
  const timeSec = Math.round(taskStatus.task.running_time_in_nanos / 1e9);
  logApp.info(`${message} done in ${timeSec} seconds`);
};

const buildMarkingRestriction = (user) => {
  const must = [];
  // eslint-disable-next-line camelcase
  const must_not = [];
  // Check user rights
  const isBypass = R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
  if (!isBypass) {
    if (user.allowed_marking.length === 0) {
      // If user have no marking, he can only access to data with no markings.
      must_not.push({ exists: { field: buildRefRelationKey(RELATION_OBJECT_MARKING) } });
    } else {
      // Markings should be group by types for restriction
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
  }
  return { must, must_not };
};

export const elIndexExists = async (indexName) => {
  const existIndex = await el.indices.exists({ index: indexName });
  return oebp(existIndex) === true;
};
const elCreateIndexTemplate = async () => {
  await el.cluster
    .putComponentTemplate({
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
    })
    .catch((e) => {
      throw DatabaseError('Error creating opencti component', { error: e });
    });
  await el.indices
    .putIndexTemplate({
      name: `${ES_INDEX_PREFIX}-index-template`,
      create: false,
      body: {
        index_patterns: [`${ES_INDEX_PREFIX}*`],
        template: {
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
              modified: {
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
              confidence: {
                type: 'integer',
              },
              x_opencti_report_status: {
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
    })
    .catch((e) => {
      throw DatabaseError('Error creating opencti template', { error: e });
    });
};
export const elCreateIndexes = async (indexesToCreate = WRITE_PLATFORM_INDICES) => {
  await elCreateIndexTemplate();
  const createdIndices = [];
  for (let i = 0; i < indexesToCreate.length; i += 1) {
    const index = indexesToCreate[i];
    const indexName = `${index}${ES_INDEX_PATTERN_SUFFIX}`;
    const isExist = await el.indices.exists({ index: indexName }).then((r) => oebp(r));
    if (!isExist) {
      const createdIndex = await el.indices.create({ index: indexName, body: { aliases: { [index]: {} } } });
      createdIndices.push(oebp(createdIndex));
    }
  }
  return createdIndices;
};
export const elDeleteIndexes = async (indexesToDelete) => {
  return Promise.all(
    indexesToDelete.map((index) => {
      return el.indices.delete({ index })
        .then((response) => oebp(response))
        .catch((err) => {
        /* istanbul ignore next */
          if (err.meta.body && err.meta.body.error.type !== 'index_not_found_exception') {
            logApp.error('[SEARCH ENGINE] Delete indices fail', { error: err });
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
    getParams: async (user) => {
      // eslint-disable-next-line no-use-before-define
      const identities = await elPaginate(user, READ_ENTITIES_INDICES, {
        types: [ENTITY_TYPE_IDENTITY],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.name })));
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
    getParams: async (user) => {
      // eslint-disable-next-line no-use-before-define
      const identities = await elPaginate(user, READ_ENTITIES_INDICES, {
        types: [ENTITY_TYPE_MARKING_DEFINITION],
        first: MAX_SEARCH_SIZE,
        connectionFormat: false,
      });
      return R.mergeAll(identities.map((i) => ({ [i.internal_id]: i.definition })));
    },
  },
};

export const elCount = (user, indexName, options = {}) => {
  const {
    endDate = null,
    types = null,
    relationshipType = null,
    authorId = null,
    fromId = null,
    toTypes = null,
    isMetaRelationship = false,
  } = options;
  let must = [];
  const markingRestrictions = buildMarkingRestriction(user);
  must.push(...markingRestrictions.must);
  if (endDate !== null) {
    must = R.append(
      {
        range: {
          created_at: {
            format: 'strict_date_optional_time',
            lt: endDate,
          },
        },
      },
      must
    );
  }
  if (types !== null && types.length > 0) {
    const should = types.map((typeValue) => {
      return {
        bool: {
          should: [
            { match_phrase: { 'entity_type.keyword': typeValue } },
            { match_phrase: { 'parent_types.keyword': typeValue } },
          ],
          minimum_should_match: 1,
        },
      };
    });
    must = R.append(
      {
        bool: {
          should,
          minimum_should_match: 1,
        },
      },
      must
    );
  }
  if (relationshipType !== null && !isMetaRelationship) {
    must = R.append(
      {
        bool: {
          should: {
            match_phrase: { 'relationship_type.keyword': relationshipType },
          },
        },
      },
      must
    );
  }
  if (authorId !== null && !isMetaRelationship) {
    must = R.append(
      {
        bool: {
          should: {
            match_phrase: { [buildRefRelationSearchKey(RELATION_CREATED_BY)]: authorId },
          },
        },
      },
      must
    );
  }
  if (fromId !== null) {
    if (isMetaRelationship) {
      must = R.append(
        {
          bool: {
            should: {
              match_phrase: { [buildRefRelationSearchKey(relationshipType)]: fromId },
            },
          },
        },
        must
      );
    } else {
      must = R.append(
        {
          nested: {
            path: 'connections',
            query: {
              bool: {
                must: [{ match_phrase: { 'connections.internal_id.keyword': fromId } }],
              },
            },
          },
        },
        must
      );
    }
  }
  if (toTypes !== null) {
    const filters = [];
    for (let index = 0; index < toTypes.length; index += 1) {
      filters.push({
        match_phrase: { 'connections.types.keyword': toTypes[index] },
      });
    }
    must = R.append(
      {
        nested: {
          path: 'connections',
          query: {
            bool: {
              should: filters,
              minimum_should_match: 1,
            },
          },
        },
      },
      must
    );
  }
  const query = {
    index: indexName,
    body: {
      query: {
        bool: {
          must,
          must_not: markingRestrictions.must_not,
        },
      },
    },
  };
  logApp.debug('[SEARCH ENGINE] countEntities', { query });
  return el
    .count(query)
    .then((data) => {
      return oebp(data).count;
    })
    .catch((err) => {
      throw DatabaseError('Count data fail', { error: err, query });
    });
};
export const elAggregationCount = (user, type, aggregationField, start, end, filters = []) => {
  const isIdFields = aggregationField.endsWith('internal_id');
  const haveRange = start && end;
  const dateFilter = [];
  if (haveRange) {
    dateFilter.push({
      range: {
        created_at: {
          gte: start,
          lte: end,
        },
      },
    });
  }
  const histoFilters = R.map((f) => {
    let key = `${f.type}.keyword`;
    if (f.isRelation) {
      key = buildRefRelationSearchKey(f.type || '*');
    } else if (booleanAttributes.includes(f.type)) {
      key = f.type;
    }
    return {
      multi_match: {
        fields: [key],
        type: 'phrase',
        query: f.value,
      },
    };
  }, filters);
  const must = R.concat(dateFilter, histoFilters);
  const markingRestrictions = buildMarkingRestriction(user);
  must.push(...markingRestrictions.must);
  const query = {
    index: READ_PLATFORM_INDICES,
    body: {
      size: MAX_SEARCH_AGGREGATION_SIZE,
      query: {
        bool: {
          must,
          must_not: markingRestrictions.must_not,
          should: [
            { match_phrase: { 'entity_type.keyword': type } },
            { match_phrase: { 'parent_types.keyword': type } },
          ],
          minimum_should_match: 1,
        },
      },
      aggs: {
        genres: {
          terms: {
            field: booleanAttributes.includes(aggregationField) ? aggregationField : `${aggregationField}.keyword`,
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
      },
    },
  };
  logApp.debug('[SEARCH ENGINE] aggregationCount', { query });
  return elRawSearch(query)
    .then((data) => {
      const { buckets } = data.aggregations.genres;
      return R.map((b) => {
        let label = b.key;
        if (typeof label === 'number') {
          label = b.key_as_string;
        } else if (!isIdFields) {
          label = pascalize(b.key);
        }
        return { label, value: b.weight.value };
      }, buckets);
    })
    .catch((err) => {
      throw DatabaseError('Aggregation fail', { error: err, query });
    });
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
    throw DatabaseError('[ELASTIC] Something fail in reconstruction of the relation', concept.internal_id);
  }
  const from = elBuildRelation('from', fromConnection);
  from.source_ref = `${convertEntityTypeToStixType(from.fromType)}--temporary`;
  const to = elBuildRelation('to', toConnection);
  to.target_ref = `${convertEntityTypeToStixType(to.toType)}--temporary`;
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
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
  };
  const entries = Object.entries(data);
  const ruleInferences = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substr(RULE_PREFIX.length);
      const ruleDefinitions = Object.values(val);
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = R.toPairs(inferred).map((s) => ({ field: R.head(s), value: String(R.last(s)) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
      data[key] = val;
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      const rel = key.substr(REL_INDEX_PREFIX.length);
      const [relType] = rel.split('.');
      data[relType] = isSingleStixEmbeddedRelationship(relType) ? R.head(val) : val;
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

export const elFindByFromAndTo = async (user, fromId, toId, relationshipType) => {
  const mustTerms = [];
  const markingRestrictions = buildMarkingRestriction(user);
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
    index: READ_RELATIONSHIPS_INDICES,
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
  const data = await elRawSearch(query).catch((e) => {
    throw DatabaseError('Find by from and to fail', { error: e, query });
  });
  const hits = [];
  for (let index = 0; index < data.hits.hits.length; index += 1) {
    const hit = data.hits.hits[index];
    hits.push(elDataConverter(hit));
  }
  return hits;
};

const loadFromCache = async (user, id, type) => {
  const data = await cacheGet(id);
  const cachedValues = data ? Object.values(data).filter((e) => isNotEmptyField(e)) : [];
  const cached = R.flatten(cachedValues.map((v) => getInstanceIds(v)));
  const accessible = R.filter((instance) => {
    if (!instance) {
      return false;
    }
    const isBypass = R.find((s) => s.name === BYPASS, user.capabilities || []) !== undefined;
    if (!isBypass) {
      const dataMarkings = instance.object_marking_refs || [];
      const userMarkings = (user.allowed_marking || []).map((a) => a.internal_id);
      const isUserHaveAccess = dataMarkings.length === 0 || dataMarkings.every((m) => userMarkings.includes(m));
      if (!isUserHaveAccess) {
        return false;
      }
    }
    // Check type
    const dataTypes = [instance.entity_type, ...getParentTypes(instance.entity_type)];
    return !(type && !dataTypes.includes(type));
  }, data || {});
  const uniqByInternal = R.mergeAll(Object.entries(accessible).map(([, v]) => ({ [v.internal_id]: v })));
  return { cached, accessible: uniqByInternal };
};
export const elFindByIds = async (user, ids, opts = {}) => {
  const { indices = READ_DATA_INDICES, toMap = false, type = null } = opts;
  const idsArray = Array.isArray(ids) ? ids : [ids];
  const processIds = R.filter((id) => isNotEmptyField(id), idsArray);
  if (processIds.length === 0) {
    return toMap ? {} : [];
  }
  const { cached, accessible } = await loadFromCache(user, ids, type);
  const cacheHits = { ...accessible };
  const remainingIds = processIds.filter((id) => !cached.includes(id));
  const elasticHits = {};
  if (remainingIds.length > 0) {
    // const startTime = Date.now();
    const groupIds = R.splitEvery(MAX_SPLIT, remainingIds);
    for (let index = 0; index < groupIds.length; index += 1) {
      const mustTerms = [];
      const workingIds = groupIds[index];
      const idsTermsPerType = [];
      const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
      if (isStixObjectAliased(type)) {
        elementTypes.push(INTERNAL_IDS_ALIASES);
      }
      for (let i = 0; i < workingIds.length; i += 1) {
        const id = workingIds[i];
        for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
          const elementType = elementTypes[indexType];
          const term = { [`${elementType}.keyword`]: id };
          idsTermsPerType.push({ term });
        }
      }
      const should = {
        bool: {
          should: idsTermsPerType,
          minimum_should_match: 1,
        },
      };
      mustTerms.push(should);
      if (type) {
        const shouldType = {
          bool: {
            should: [
              { match_phrase: { 'entity_type.keyword': type } },
              { match_phrase: { 'parent_types.keyword': type } },
            ],
            minimum_should_match: 1,
          },
        };
        mustTerms.push(shouldType);
      }
      const markingRestrictions = buildMarkingRestriction(user);
      mustTerms.push(...markingRestrictions.must);
      const query = {
        index: indices,
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
      logApp.debug('[SEARCH ENGINE] elInternalLoadById', { query });
      const data = await elRawSearch(query).catch((err) => {
        throw DatabaseError('Error loading ids', { error: err, query });
      });
      for (let j = 0; j < data.hits.hits.length; j += 1) {
        const hit = data.hits.hits[j];
        const element = elDataConverter(hit);
        elasticHits[element.internal_id] = element;
      }
      await cacheSet(Object.values(elasticHits));
    }
  }
  const hits = { ...cacheHits, ...elasticHits };
  return toMap ? hits : Object.values(hits);
};

export const elLoadById = async (user, id, type = null, indices = READ_DATA_INDICES) => {
  const hits = await elFindByIds(user, id, { type, indices });
  /* istanbul ignore if */
  if (hits.length > 1) {
    const errorMeta = { id, type, hits: hits.length };
    throw DatabaseError('Expect only one response', errorMeta);
  }
  return R.head(hits);
};
export const elBatchIds = async (user, ids) => {
  const hits = await elFindByIds(user, ids);
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
};

// field can be "entity_type" or "internal_id"
export const elAggregationRelationsCount = async (user, type, opts) => {
  const { startDate: start, endDate: end = now(), toTypes = [], dateAttribute = 'created_at' } = opts;
  const { fromId = null, field = null, isTo = false, noDirection = false } = opts;
  if (!R.includes(field, ['entity_type', 'internal_id', null])) {
    throw FunctionalError('Unsupported field', field);
  }
  const roleFilter = { query_string: { query: !isTo ? '*_to' : '*_from', fields: ['connections.role'] } };
  const haveRange = start && end;
  const filters = [];
  if (haveRange) {
    filters.push({ range: { [dateAttribute]: { gte: start, lte: end } } });
  } else if (start) {
    filters.push({ range: { [dateAttribute]: { gte: start } } });
  } else if (end) {
    filters.push({ range: { [dateAttribute]: { lte: end } } });
  }
  if (fromId) {
    filters.push({
      nested: {
        path: 'connections',
        query: {
          bool: {
            must: [{ match_phrase: { 'connections.internal_id': fromId } }],
          },
        },
      },
    });
  }
  const typesFilters = [];
  for (let index = 0; index < toTypes.length; index += 1) {
    typesFilters.push({
      match_phrase: { 'connections.types': toTypes[index] },
    });
  }
  if (typesFilters.length > 0) {
    filters.push({
      nested: {
        path: 'connections',
        query: {
          bool: {
            should: typesFilters,
            minimum_should_match: 1,
          },
        },
      },
    });
  }
  const must = R.concat(
    [
      {
        bool: {
          should: [
            { match_phrase: { 'entity_type.keyword': type } },
            { match_phrase: { 'parent_types.keyword': type } },
          ],
          minimum_should_match: 1,
        },
      },
    ],
    filters
  );
  const markingRestrictions = buildMarkingRestriction(user);
  must.push(...markingRestrictions.must);
  const query = {
    index: READ_RELATIONSHIPS_INDICES,
    ignore_throttled: ES_IGNORE_THROTTLED,
    body: {
      size: MAX_SEARCH_AGGREGATION_SIZE,
      query: {
        bool: {
          must,
          must_not: markingRestrictions.must_not,
        },
      },
      aggs: {
        connections: {
          nested: {
            path: 'connections',
          },
          aggs: {
            filtered: {
              filter: {
                bool: {
                  must: typesFilters.length > 0 && !noDirection ? roleFilter : [],
                },
              },
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
      },
    },
  };
  logApp.debug('[SEARCH ENGINE] aggregationRelationsCount', { query });
  return elRawSearch(query)
    .then(async (data) => {
      if (field === 'internal_id') {
        const { buckets } = data.aggregations.connections.filtered.genres;
        const filteredBuckets = R.filter((b) => b.key !== fromId, buckets);
        return R.map((b) => ({ label: b.key, value: b.parent.weight.value }), filteredBuckets);
      }
      let fromType = null;
      if (fromId) {
        const fromEntity = await elLoadById(user, fromId);
        fromType = fromEntity.entity_type;
      }
      const types = R.pipe(
        R.map((h) => h._source.connections),
        R.flatten(),
        R.filter((c) => c.internal_id !== fromId && !R.includes(fromType, c.types)),
        R.filter((c) => toTypes.length === 0 || R.includes(R.head(toTypes), c.types)),
        R.map((e) => e.types),
        R.flatten(),
        R.uniq(),
        R.filter((f) => !isAbstract(f)),
        R.map((u) => u.toLowerCase())
      )(data.hits.hits);
      const { buckets } = data.aggregations.connections.filtered.genres;
      const filteredBuckets = R.filter((b) => R.includes(b.key, types), buckets);
      return R.map((b) => ({ label: pascalize(b.key), value: b.parent.weight.value }), filteredBuckets);
    })
    .catch((e) => {
      throw DatabaseError('Fail processing AggregationRelationsCount', { error: e });
    });
};
export const elHistogramCount = async (user, type, field, interval, start, end, toTypes, filters) => {
  const histogramFilters = R.map((f) => {
    const { isRelation = false, isNested = false, type: filterType, value, operator = 'eq' } = f;
    if (isNested) {
      const [path] = filterType.split('.');
      return {
        nested: {
          path,
          query: {
            bool: {
              must: [{ match_phrase: { [filterType]: value } }],
            },
          },
        },
      };
    }
    let key = `${filterType}.keyword`;
    if (operator === 'wilcard') {
      key = `${filterType}`;
    }
    if (isRelation) {
      key = buildRefRelationSearchKey(filterType || '*');
    }
    return {
      multi_match: {
        fields: [key],
        type: 'phrase',
        query: value,
      },
    };
  }, filters);
  let dateFormat;
  switch (interval) {
    case 'year':
      dateFormat = 'yyyy';
      break;
    case 'month':
      dateFormat = 'yyyy-MM';
      break;
    case 'day':
      dateFormat = 'yyyy-MM-dd';
      break;
    default:
      throw FunctionalError('Unsupported interval, please choose between year, month or day', interval);
  }
  let baseFilters = [
    {
      range: {
        [field]: {
          gte: start,
          lte: end ?? now(),
        },
      },
    },
  ];
  if (type) {
    baseFilters = R.append(
      {
        bool: {
          should: [
            { match_phrase: { 'entity_type.keyword': type } },
            { match_phrase: { 'parent_types.keyword': type } },
          ],
          minimum_should_match: 1,
        },
      },
      baseFilters
    );
  }
  const typesFilters = [];
  for (let index = 0; index < toTypes.length; index += 1) {
    typesFilters.push({
      match_phrase: { 'connections.types.keyword': toTypes[index] },
    });
  }
  if (typesFilters.length > 0) {
    baseFilters.push({
      nested: {
        path: 'connections',
        query: {
          bool: {
            should: typesFilters,
            minimum_should_match: 1,
          },
        },
      },
    });
  }
  const must = R.concat(baseFilters, histogramFilters);
  const markingRestrictions = buildMarkingRestriction(user);
  must.push(...markingRestrictions.must);
  const query = {
    index: READ_PLATFORM_INDICES,
    ignore_throttled: ES_IGNORE_THROTTLED,
    _source_excludes: '*', // Dont need to get anything
    body: {
      query: {
        bool: {
          must,
          must_not: markingRestrictions.must_not,
        },
      },
      aggs: {
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
      },
    },
  };
  logApp.debug('[SEARCH ENGINE] histogramCount', { query });
  return elRawSearch(query).then((data) => {
    const { buckets } = data.aggregations.count_over_time;
    const dataToPairs = R.toPairs(buckets);
    return R.map((b) => ({ date: R.head(b), value: R.last(b).weight.value }), dataToPairs);
  });
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
export const elGenerateFullTextSearchShould = (search) => {
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
      querySearch.push(`${cleanElement}*`);
    }
  }
  // Return the elastic search engine expected bool should terms
  const shouldSearch = [];
  const cleanExactSearch = exactSearch.map((e) => e.replace(/"|http?:/g, ''));
  shouldSearch.push(
    ...R.flatten(
      cleanExactSearch.map((ex) => [
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
      ])
    )
  );
  shouldSearch.push(
    ...R.flatten(
      querySearch.map((ex) => [
        {
          query_string: {
            query: ex,
            analyze_wildcard: true,
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
                      query: ex,
                      analyze_wildcard: true,
                      fields: BASE_SEARCH_CONNECTIONS,
                    },
                  },
                ],
              },
            },
          },
        },
      ])
    )
  );
  return shouldSearch;
};

const BASE_FIELDS = ['_index', 'internal_id', 'standard_id', 'sort', 'base_type', 'entity_type',
  'connections', 'first_seen', 'last_seen', 'start_time', 'stop_time'];
export const elPaginate = async (user, indexName, options = {}) => {
  // eslint-disable-next-line no-use-before-define
  const { ids = [], baseData = false, first = 200, after, orderBy = null, orderMode = 'asc' } = options;
  const { types = null, filters = [], filterMode = 'and', search = null, connectionFormat = true } = options;
  const searchAfter = after ? cursorToOffset(after) : undefined;
  let must = [];
  let mustnot = [];
  let ordering = [];
  const markingRestrictions = buildMarkingRestriction(user);
  must.push(...markingRestrictions.must);
  mustnot.push(...markingRestrictions.must_not);
  if (ids.length > 0) {
    const idsTermsPerType = [];
    const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
    for (let i = 0; i < ids.length; i += 1) {
      const id = ids[i];
      for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
        const elementType = elementTypes[indexType];
        const term = { [`${elementType}.keyword`]: id };
        idsTermsPerType.push({ term });
      }
    }
    must = R.append({ bool: { should: idsTermsPerType, minimum_should_match: 1 } }, must);
  }
  if (types !== null && types.length > 0) {
    const should = R.flatten(
      types.map((typeValue) => {
        return [
          { match_phrase: { 'entity_type.keyword': typeValue } },
          { match_phrase: { 'parent_types.keyword': typeValue } },
        ];
      })
    );
    must = R.append({ bool: { should, minimum_should_match: 1 } }, must);
  }
  let mustFilters = [];
  const validFilters = R.filter((f) => f?.values?.length > 0 || f?.nested?.length > 0, filters || []);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const { key, values, nested, operator = 'eq', filterMode: localFilterMode = 'or' } = validFilters[index];
      // const rulesKeys = getAttributesRulesFor(key);
      // TODO IF KEY is PART OF Rule we need to add extra fields search
      if (nested) {
        const nestedMust = [];
        for (let nestIndex = 0; nestIndex < nested.length; nestIndex += 1) {
          const nestedElement = nested[nestIndex];
          const { key: nestedKey, values: nestedValues, operator: nestedOperator = 'eq' } = nestedElement;
          const nestedShould = [];
          for (let i = 0; i < nestedValues.length; i += 1) {
            if (nestedOperator === 'wildcard') {
              nestedShould.push({
                query_string: {
                  query: `${nestedValues[i].toString()}`,
                  fields: [`${key}.${nestedKey}`],
                },
              });
            } else {
              nestedShould.push({
                match_phrase: { [`${key}.${nestedKey}`]: nestedValues[i].toString() },
              });
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
          path: key,
          query: {
            bool: {
              must: nestedMust,
            },
          },
        };
        mustFilters = R.append({ nested: nestedQuery }, mustFilters);
      } else {
        for (let i = 0; i < values.length; i += 1) {
          if (values[i] === null) {
            mustnot = R.append({ exists: { field: key } }, mustnot);
          } else if (values[i] === 'EXISTS') {
            valuesFiltering.push({ exists: { field: key } });
          } else if (operator === 'eq') {
            const isDateOrNumber = dateAttributes.includes(key) || numericOrBooleanAttributes.includes(key);
            valuesFiltering.push({
              match_phrase: { [`${isDateOrNumber ? key : `${key}.keyword`}`]: values[i].toString() },
            });
          } else if (operator === 'match') {
            valuesFiltering.push({
              match_phrase: { [key]: values[i].toString() },
            });
          } else if (operator === 'wildcard') {
            valuesFiltering.push({
              query_string: {
                query: `"${values[i].toString()}"`,
                fields: [key],
              },
            });
          } else {
            valuesFiltering.push({ range: { [key]: { [operator]: values[i] } } });
          }
        }
        mustFilters = R.append(
          {
            bool: {
              should: valuesFiltering,
              minimum_should_match: localFilterMode === 'or' ? 1 : valuesFiltering.length,
            },
          },
          mustFilters
        );
      }
    }
  }
  if (filterMode === 'or') {
    must = R.append({ bool: { should: mustFilters, minimum_should_match: 1 } }, must);
  } else {
    must = [...must, ...mustFilters];
  }
  if (search !== null && search.length > 0) {
    const shouldSearch = elGenerateFullTextSearchShould(search);
    const bool = {
      bool: {
        should: shouldSearch,
        minimum_should_match: 1,
      },
    };
    must = R.append(bool, must);
  }
  // Handle orders
  if (isNotEmptyField(orderBy)) {
    const orderCriterion = Array.isArray(orderBy) ? orderBy : [orderBy];
    for (let index = 0; index < orderCriterion.length; index += 1) {
      const orderCriteria = orderCriterion[index];
      const isDateOrNumber = dateAttributes.includes(orderCriteria) || numericOrBooleanAttributes.includes(orderCriteria);
      const orderKeyword = isDateOrNumber ? orderCriteria : `${orderCriteria}.keyword`;
      const order = { [orderKeyword]: orderMode };
      ordering = R.append(order, ordering);
      must = R.append({ exists: { field: orderKeyword } }, must);
    }
    // Add standard_id if not specify to ensure ordering uniqueness
    if (!orderCriterion.includes('standard_id')) {
      ordering.push({ 'standard_id.keyword': 'asc' });
    }
  } else if (search !== null && search.length > 0) {
    ordering.push({ _score: 'desc' });
  } else { // If not ordering criteria, order by standard_id
    ordering.push({ 'standard_id.keyword': 'asc' });
  }
  // Build runtime mappings
  const runtimeMappings = {};
  if (isRuntimeAttribute(orderBy)) {
    const runtime = RUNTIME_ATTRIBUTES[orderBy];
    if (isEmptyField(runtime)) {
      throw UnsupportedError(`Unsupported runtime field ${orderBy}`);
    }
    const source = await runtime.getSource();
    const params = await runtime.getParams(user);
    runtimeMappings[runtime.field] = {
      type: runtime.type,
      script: { source, params },
    };
  }
  // Build query
  const querySize = first || 10;
  const body = {
    size: querySize,
    sort: ordering,
    query: {
      bool: {
        must,
        must_not: mustnot,
      },
    },
  };
  // Add extra configuration
  if (isNotEmptyField(runtimeMappings)) {
    const isRuntimeSortFeatureEnable = isRuntimeSortEnable();
    if (!isRuntimeSortFeatureEnable) {
      throw UnsupportedError(`Sorting of field ${orderBy} is only possible with elastic >=7.12`);
    }
    body.runtime_mappings = runtimeMappings;
  }
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  if (querySize > ES_MAX_PAGINATION) {
    const message = `You cannot ask for more than ${ES_MAX_PAGINATION} results. If you need more, please use pagination`;
    throw DatabaseError(message, { body });
  }
  const query = {
    index: indexName,
    ignore_throttled: ES_IGNORE_THROTTLED,
    track_total_hits: true,
    _source: baseData ? BASE_FIELDS : true,
    body,
  };
  logApp.debug('[SEARCH ENGINE] paginate', { query });
  return elRawSearch(query)
    .then((data) => {
      const convertedHits = R.map((n) => elDataConverter(n), data.hits.hits);
      if (connectionFormat) {
        const nodeHits = R.map((n) => ({ node: n, sort: n.sort }), convertedHits);
        return buildPagination(first, searchAfter, nodeHits, data.hits.total.value);
      }
      return convertedHits;
    })
    .catch(
      /* istanbul ignore next */ (err) => {
        // Because we create the mapping at element creation
        // We log the error only if its not a mapping not found error
        let isTechnicalError = true;
        if (isNotEmptyField(err.meta.body)) {
          const numberOfCauses = err.meta.body.error.root_cause.length;
          const invalidMappingCauses = R.pipe(
            R.map((r) => r.reason ?? ''),
            R.filter((r) => R.includes('No mapping found for', r) || R.includes('no such index', r))
          )(err.meta.body.error.root_cause);
          isTechnicalError = numberOfCauses > invalidMappingCauses.length;
        }
        // If uncontrolled error, log and propagate
        if (isTechnicalError) {
          logApp.error('[SEARCH ENGINE] Paginate fail', { error: err, query });
          throw err;
        } else {
          return connectionFormat ? buildPagination(0, null, [], 0) : [];
        }
      }
    );
};
export const elList = async (user, indexName, options = {}) => {
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
    const elements = await elPaginate(user, indexName, opts);
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
export const elLoadBy = async (user, field, value, type = null, indices = READ_DATA_INDICES) => {
  const opts = { filters: [{ key: field, values: [value] }], connectionFormat: false, types: type ? [type] : [] };
  const hits = await elPaginate(user, indices, opts);
  if (hits.length > 1) throw UnsupportedError(`Expected only one response, found ${hits.length}`);
  return R.head(hits);
};
export const elAttributeValues = async (user, field, opts = {}) => {
  const { first, orderMode = 'asc', search } = opts;
  const markingRestrictions = buildMarkingRestriction(user);
  const isDateOrNumber = dateAttributes.includes(field) || numericOrBooleanAttributes.includes(field);
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
          size: first,
          order: { _key: orderMode },
        },
      },
    },
  };
  const query = {
    index: [READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS],
    ignore_throttled: ES_IGNORE_THROTTLED,
    body,
  };
  const data = await elRawSearch(query);
  const { buckets } = data.aggregations.values;
  const values = (buckets ?? []).map((n) => n.key);
  const nodeElements = values.map((val) => ({ node: { id: val, key: field, value: val } }));
  return buildPagination(0, null, nodeElements, nodeElements.length);
};
// endregion

export const elBulk = async (args) => {
  return el
    .bulk(args)
    .then((result) => {
      const data = oebp(result);
      if (data.errors) {
        const errors = data.items.map((i) => i.index?.error || i.update?.error).filter((f) => f !== undefined);
        throw DatabaseError('Error executing bulk indexing', { errors });
      }
      return result;
    })
    .catch((e) => {
      throw DatabaseError('Error updating elastic', { error: e });
    });
};
/* istanbul ignore next */
export const elReindex = async (indices) => {
  return Promise.all(
    indices.map((indexMap) => {
      return el.reindex({
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
  logApp.debug(`[SEARCH ENGINE] index > ${entityType} ${internalId} in ${indexName}`, documentBody);
  await el
    .index({
      index: indexName,
      id: documentBody.internal_id,
      refresh,
      timeout: '60m',
      body: R.dissoc('_index', documentBody),
    })
    .catch((err) => {
      throw DatabaseError('Error indexing elastic', { error: err, body: documentBody });
    });
  return documentBody;
};
/* istanbul ignore next */
export const elUpdate = (indexName, documentId, documentBody, retry = ES_RETRY_ON_CONFLICT) => {
  return el
    .update({
      id: documentId,
      index: indexName,
      retry_on_conflict: retry,
      timeout: BULK_TIMEOUT,
      refresh: true,
      body: documentBody,
    })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err, documentId, body: documentBody });
    });
};
export const elReplace = (indexName, documentId, documentBody) => {
  const doc = R.dissoc('_index', documentBody.doc);
  const entries = Object.entries(doc);
  const rawSources = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (isEmptyField(val)) {
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

const getRelatedRelations = async (user, targetIds, elements, level, cache) => {
  const elementIds = Array.isArray(targetIds) ? targetIds : [targetIds];
  const filters = [{ nested: [{ key: 'internal_id', values: elementIds }], key: 'connections' }];
  const opts = { filters, connectionFormat: false, types: [ABSTRACT_BASIC_RELATIONSHIP] };
  const hits = await elList(user, READ_RELATIONSHIPS_INDICES, opts);
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
    const groups = R.splitEvery(MAX_SPLIT, foundRelations);
    const concurrentFetch = (gIds) => getRelatedRelations(user, gIds, elements, level + 1, cache);
    await BluePromise.map(groups, concurrentFetch, { concurrency: ES_MAX_CONCURRENCY });
  }
};
export const getRelationsToRemove = async (user, elements) => {
  const relationsToRemoveMap = new Map();
  const relationsToRemove = [];
  const ids = elements.map((e) => e.internal_id);
  await getRelatedRelations(user, ids, relationsToRemove, 0, relationsToRemoveMap);
  return { relations: R.flatten(relationsToRemove), relationsToRemoveMap };
};
export const elDeleteInstances = async (instances) => {
  // If nothing to delete, return immediately to prevent elastic to delete everything
  if (instances.length > 0) {
    logApp.debug(`[SEARCH ENGINE] Deleting ${instances.length} instances`);
    const bodyDelete = instances.flatMap((doc) => {
      return [{ delete: { _index: doc._index, _id: doc.internal_id, retry_on_conflict: ES_RETRY_ON_CONFLICT } }];
    });
    const cachePromise = cacheDel(instances);
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyDelete });
    await Promise.all([cachePromise, bulkPromise]);
  }
};
const elRemoveRelationConnection = async (user, relsFromTo) => {
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
    const dataIds = await elFindByIds(user, idsToResolve);
    const indexCache = R.mergeAll(dataIds.map((element) => ({ [element.internal_id]: element._index })));
    const bodyUpdateRaw = relsFromTo.map(({ relation, isFromCleanup, isToCleanup }) => {
      const type = buildRefRelationKey(relation.entity_type);
      const updates = [];
      const fromIndex = indexCache[relation.fromId];
      if (isFromCleanup && fromIndex) {
        let source = `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`;
        if (isStixMetaRelationship(relation.entity_type)) {
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
    const cachePromise = cacheDel(dataIds);
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    await Promise.all([cachePromise, bulkPromise]);
  }
};

export const elDeleteElements = async (user, elements, stixLoadById) => {
  if (elements.length === 0) return [];
  const toBeRemovedIds = elements.map((e) => e.internal_id);
  const opts = { concurrency: ES_MAX_CONCURRENCY };
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(user, elements);
  const stixRelations = relations.filter((r) => isStixRelationShipExceptMeta(r.relationship_type));
  const dependencyDeletions = await BluePromise.map(stixRelations, (r) => stixLoadById(user, r.internal_id), opts);
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
  const groupsOfDeletions = R.splitEvery(MAX_SPLIT, relations);
  const concurrentDeletions = async (deletions) => {
    await elDeleteInstances(deletions);
    currentRelationsDelete += deletions.length;
    logApp.debug(`[OPENCTI] Deleting related relations ${currentRelationsDelete} / ${relations.length}`);
  };
  await BluePromise.map(groupsOfDeletions, concurrentDeletions, opts);
  // Remove the elements
  await elDeleteInstances(elements);
  // Update all rel connections that will remain
  let currentRelationsCount = 0;
  const groupsOfRelsFromTo = R.splitEvery(MAX_SPLIT, relsFromToImpacts);
  const concurrentRelsFromTo = async (relsToClean) => {
    await elRemoveRelationConnection(user, relsToClean);
    currentRelationsCount += relsToClean.length;
    logApp.debug(`[OPENCTI] Updating relations for deletion ${currentRelationsCount} / ${relsFromToImpacts.length}`);
  };
  await BluePromise.map(groupsOfRelsFromTo, concurrentRelsFromTo, opts);
  // Return the relations deleted because of the entity deletion
  return dependencyDeletions;
};

export const prepareElementForIndexing = (element) => {
  const thing = {};
  Object.keys(element).forEach((key) => {
    const value = element[key];
    if (Array.isArray(value)) {
      const filteredArray = value.filter((i) => i);
      thing[key] = filteredArray.length > 0 ? filteredArray : [];
    } else if (isBooleanAttribute(key)) {
      // patch field is string generic so need to be cast to boolean
      thing[key] = typeof value === 'boolean' ? value : value?.toLowerCase() === 'true';
    } else {
      thing[key] = value;
    }
  });
  return thing;
};
const prepareRelation = (thing) => {
  if (thing.fromRole === undefined || thing.toRole === undefined) {
    throw DatabaseError(`[ELASTIC] Cant index relation ${thing.internal_id} connections without from or to`, thing);
  }
  const connections = [];
  if (!thing.from || !thing.to) {
    throw DatabaseError(`[ELASTIC] Cant index relation ${thing.internal_id}, error resolving dependency IDs`, {
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
export const elIndexElements = async (elements) => {
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
      const relationshipType = e.entity_type;
      const impacts = [];
      // We impact target entities of the relation only if not global entities like
      // MarkingDefinition (marking) / KillChainPhase (kill_chain_phase) / Label (tagging)
      cache[e.fromId] = e.from;
      cache[e.toId] = e.to;
      if (isImpactedRole(fromRole)) {
        impacts.push({ from: e.fromId, relationshipType, to: e.to, type: e.to.entity_type, side: 'from' });
      }
      if (isImpactedRole(toRole)) {
        impacts.push({ from: e.toId, relationshipType, to: e.from, type: e.from.entity_type, side: 'to' });
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
    const targetsByRelation = R.groupBy((i) => i.relationshipType, targets);
    const targetsElements = R.map((relType) => {
      const data = targetsByRelation[relType];
      const resolvedData = R.map((d) => {
        return { id: d.to.internal_id, side: d.side, type: d.type };
      }, data);
      return { relation: relType, elements: resolvedData };
    }, Object.keys(targetsByRelation));
    // Create params and scripted update
    const params = { updated_at: now() };
    const sources = R.map((t) => {
      const field = buildRefRelationKey(t.relation);
      let script = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
      script += `ctx._source['${field}'].addAll(params['${field}'])`;
      if (isStixMetaRelationship(t.relation)) {
        const fromSide = R.find((e) => e.side === 'from', t.elements);
        if (fromSide && isUpdatedAtObject(fromSide.type)) {
          script += '; ctx._source[\'updated_at\'] = params.updated_at';
        }
        if (fromSide && isModifiedObject(fromSide.type)) {
          script += '; ctx._source[\'modified\'] = params.updated_at';
        }
      }
      return script;
    }, targetsElements);
    const source = sources.length > 1 ? R.join(';', sources) : `${R.head(sources)};`;
    for (let index = 0; index < targetsElements.length; index += 1) {
      const targetElement = targetsElements[index];
      params[buildRefRelationKey(targetElement.relation)] = targetElement.elements.map((e) => e.id);
    }
    return { ...entity, id: entityId, data: { script: { source, params } } };
  });
  const bodyUpdate = elementsToUpdate.flatMap((doc) => [
    { update: { _index: doc._index, _id: doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
    R.dissoc('_index', doc.data),
  ]);
  if (bodyUpdate.length > 0) {
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    const cachePromise = cacheDel(elementsToUpdate);
    await Promise.all([cachePromise, bulkPromise]);
  }
  return transformedElements.length;
};

export const elUpdateAttributeValue = async (key, previousValue, value) => {
  const isMultiple = isMultipleAttribute(key);
  const source = !isMultiple
    ? 'ctx._source[params.key] = params.value'
    : `def index = 0;
       for (att in ctx._source[params.key]) {
        if(att == params.previousValue) {
          ctx._source[params.key][index] = params.value;
        }
        index++;
       }`;
  const query = { match_phrase: { [`${key}.keyword`]: previousValue } };
  const params = {
    index: READ_DATA_INDICES,
    refresh: true,
    body: {
      script: { source, params: { key, value, previousValue } },
      query,
    },
  };
  const cachePromise = cachePurge();
  const updatePromise = el.updateByQuery(params).catch((err) => {
    throw DatabaseError('Updating attribute value fail', { error: err, key, value });
  });
  await Promise.all([cachePromise, updatePromise]);
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
    const cachePromise = cacheDel(elements);
    await Promise.all([cachePromise, bulkPromise]);
  }
};
export const elUpdateEntityConnections = async (elements) => {
  if (elements.length > 0) {
    const source = `if (ctx._source[params.key] == null) {
      ctx._source[params.key] = [params.to];
    } else if (params.from == null) {
      ctx._source[params.key].addAll(params.to);
    } else {
      def values = [params.to];
      for (current in ctx._source[params.key]) {
        if (current != params.from) { values.add(current); }
      }
      ctx._source[params.key] = values;
    }
  `;
    const addMultipleFormat = (doc) => {
      if (doc.toReplace === null && !Array.isArray(doc.data.internal_id)) {
        return [doc.data.internal_id];
      }
      return doc.data.internal_id;
    };
    const bodyUpdate = elements.flatMap((doc) => [
      { update: { _index: doc._index, _id: doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
      {
        script: {
          source,
          params: { key: buildRefRelationKey(doc.relationType), from: doc.toReplace, to: addMultipleFormat(doc) },
        },
      },
    ]);
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    const cachePromise = cacheDel(elements);
    await Promise.all([cachePromise, bulkPromise]);
  }
};

export const elUpdateConnectionsOfElement = async (documentId, documentBody) => {
  const source = 'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); '
    + 'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
  return el
    .updateByQuery({
      index: READ_RELATIONSHIPS_INDICES,
      refresh: true,
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
    })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err, documentId, body: documentBody });
    });
};
export const elUpdateElement = async (instance) => {
  // Update the element it self
  const esData = prepareElementForIndexing(instance);
  // Set the cache
  const cachePromise = cacheDel([esData]);
  const replacePromise = elReplace(instance._index, instance.internal_id, { doc: esData });
  // If entity with a name, must update connections
  let connectionPromise = Promise.resolve();
  if (esData.name && isStixObject(instance.entity_type)) {
    connectionPromise = elUpdateConnectionsOfElement(instance.internal_id, { name: esData.name });
  }
  await Promise.all([cachePromise, replacePromise, connectionPromise]);
};

export const getStats = () => {
  return el.indices
    .stats({ index: READ_PLATFORM_INDICES }) //
    .then((result) => oebp(result)._all.total);
};
