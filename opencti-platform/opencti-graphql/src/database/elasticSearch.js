/* eslint-disable no-underscore-dangle */
import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import * as R from 'ramda';
import {
  buildPagination,
  INDEX_INTERNAL_OBJECTS,
  INDEX_INTERNAL_RELATIONSHIPS,
  INDEX_STIX_CORE_RELATIONSHIPS,
  INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  INDEX_STIX_CYBER_OBSERVABLES,
  INDEX_STIX_DOMAIN_OBJECTS,
  INDEX_STIX_META_OBJECTS,
  INDEX_STIX_META_RELATIONSHIPS,
  INDEX_STIX_SIGHTING_RELATIONSHIPS,
  inferIndexFromConceptType,
  isNotEmptyField,
  pascalize,
} from './utils';
import conf, { logger } from '../config/conf';
import { ConfigurationError, DatabaseError, FunctionalError } from '../config/errors';
import {
  RELATION_CREATED_BY,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  BASE_TYPE_RELATION,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INTERNAL_IDS_ALIASES,
  isAbstract,
  REL_INDEX_PREFIX,
} from '../schema/general';
import {
  dateAttributes,
  isBooleanAttribute,
  isMultipleAttribute,
  numericOrBooleanAttributes,
} from '../schema/fieldDataAdapter';
import { getParentTypes } from '../schema/schemaUtils';
import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  isStixObjectAliased,
} from '../schema/stixDomainObject';
import { isStixObject } from '../schema/stixCoreObject';
import {
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';

const MAX_AGGREGATION_SIZE = 100;
const MAX_SEARCH_AGGREGATION_SIZE = 10000;
const MAX_SEARCH_SIZE = 10000;
export const INDEX_HISTORY = 'opencti_history';
const UNIMPACTED_ENTITIES = [
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
];
const UNIMPACTED_ENTITIES_ROLE = [
  `${RELATION_CREATED_BY}_to`,
  `${RELATION_OBJECT_MARKING}_to`,
  `${RELATION_OBJECT_LABEL}_to`,
  `${RELATION_KILL_CHAIN_PHASE}_to`,
];
export const isUnimpactedEntity = (entity) => UNIMPACTED_ENTITIES.includes(entity.entity_type);
export const isImpactedType = (type) => !UNIMPACTED_ENTITIES.includes(type);

export const DATA_INDICES = [
  INDEX_INTERNAL_OBJECTS,
  INDEX_STIX_META_OBJECTS,
  INDEX_STIX_DOMAIN_OBJECTS,
  INDEX_STIX_CYBER_OBSERVABLES,
  INDEX_INTERNAL_RELATIONSHIPS,
  INDEX_STIX_CORE_RELATIONSHIPS,
  INDEX_STIX_SIGHTING_RELATIONSHIPS,
  INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  INDEX_STIX_META_RELATIONSHIPS,
];
export const PLATFORM_INDICES = [INDEX_HISTORY, ...DATA_INDICES];
export const ENTITIES_INDICES = [
  INDEX_INTERNAL_OBJECTS,
  INDEX_STIX_META_OBJECTS,
  INDEX_STIX_DOMAIN_OBJECTS,
  INDEX_STIX_CYBER_OBSERVABLES,
];
export const RELATIONSHIPS_INDICES = [
  INDEX_INTERNAL_RELATIONSHIPS,
  INDEX_STIX_CORE_RELATIONSHIPS,
  INDEX_STIX_SIGHTING_RELATIONSHIPS,
  INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  INDEX_STIX_META_RELATIONSHIPS,
];

export const useCache = (args = {}) => {
  const { noCache = false, infer = false } = args;
  return !infer && !noCache && !conf.get('elasticsearch:noQueryCache');
};
export const el = new Client({ node: conf.get('elasticsearch:url') });

export const elIsAlive = async () => {
  return el
    .info()
    .then((info) => {
      /* istanbul ignore if */
      if (info.meta.connection.status !== 'alive') {
        throw ConfigurationError('ElasticSearch seems down');
      }
      return true;
    })
    .catch(
      /* istanbul ignore next */ () => {
        throw ConfigurationError('ElasticSearch seems down');
      }
    );
};
export const elVersion = () => {
  return el
    .info()
    .then((info) => info.body.version.number)
    .catch(
      /* istanbul ignore next */ () => {
        return 'Disconnected';
      }
    );
};
export const elIndexExists = async (indexName) => {
  const existIndex = await el.indices.exists({ index: indexName });
  return existIndex.body === true;
};
export const elCreateIndexes = async (indexesToCreate = PLATFORM_INDICES) => {
  return Promise.all(
    indexesToCreate.map((index) => {
      return el.indices.exists({ index }).then((result) => {
        if (result.body === false) {
          return el.indices.create({
            index,
            body: {
              settings: {
                index: {
                  max_result_window: 100000,
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
          });
        }
        /* istanbul ignore next */
        return result;
      });
    })
  );
};
export const elDeleteIndexes = async (indexesToDelete) => {
  return Promise.all(
    indexesToDelete.map((index) => {
      return el.indices.delete({ index }).catch((err) => {
        /* istanbul ignore next */
        if (err.meta.body && err.meta.body.error.type !== 'index_not_found_exception') {
          logger.error(`[ELASTICSEARCH] Delete indices fail`, { error: err });
        }
      });
    })
  );
};

export const elCount = (indexName, options = {}) => {
  const {
    endDate = null,
    types = null,
    relationshipType = null,
    fromId = null,
    toTypes = null,
    isMetaRelationship = false,
  } = options;
  let must = [];
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
  if (fromId !== null) {
    if (isMetaRelationship) {
      must = R.append(
        {
          bool: {
            should: {
              match_phrase: { [`${REL_INDEX_PREFIX}${relationshipType}.internal_id.keyword`]: fromId },
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
                must: [{ match_phrase: { [`connections.internal_id`]: fromId } }],
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
        match_phrase: { 'connections.types': toTypes[index] },
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
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] countEntities`, { query });
  return el
    .count(query)
    .then((data) => {
      return data.body.count;
    })
    .catch((err) => {
      throw DatabaseError('Count data fail', { error: err, query });
    });
};
export const elAggregationCount = (type, aggregationField, start, end, filters) => {
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
    const key = f.isRelation ? `${REL_INDEX_PREFIX}${f.type ? f.type : '*'}.internal_id.keyword` : `${f.type}.keyword`;
    return {
      multi_match: {
        fields: [key],
        type: 'phrase',
        query: f.value,
      },
    };
  }, filters);
  const query = {
    index: PLATFORM_INDICES,
    body: {
      size: MAX_SEARCH_AGGREGATION_SIZE,
      query: {
        bool: {
          must: R.concat(dateFilter, histoFilters),
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
            field: `${aggregationField}.keyword`,
            size: MAX_AGGREGATION_SIZE,
          },
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] aggregationCount`, { query });
  return el
    .search(query)
    .then((data) => {
      const { buckets } = data.body.aggregations.genres;
      return R.map((b) => ({ label: pascalize(b.key), value: b.doc_count }), buckets);
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
    [`${type}Type`]: R.head(connection.types),
  };
};
const elMergeRelation = (concept, fromConnection, toConnection) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError(`[ELASTIC] Something fail in reconstruction of the relation`, concept.internal_id);
  }
  const from = elBuildRelation('from', fromConnection);
  const to = elBuildRelation('to', toConnection);
  return R.mergeAll([concept, from, to]);
};
export const elReconstructRelation = (concept) => {
  const { connections } = concept;
  const entityType = concept.entity_type;
  const fromConnection = R.find((connection) => connection.role === `${entityType}_from`, connections);
  const toConnection = R.find((connection) => connection.role === `${entityType}_to`, connections);
  return elMergeRelation(concept, fromConnection, toConnection);
};
// endregion
export const elFindByFromAndTo = async (fromId, toId, relationshipType) => {
  const mustTerms = [];
  mustTerms.push({
    nested: {
      path: 'connections',
      query: {
        bool: {
          must: [
            { match_phrase: { 'connections.internal_id': fromId } },
            // { query_string: { query: `*_from`, fields: [`connections.role`] } },
          ],
        },
      },
    },
  });
  mustTerms.push({
    nested: {
      path: 'connections',
      query: {
        bool: {
          must: [
            { match_phrase: { 'connections.internal_id': toId } },
            // { query_string: { query: `*_to`, fields: [`connections.role`] } },
          ],
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
    index: RELATIONSHIPS_INDICES,
    size: MAX_SEARCH_SIZE,
    _source_excludes: `${REL_INDEX_PREFIX}*`,
    body: {
      query: {
        bool: {
          must: mustTerms,
        },
      },
    },
  };
  const data = await el.search(query).catch((e) => {
    throw DatabaseError('Find by from and to fail', { error: e, query });
  });
  const hits = [];
  for (let index = 0; index < data.body.hits.hits.length; index += 1) {
    const hit = data.body.hits.hits[index];
    const loadedElement = R.assoc('_index', hit._index, hit._source);
    hits.push(elReconstructRelation(loadedElement));
  }
  return hits;
};

const elFindBy = async (fields, values, type = null, indices = DATA_INDICES) => {
  const mustTerms = [];
  const valsArray = Array.isArray(values) ? values : [values];
  const fieldsArray = Array.isArray(fields) ? fields : [fields];
  const workingVals = R.filter((id) => isNotEmptyField(id), valsArray);
  if (workingVals.length === 0) return [];
  const valsTermsPerType = [];
  for (let index = 0; index < workingVals.length; index += 1) {
    const val = workingVals[index];
    for (let indexType = 0; indexType < fieldsArray.length; indexType += 1) {
      const field = fieldsArray[indexType];
      if (R.includes('connections.', field)) {
        valsTermsPerType.push({
          nested: {
            path: 'connections',
            query: {
              bool: {
                must: [{ match_phrase: { [field]: val } }],
              },
            },
          },
        });
      } else {
        const term = { [`${field}.keyword`]: val };
        valsTermsPerType.push({ term });
      }
    }
  }
  // const idsTermsPerType = map((e) => ({ [`${e}.keyword`]: id }), elementTypes);
  const should = {
    bool: {
      should: valsTermsPerType,
      minimum_should_match: 1,
    },
  };
  mustTerms.push(should);
  if (type) {
    const shouldType = {
      bool: {
        should: [{ match_phrase: { 'entity_type.keyword': type } }, { match_phrase: { 'parent_types.keyword': type } }],
        minimum_should_match: 1,
      },
    };
    mustTerms.push(shouldType);
  }
  const query = {
    index: indices,
    size: MAX_SEARCH_SIZE,
    track_total_hits: true,
    _source_excludes: `${REL_INDEX_PREFIX}*`,
    body: {
      query: {
        bool: {
          must: mustTerms,
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] elFindBy`, { query });
  const data = await el.search(query).catch((err) => {
    throw DatabaseError('Find data fail', { error: err, query });
  });
  const hits = [];
  const total = data.body.hits.total.value;
  for (let index = 0; index < data.body.hits.hits.length; index += 1) {
    const hit = data.body.hits.hits[index];
    let loadedElement = R.assoc('_index', hit._index, hit._source);
    // And a specific processing for a relation
    if (loadedElement.base_type === BASE_TYPE_RELATION) {
      loadedElement = elReconstructRelation(loadedElement);
    }
    hits.push(loadedElement);
  }
  return { total, hits };
};
export const elLoadBy = async (fields, values, type = null, indices = DATA_INDICES) => {
  const { total, hits } = await elFindBy(fields, values, type, indices);
  if (total > 1) throw Error(`Expected only one response, found ${total}`);
  return R.head(hits);
};

export const elFindByIds = async (ids, type = null, indices = DATA_INDICES) => {
  const mustTerms = [];
  const idsArray = Array.isArray(ids) ? ids : [ids];
  const workingIds = R.filter((id) => isNotEmptyField(id), idsArray);
  if (workingIds.length === 0) return [];
  const idsTermsPerType = [];
  const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
  if (isStixObjectAliased(type)) {
    elementTypes.push(INTERNAL_IDS_ALIASES);
  }
  for (let index = 0; index < workingIds.length; index += 1) {
    const id = workingIds[index];
    for (let indexType = 0; indexType < elementTypes.length; indexType += 1) {
      const elementType = elementTypes[indexType];
      const term = { [`${elementType}.keyword`]: id };
      idsTermsPerType.push({ term });
    }
  }
  // const idsTermsPerType = map((e) => ({ [`${e}.keyword`]: id }), elementTypes);
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
        should: [{ match_phrase: { 'entity_type.keyword': type } }, { match_phrase: { 'parent_types.keyword': type } }],
        minimum_should_match: 1,
      },
    };
    mustTerms.push(shouldType);
  }
  const query = {
    index: indices,
    size: MAX_SEARCH_SIZE,
    _source_excludes: `${REL_INDEX_PREFIX}*`,
    body: {
      query: {
        bool: {
          must: mustTerms,
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] elInternalLoadById`, { query });
  const data = await el.search(query).catch((err) => {
    throw DatabaseError('Error loading ids', { error: err, query });
  });
  const hits = [];
  for (let index = 0; index < data.body.hits.hits.length; index += 1) {
    const hit = data.body.hits.hits[index];
    let loadedElement = R.assoc('_index', hit._index, hit._source);
    // And a specific processing for a relation
    if (loadedElement.base_type === BASE_TYPE_RELATION) {
      loadedElement = elReconstructRelation(loadedElement);
    }
    hits.push(loadedElement);
  }
  return hits;
};
export const elLoadByIds = async (ids, type = null, indices = DATA_INDICES) => {
  const hits = await elFindByIds(ids, type, indices);
  /* istanbul ignore if */
  if (hits.length > 1) {
    const errorMeta = { ids, type, hits: hits.length };
    throw DatabaseError('Expect only one response', errorMeta);
  }
  return R.head(hits);
};

export const elBatchIds = async (ids) => {
  const hits = await elFindByIds(ids);
  return ids.map((id) => R.find((h) => h.internal_id === id, hits));
};

// field can be "entity_type" or "internal_id"
export const elAggregationRelationsCount = async (
  type,
  start,
  end,
  toTypes,
  fromId = null,
  field = null,
  dateAttribute = 'start_time',
  isTo = false,
  noDirection = false
) => {
  if (!R.includes(field, ['entity_type', 'internal_id', null])) {
    throw FunctionalError('Unsupported field', field);
  }
  const roleFilter = { query_string: { query: !isTo ? `*_to` : `*_from`, fields: [`connections.role`] } };
  const haveRange = start && end;
  const filters = [];
  if (haveRange) {
    filters.push({ range: { [dateAttribute]: { gte: start, lte: end } } });
  }
  if (fromId) {
    filters.push({
      nested: {
        path: 'connections',
        query: {
          bool: {
            must: [{ match_phrase: { [`connections.internal_id`]: fromId } }],
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
            // must: toRoleFilter,
            should: typesFilters,
            minimum_should_match: 1,
          },
        },
      },
    });
  }
  const query = {
    index: RELATIONSHIPS_INDICES,
    body: {
      size: MAX_SEARCH_AGGREGATION_SIZE,
      query: {
        bool: {
          must: R.concat(
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
          ),
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
                    field: field === 'internal_id' ? `connections.internal_id.keyword` : `connections.types.keyword`,
                  },
                },
              },
            },
          },
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] aggregationRelationsCount`, { query });
  return el.search(query).then(async (data) => {
    if (field === 'internal_id') {
      const { buckets } = data.body.aggregations.connections.filtered.genres;
      const filteredBuckets = R.filter((b) => b.key !== fromId, buckets);
      return R.map((b) => ({ label: b.key, value: b.doc_count }), filteredBuckets);
    }
    let fromType = null;
    if (fromId) {
      const fromEntity = await elLoadByIds(fromId);
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
    )(data.body.hits.hits);
    const { buckets } = data.body.aggregations.connections.filtered.genres;
    const filteredBuckets = R.filter((b) => R.includes(b.key, types), buckets);
    return R.map((b) => ({ label: pascalize(b.key), value: b.doc_count }), filteredBuckets);
  });
};
export const elHistogramCount = async (type, field, interval, start, end, filters) => {
  // const tzStart = moment.parseZone(start).format('Z');
  // Filter: { type: 'relation/attribute/nested' }
  const histogramFilters = R.map((f) => {
    // isRelation: false, isNested: true, type: 'connections.internal_id', value: fromId
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
      key = filterType ? `${REL_INDEX_PREFIX}${f.type}.internal_id` : `${REL_INDEX_PREFIX}*.internal_id`;
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
          lte: end,
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
  const query = {
    index: PLATFORM_INDICES,
    _source_excludes: '*', // Dont need to get anything
    body: {
      query: {
        bool: {
          must: R.concat(baseFilters, histogramFilters),
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
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] histogramCount`, { query });
  return el.search(query).then((data) => {
    const { buckets } = data.body.aggregations.count_over_time;
    const dataToPairs = R.toPairs(buckets);
    return R.map((b) => ({ date: R.head(b), value: R.last(b).doc_count }), dataToPairs);
  });
};

// region elastic common loader.
export const specialElasticCharsEscape = (query) => {
  return query.replace(/([+|\-*()~={}[\]:?\\])/g, '\\$1');
};
export const elPaginate = async (indexName, options = {}) => {
  const { first = 200, after, orderBy = null, orderMode = 'asc' } = options;
  const { types = null, filters = [], search = null, connectionFormat = true } = options;
  const offset = after ? cursorToOffset(after) : 0;
  let must = [];
  let mustnot = [];
  let ordering = [];
  if (search !== null && search.length > 0) {
    // Try to decode before search
    let decodedSearch;
    try {
      decodedSearch = decodeURIComponent(search);
    } catch (e) {
      decodedSearch = search;
    }
    const cleanSearch = specialElasticCharsEscape(decodedSearch.trim());
    let finalSearch;
    if (cleanSearch.startsWith('http\\://')) {
      finalSearch = `"*${cleanSearch.replace('http\\://', '')}*"`;
    } else if (cleanSearch.startsWith('https\\://')) {
      finalSearch = `"*${cleanSearch.replace('https\\://', '')}*"`;
    } else if (cleanSearch.startsWith('"')) {
      finalSearch = `${cleanSearch}`;
    } else {
      const splitSearch = cleanSearch.split(/[\s/]+/);
      finalSearch = R.pipe(
        R.map((n) => `*${n}*`),
        R.join(' ')
      )(splitSearch);
    }
    const bool = {
      bool: {
        should: [
          {
            query_string: {
              query: finalSearch,
              analyze_wildcard: true,
              fields: ['name^5', '*'],
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
                        query: finalSearch,
                        analyze_wildcard: true,
                        fields: ['connections.name^5', 'connections.*'],
                      },
                    },
                  ],
                },
              },
            },
          },
        ],
        minimum_should_match: 1,
      },
    };
    must = R.append(bool, must);
  }
  if (types !== null && types.length > 0) {
    const should = R.flatten(
      types.map((typeValue) => {
        return [{ match_phrase: { entity_type: typeValue } }, { match_phrase: { parent_types: typeValue } }];
      })
    );
    must = R.append({ bool: { should, minimum_should_match: 1 } }, must);
  }
  const validFilters = R.filter((f) => f?.values?.length > 0 || f?.nested?.length > 0, filters || []);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const { key, values, nested, operator = 'eq' } = validFilters[index];
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
              minimum_should_match: 1,
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
        must = R.append({ nested: nestedQuery }, must);
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
        must = R.append({ bool: { should: valuesFiltering, minimum_should_match: 1 } }, must);
      }
    }
  }
  if (orderBy !== null && orderBy.length > 0) {
    const order = {};
    const orderKeyword =
      dateAttributes.includes(orderBy) || numericOrBooleanAttributes.includes(orderBy) ? orderBy : `${orderBy}.keyword`;
    order[orderKeyword] = orderMode;
    ordering = R.append(order, ordering);
    must = R.append({ exists: { field: orderKeyword } }, must);
  }
  const query = {
    index: indexName,
    _source_excludes: `${REL_INDEX_PREFIX}*`,
    track_total_hits: true,
    body: {
      from: offset,
      size: first,
      sort: ordering,
      query: {
        bool: {
          must,
          must_not: mustnot,
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] paginate`, { query });
  return el
    .search(query)
    .then((data) => {
      const dataWithIds = R.map((n) => {
        const loadedElement = R.pipe(R.assoc('id', n._source.internal_id), R.assoc('_index', n._index))(n._source);
        if (loadedElement.base_type === BASE_TYPE_RELATION) {
          return elReconstructRelation(loadedElement);
        }
        if (loadedElement.event_data) {
          return R.assoc('event_data', JSON.stringify(loadedElement.event_data), loadedElement);
        }
        return loadedElement;
      }, data.body.hits.hits);
      if (connectionFormat) {
        const nodeHits = R.map((n) => ({ node: n }), dataWithIds);
        return buildPagination(first, offset, nodeHits, data.body.hits.total.value);
      }
      return dataWithIds;
    })
    .catch(
      /* istanbul ignore next */ (err) => {
        // Because we create the mapping at element creation
        // We log the error only if its not a mapping not found error
        const numberOfCauses = err.meta.body.error.root_cause.length;
        const invalidMappingCauses = R.pipe(
          R.map((r) => r.reason),
          R.filter((r) => R.includes('No mapping found for', r) || R.includes('no such index', r))
        )(err.meta.body.error.root_cause);
        // If uncontrolled error, log and propagate
        if (numberOfCauses > invalidMappingCauses.length) {
          logger.error(`[ELASTICSEARCH] Paginate fail`, { error: err, query });
          throw err;
        } else {
          return connectionFormat ? buildPagination(0, 0, [], 0) : [];
        }
      }
    );
};
// endregion

export const elBulk = async (args) => {
  return el
    .bulk(args)
    .then((result) => {
      if (result.body.errors) {
        const errors = result.body.items.map((i) => i.index?.error).filter((f) => f !== undefined);
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
  logger.debug(`[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}`, documentBody);
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
export const elUpdate = (indexName, documentId, documentBody, retry = 5) => {
  return el
    .update({
      id: documentId,
      index: indexName,
      retry_on_conflict: retry,
      timeout: '60m',
      refresh: true,
      body: R.dissoc('_index', documentBody),
    })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err, documentId, body: documentBody });
    });
};

export const elReplace = (indexName, documentId, documentBody) => {
  const keys = R.keys(documentBody.doc);
  const rawSource = R.map((key) => `ctx._source['${key}'] = params['${key}']`, keys);
  const source = R.join(';', rawSource);
  return elUpdate(indexName, documentId, {
    script: { source, params: documentBody.doc },
  });
};

export const elDeleteByField = async (indexName, fieldName, value) => {
  const query = {
    match: { [fieldName]: value },
  };
  await el
    .deleteByQuery({
      index: indexName,
      refresh: true,
      body: { query },
    })
    .catch((err) => {
      throw DatabaseError('Delete by field fail', { error: err, fieldName, value });
    });
  return value;
};

const getRelatedRelations = async (targetId, elements = [], options = {}) => {
  const { total, hits } = await elFindBy('connections.internal_id', targetId, ABSTRACT_BASIC_RELATIONSHIP);
  const isPartialRemove = total > hits.length;
  const connectedRelationsIds = R.map((r) => {
    const { internal_id: internalId, entity_type: entityType } = r;
    return {
      internal_id: internalId,
      type: entityType,
      fromId: r.fromId,
      fromType: r.fromType,
      toId: r.toId,
      toType: r.toType,
    };
  }, hits);
  elements.push(...connectedRelationsIds);
  await Promise.all(connectedRelationsIds.map(({ internal_id: id }) => getRelatedRelations(id, elements, options)));
  return isPartialRemove;
};
export const getRelationsToRemove = async (element, options = {}) => {
  const removed = [];
  const isPartialRemove = await getRelatedRelations(element.internal_id, removed, options);
  // Return list of deleted ids
  return { isPartialRemove, removed };
};

export const elDeleteInstanceIds = async (ids, indexesToHandle = DATA_INDICES) => {
  // If nothing to delete, return immediately to prevent elastic to delete everything
  if (ids.length === 0) {
    return Promise.resolve(0);
  }
  logger.debug(`[ELASTICSEARCH] elDeleteInstanceIds`, { ids });
  const terms = R.map((id) => ({ term: { 'internal_id.keyword': id } }), ids);
  return el
    .deleteByQuery({
      index: indexesToHandle,
      _source_excludes: '*',
      refresh: true,
      body: {
        query: {
          bool: {
            should: terms,
          },
        },
      },
    })
    .catch((err) => {
      throw DatabaseError('Error deleting instance', { error: err, ids });
    });
};

const elRemoveRelationConnection = async (relsFromTo) => {
  if (relsFromTo.length === 0) return true;
  const bodyUpdateRaw = relsFromTo.map(({ relation, isFromCleanup, isToCleanup }) => {
    const type = `${REL_INDEX_PREFIX + relation.type}.internal_id`;
    const updates = [];
    if (isFromCleanup) {
      const fromIndex = inferIndexFromConceptType(relation.fromType);
      const script = {
        source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
        params: {
          key: relation.toId,
        },
      };
      updates.push([{ update: { _index: fromIndex, _id: relation.fromId } }, { script }]);
    }
    // Update to to entity
    if (isToCleanup) {
      const toIndex = inferIndexFromConceptType(relation.toType);
      const script = {
        source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
        params: {
          key: relation.fromId,
        },
      };
      updates.push([{ update: { _index: toIndex, _id: relation.toId } }, { script }]);
    }
    return updates;
  });
  const bodyUpdate = R.flatten(bodyUpdateRaw);
  return elBulk({ refresh: true, timeout: '5m', body: bodyUpdate });
};

export const elDeleteElements = async (elements) => {
  // eslint-disable-next-line no-use-before-define,prettier/prettier
  return Promise.all(elements.map(async (element) => {
      const { isPartialRemove, removed } = await getRelationsToRemove(element);
      const resolved = R.flatten(removed);
      const idsToRemove = R.uniq(resolved.map((e) => e.internal_id));
      // 02. Compute the id that needs to be remove from rel
      const relsFromTo = resolved
        .map((r) => {
          const isFromCleanup = isImpactedType(r.fromType) && !idsToRemove.includes(r.fromId);
          const isToCleanup = isImpactedType(r.toType) && !idsToRemove.includes(r.toId);
          return { relation: r, isFromCleanup, isToCleanup };
        })
        .filter((r) => r.isFromCleanup || r.isToCleanup);
      // Update all rel connections that will remain
      await elRemoveRelationConnection(relsFromTo); // Bulk
      // Delete all related elements
      await elDeleteInstanceIds(idsToRemove); // deleteByQuery
      // delete source elements if everything connected have been deleted
      if (!isPartialRemove) {
        // eslint-disable-next-line no-await-in-loop
        await elDeleteInstanceIds([element.internal_id]);
      }
    })
  );
};

export const elDeleteElement = (element) => {
  return elDeleteElements([element]);
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
  return R.dissoc('_index', thing);
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
    R.dissoc('i_relations_to'),
    R.dissoc('i_relations_from'),
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
  return R.pipe(R.dissoc('i_relations_to'), R.dissoc('i_relations_from'))(thing);
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
export const elIndexElements = async (elements, retry = 5) => {
  // 00. Relations must be transformed before indexing.
  const transformedElements = await prepareIndexing(elements);
  // 01. Bulk the indexing of row elements
  const body = transformedElements.flatMap((doc) => [
    { index: { _index: inferIndexFromConceptType(doc.entity_type), _id: doc.internal_id } },
    R.pipe(R.dissoc('_index'))(doc),
  ]);
  if (body.length > 0) {
    await elBulk({ refresh: true, body });
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
      if (!R.includes(fromRole, UNIMPACTED_ENTITIES_ROLE)) {
        impacts.push({ from: e.fromId, relationshipType, to: e.to });
      }
      if (!R.includes(toRole, UNIMPACTED_ENTITIES_ROLE)) {
        impacts.push({ from: e.toId, relationshipType, to: e.from });
      }
      return impacts;
    }),
    R.flatten,
    R.groupBy((i) => i.from)
  )(elements);
  const elementsToUpdate = await Promise.all(
    // For each from, generate the
    R.map(async (entityId) => {
      const entity = cache[entityId];
      const targets = impactedEntities[entityId];
      // Build document fields to update ( per relation type )
      // rel_membership: [{ internal_id: ID, types: [] }]
      const targetsByRelation = R.groupBy((i) => i.relationshipType, targets);
      const targetsElements = await Promise.all(
        R.map(async (relType) => {
          const data = targetsByRelation[relType];
          const resolvedData = await Promise.all(
            R.map(async (d) => {
              return d.to.internal_id;
            }, data)
          );
          return { relation: relType, elements: resolvedData };
        }, Object.keys(targetsByRelation))
      );
      // Create params and scripted update
      const params = {};
      const sources = R.map((t) => {
        const field = `${REL_INDEX_PREFIX + t.relation}.internal_id`;
        const createIfNotExist = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
        const addAllElements = `ctx._source['${field}'].addAll(params['${field}'])`;
        return `${createIfNotExist} ${addAllElements}`;
      }, targetsElements);
      const source = sources.length > 1 ? R.join(';', sources) : `${R.head(sources)};`;
      for (let index = 0; index < targetsElements.length; index += 1) {
        const targetElement = targetsElements[index];
        params[`${REL_INDEX_PREFIX + targetElement.relation}.internal_id`] = targetElement.elements;
      }
      // eslint-disable-next-line no-underscore-dangle
      const index = inferIndexFromConceptType(entity.entity_type);
      return { _index: index, id: entityId, data: { script: { source, params } } };
    }, Object.keys(impactedEntities))
  );
  const bodyUpdate = elementsToUpdate.flatMap((doc) => [
    // eslint-disable-next-line no-underscore-dangle
    { update: { _index: doc._index, _id: doc.id, retry_on_conflict: retry } },
    R.dissoc('_index', doc.data),
  ]);
  if (bodyUpdate.length > 0) {
    await elBulk({ refresh: true, timeout: '5m', body: bodyUpdate });
  }
  return transformedElements.length;
};

export const elUpdateAttributeValue = (key, previousValue, value) => {
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
  const query = { match_phrase: { [key]: previousValue } };
  return el
    .updateByQuery({
      index: DATA_INDICES,
      refresh: false,
      body: {
        script: { source, params: { key, value, previousValue } },
        query,
      },
    })
    .catch((err) => {
      throw DatabaseError('Updating attribute value fail', { error: err, key, value });
    });
};

export const elUpdateRelationConnections = (elements) => {
  if (elements.length === 0) return Promise.resolve();
  const source =
    'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); ' +
    'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
  const bodyUpdate = elements.flatMap((doc) => [
    // eslint-disable-next-line no-underscore-dangle
    { update: { _index: inferIndexFromConceptType(doc.entity_type), _id: doc.id } },
    { script: { source, params: { id: doc.toReplace, changes: doc.data } } },
  ]);
  return elBulk({ refresh: true, timeout: '5m', body: bodyUpdate });
};

export const elUpdateEntityConnections = (elements) => {
  const source = `if (ctx._source[params.key] == null) { 
      ctx._source[params.key] = [params.to];
    } else if (params.from == null) {
      ctx._source[params.key].add(params.to);
    } else {
      def values = [params.to];
      for (current in ctx._source[params.key]) { 
        if (current != params.from) { values.add(current); }
      }
      ctx._source[params.key] = values;
    }
  `;
  const docsToImpact = elements.filter((e) => !R.includes(e.entity_type, UNIMPACTED_ENTITIES));
  if (docsToImpact.length === 0) return Promise.resolve();
  const bodyUpdate = docsToImpact.flatMap((doc) => [
    // eslint-disable-next-line no-underscore-dangle
    { update: { _index: inferIndexFromConceptType(doc.entity_type), _id: doc.id } },
    {
      script: {
        source,
        params: { key: `rel_${doc.relationType}.internal_id`, from: doc.toReplace, to: doc.data.internal_id },
      },
    },
  ]);
  return elBulk({ refresh: true, timeout: '5m', body: bodyUpdate });
};

export const elUpdateConnectionsOfElement = (documentId, documentBody) => {
  const source =
    'def conn = ctx._source.connections.find(c -> c.internal_id == params.id); ' +
    'for (change in params.changes.entrySet()) { conn[change.getKey()] = change.getValue() }';
  return el
    .updateByQuery({
      index: RELATIONSHIPS_INDICES,
      refresh: true,
      body: {
        script: { source, params: { id: documentId, changes: documentBody } },
        query: {
          nested: {
            path: 'connections',
            query: {
              bool: {
                must: [{ match_phrase: { [`connections.internal_id`]: documentId } }],
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
  const index = inferIndexFromConceptType(instance.entity_type);
  await elReplace(index, instance.internal_id, { doc: esData });
  // If entity with a name, must update connections
  if (esData.name && isStixObject(instance.entity_type)) {
    await elUpdateConnectionsOfElement(instance.internal_id, { name: esData.name });
  }
};
