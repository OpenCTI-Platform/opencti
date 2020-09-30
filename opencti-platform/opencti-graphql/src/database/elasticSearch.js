/* eslint-disable no-underscore-dangle */
import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import * as R from 'ramda';
import {
  buildPagination,
  INDEX_INTERNAL_OBJECTS,
  INDEX_STIX_META_OBJECTS,
  INDEX_STIX_DOMAIN_OBJECTS,
  INDEX_STIX_CYBER_OBSERVABLES,
  INDEX_INTERNAL_RELATIONSHIPS,
  INDEX_STIX_CORE_RELATIONSHIPS,
  INDEX_STIX_SIGHTING_RELATIONSHIPS,
  INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  INDEX_STIX_META_RELATIONSHIPS,
  inferIndexFromConceptType,
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
  BASE_TYPE_RELATION,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_ALIASES,
  IDS_STIX,
  isAbstract,
  REL_INDEX_PREFIX,
} from '../schema/general';
import { isBooleanAttribute } from '../schema/fieldDataAdapter';
import { getParentTypes } from '../schema/schemaUtils';
import { isStixDomainObjectNamed } from '../schema/stixDomainObject';

export const dateFields = [
  'created',
  'modified',
  'created_at',
  'i_created_at_day',
  'i_created_at_month',
  'updated_at',
  'first_seen',
  'i_first_seen_day',
  'i_first_seen_month',
  'last_seen',
  'i_last_seen_day',
  'i_last_seen_month',
  'start_time',
  'i_start_time_day',
  'i_start_time_month',
  'stop_time',
  'i_stop_time_day',
  'i_stop_time_month',
  'published',
  'i_published_day',
  'i_published_month',
  'valid_from',
  'i_valid_from_day',
  'i_valid_from_month',
  'valid_until',
  'i_valid_until_day',
  'i_valid_until_month',
  'observable_date',
  'event_date',
  'timestamp',
];
const numericOrBooleanFields = [
  'object_status',
  'level',
  'attribute_order',
  'base_score',
  'confidence',
  'is_family',
  'number',
  'negative',
  'default_assignation',
  'x_opencti_detection',
  'x_opencti_order',
];

export const INDEX_JOBS = 'opencti_jobs';
export const INDEX_HISTORY = 'opencti_history';
const UNIMPACTED_ENTITIES_ROLE = [
  `${RELATION_CREATED_BY}_to`,
  `${RELATION_OBJECT_MARKING}_to`,
  `${RELATION_OBJECT_LABEL}_to`,
  `${RELATION_KILL_CHAIN_PHASE}_to`,
];
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
  INDEX_JOBS,
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
                  confidence: {
                    type: 'integer',
                  },
                  x_opencti_report_status: {
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
  const { endDate = null, types = null, relationshipType = null, fromId = null, toTypes = null } = options;
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
  if (relationshipType !== null) {
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
  if (toTypes !== null) {
    const filters = [];
    for (let index = 0; index < toTypes.length; index += 1) {
      filters.push({
        match_phrase: { 'connections.types': toTypes[index] },
      });
    }
    must = R.append(
      {
        bool: {
          should: filters,
          minimum_should_match: 1,
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
  return el.count(query).then((data) => {
    return data.body.count;
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
      size: 10000,
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
            size: 100,
          },
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] aggregationCount`, { query });
  return el.search(query).then((data) => {
    const { buckets } = data.body.aggregations.genres;
    return R.map((b) => ({ label: pascalize(b.key), value: b.doc_count }), buckets);
  });
};
// field can be "entity_type" or "internal_id"
export const elAggregationRelationsCount = (
  type,
  start,
  end,
  toTypes,
  fromId = null,
  field = null,
  dateAttribute = 'start_time',
  isTo = false
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
            must: [
              { match_phrase: { [`connections.internal_id`]: fromId } },
              // { query_string: { query: `*_from`, fields: [`connections.role`] } },
            ],
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
      size: 10000,
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
                  must: typesFilters.length > 0 && !isAbstract(toTypes[0]) ? roleFilter : [],
                },
              },
              aggs: {
                genres: {
                  terms: {
                    size: 100,
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
  return el.search(query).then((data) => {
    if (field === 'internal_id') {
      const { buckets } = data.body.aggregations.connections.filtered.genres;
      const filteredBuckets = R.filter((b) => b.key !== fromId, buckets);
      return R.map((b) => ({ label: b.key, value: b.doc_count }), filteredBuckets);
    }
    const types = R.pipe(
      R.map((h) => h._source.connections),
      R.flatten(),
      R.filter((c) => c.internal_id !== fromId),
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
    const { isRelation = false, isNested = false, type: filterType, value } = f;
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
  const query = {
    index: PLATFORM_INDICES,
    _source_excludes: '*', // Dont need to get anything
    body: {
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
              {
                range: {
                  [field]: {
                    gte: start,
                    lte: end,
                  },
                },
              },
            ],
            histogramFilters
          ),
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
    must = R.append(
      {
        query_string: {
          query: finalSearch,
          analyze_wildcard: true,
          fields: ['name^5', '*'],
        },
      },
      must
    );
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
            const isDateOrNumber = dateFields.includes(key) || numericOrBooleanFields.includes(key);
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
      dateFields.includes(orderBy) || numericOrBooleanFields.includes(orderBy) ? orderBy : `${orderBy}.keyword`;
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
          R.filter((r) => R.includes('No mapping found for', r))
        )(err.meta.body.error.root_cause);
        // If uncontrolled error, log and propagate
        if (numberOfCauses > invalidMappingCauses.length) {
          logger.error(`[ELASTICSEARCH] Paginate fail`, { error: err });
          throw err;
        } else {
          return connectionFormat ? buildPagination(0, 0, [], 0) : [];
        }
      }
    );
};

export const elFindByIds = async (ids, type = null, indices = DATA_INDICES) => {
  const mustTerms = [];
  const workingIds = Array.isArray(ids) ? ids : [ids];
  const idsTermsPerType = [];
  const elementTypes = [ID_INTERNAL, ID_STANDARD, IDS_STIX];
  if (isStixDomainObjectNamed(type)) {
    elementTypes.push(IDS_ALIASES);
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
    size: 1000,
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
  const data = await el.search(query);
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
// endregion

export const elBulk = async (args) => {
  return el.bulk(args);
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
  await el.deleteByQuery({
    index: indexName,
    refresh: true,
    body: { query },
  });
  return value;
};
export const elDeleteInstanceIds = async (ids, indexesToHandle = DATA_INDICES) => {
  logger.debug(`[ELASTICSEARCH] elDeleteInstanceIds`, { ids });
  const terms = R.map((id) => ({ term: { 'internal_id.keyword': id } }), ids);
  return el.deleteByQuery({
    index: indexesToHandle,
    refresh: true,
    body: {
      query: {
        bool: {
          should: terms,
        },
      },
    },
  });
};
export const elRemoveRelationConnection = async (relationId) => {
  const relation = await elLoadByIds(relationId);
  const from = await elLoadByIds(relation.fromId);
  const to = await elLoadByIds(relation.toId);
  const type = `${REL_INDEX_PREFIX + relation.entity_type}.internal_id`;
  // Update the from entity
  await elUpdate(from._index, relation.fromId, {
    script: {
      source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: relation.toId,
      },
    },
  });
  // Update to to entity
  await elUpdate(to._index, relation.toId, {
    script: {
      source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: relation.fromId,
      },
    },
  });
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
const prepareIndexing = async (elements) => {
  return Promise.all(
    R.map(async (element) => {
      // Ensure empty list are not indexed
      const thing = prepareElementForIndexing(element);
      // For relation, index a list of connections.
      if (thing.base_type === BASE_TYPE_RELATION) {
        if (thing.fromRole === undefined || thing.toRole === undefined) {
          throw DatabaseError(
            `[ELASTIC] Cant index relation ${thing.internal_id} connections without from or to`,
            thing
          );
        }
        const connections = [];
        const [from, to] = await Promise.all([elLoadByIds(thing.fromId), elLoadByIds(thing.toId)]);
        connections.push({
          internal_id: from.internal_id,
          types: [thing.fromType, ...getParentTypes(thing.fromType)],
          role: thing.fromRole,
        });
        connections.push({
          internal_id: to.internal_id,
          types: [thing.toType, ...getParentTypes(thing.toType)],
          role: thing.toRole,
        });
        return R.pipe(
          R.assoc('connections', connections),
          // Dissoc from
          R.dissoc('from'),
          R.dissoc('fromId'),
          R.dissoc('fromRole'),
          // Dissoc to
          R.dissoc('to'),
          R.dissoc('toId'),
          R.dissoc('toRole')
        )(thing);
      }
      return thing;
    }, elements)
  );
};
export const elIndexElements = async (elements, retry = 5) => {
  // 00. Relations must be transformed before indexing.
  const transformedElements = await prepareIndexing(elements);
  // 01. Bulk the indexing of row elements
  const body = transformedElements.flatMap((doc) => [
    { index: { _index: inferIndexFromConceptType(doc.entity_type), _id: doc.internal_id } },
    R.pipe(R.dissoc('_index'), R.dissoc('grakn_id'))(doc),
  ]);
  if (body.length > 0) {
    await elBulk({ refresh: true, body });
  }
  // 02. If relation, generate impacts for from and to sides
  const impactedEntities = R.pipe(
    R.filter((e) => e.base_type === BASE_TYPE_RELATION),
    R.map((e) => {
      const { fromRole, toRole } = e;
      const relationshipType = e.entity_type;
      const impacts = [];
      // We impact target entities of the relation only if not global entities like
      // MarkingDefinition (marking) / KillChainPhase (kill_chain_phase) / Label (tagging)
      if (!R.includes(fromRole, UNIMPACTED_ENTITIES_ROLE))
        impacts.push({ from: e.fromId, relationshipType, to: e.toId });
      if (!R.includes(toRole, UNIMPACTED_ENTITIES_ROLE)) impacts.push({ from: e.toId, relationshipType, to: e.fromId });
      return impacts;
    }),
    R.flatten,
    R.groupBy((i) => i.from)
  )(elements);
  const elementsToUpdate = await Promise.all(
    // For each from, generate the
    R.map(async (entityId) => {
      const entity = await elLoadByIds(entityId);
      const targets = impactedEntities[entityId];
      // Build document fields to update ( per relation type )
      // rel_membership: [{ internal_id: ID, types: [] }]
      const targetsByRelation = R.groupBy((i) => i.relationshipType, targets);
      const targetsElements = await Promise.all(
        R.map(async (relType) => {
          const data = targetsByRelation[relType];
          const resolvedData = await Promise.all(
            R.map(async (d) => {
              const resolvedTarget = await elLoadByIds(d.to);
              return resolvedTarget.internal_id;
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
      return { _index: entity._index, id: entityId, data: { script: { source, params } } };
    }, Object.keys(impactedEntities))
  );
  const bodyUpdate = elementsToUpdate.flatMap((doc) => [
    // eslint-disable-next-line no-underscore-dangle
    { update: { _index: doc._index, _id: doc.id, retry_on_conflict: retry } },
    R.dissoc('_index', doc.data),
  ]);
  if (bodyUpdate.length > 0) {
    await elBulk({ refresh: true, timeout: '60m', body: bodyUpdate });
  }
  return transformedElements.length;
};
