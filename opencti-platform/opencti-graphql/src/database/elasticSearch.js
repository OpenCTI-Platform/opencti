/* eslint-disable no-underscore-dangle */
import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import {
  append,
  assoc,
  concat,
  dissoc,
  filter,
  find as Rfind,
  flatten,
  groupBy,
  head,
  includes,
  invertObj,
  join,
  last,
  map,
  mergeAll,
  pipe,
  toPairs,
  uniq,
} from 'ramda';
import {
  buildPagination,
  INDEX_STIX_ENTITIES,
  INDEX_STIX_OBSERVABLE,
  INDEX_STIX_RELATIONS,
  inferIndexFromConceptTypes,
} from './utils';
import conf, { logger } from '../config/conf';
import { resolveNaturalRoles } from './graknRoles';

const dateFields = [
  'created',
  'modified',
  'created_at',
  'created_at_day',
  'created_at_month',
  'updated_at',
  'first_seen',
  'first_seen_day',
  'first_seen_month',
  'last_seen',
  'last_seen_day',
  'last_seen_month',
  'published',
  'published_day',
  'published_month',
  'valid_from',
  'valid_from_day',
  'valid_from_month',
  'valid_until',
  'valid_until_day',
  'valid_until_month',
  'observable_date',
  'default_assignation', // TODO @JRI Ask @Sam for this.
];
const numberFields = ['object_status', 'phase_order', 'level', 'weight', 'ordering', 'base_score'];
const virtualTypes = ['Identity', 'Email', 'File', 'Stix-Domain-Entity', 'Stix-Domain', 'Stix-Observable'];

export const REL_INDEX_PREFIX = 'rel_';
export const INDEX_WORK_JOBS = 'work_jobs_index';
const UNIMPACTED_ENTITIES_ROLE = ['tagging', 'marking', 'kill_chain_phase', 'creator'];
export const PLATFORM_INDICES = [INDEX_STIX_ENTITIES, INDEX_STIX_RELATIONS, INDEX_STIX_OBSERVABLE, INDEX_WORK_JOBS];

export const forceNoCache = () => conf.get('elasticsearch:noQueryCache') || false;
export const el = new Client({ node: conf.get('elasticsearch:url') });

export const elIsAlive = async () => {
  return el
    .info()
    .then((info) => {
      /* istanbul ignore if */
      if (info.meta.connection.status !== 'alive') {
        logger.error(`[ELASTICSEARCH] Seems down`);
        throw new Error('elastic seems down');
      }
      return true;
    })
    .catch(
      /* istanbul ignore next */ () => {
        logger.error(`[ELASTICSEARCH] Seems down`);
        throw new Error('elastic seems down');
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
                  created_at_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true,
                  },
                  first_seen_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true,
                  },
                  last_seen_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true,
                  },
                  expiration_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true,
                  },
                  published_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true,
                  },
                  object_status: {
                    type: 'integer',
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
export const elDeleteIndexes = async (indexesToDelete = PLATFORM_INDICES) => {
  return Promise.all(
    indexesToDelete.map((index) => {
      return el.indices.delete({ index }).catch((err) => {
        /* istanbul ignore next */
        logger.error(`[ELASTICSEARCH] Delete indices fail > ${err}`);
      });
    })
  );
};

export const elCount = (indexName, options = {}) => {
  const { endDate = null, types = null } = options;
  let must = [];
  if (endDate !== null) {
    must = append(
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
        match_phrase: {
          entity_type: typeValue,
        },
      };
    });
    must = append(
      {
        bool: {
          should,
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
  logger.debug(`[ELASTICSEARCH] countEntities > ${JSON.stringify(query)}`);
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
  const histoFilters = map((f) => {
    const key = f.isRelation ? 'rel_*.internal_id_key.keyword' : `${f.type}.keyword`;
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
          must: concat(dateFilter, histoFilters),
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
  logger.debug(`[ELASTICSEARCH] aggregationCount > ${JSON.stringify(query)}`);
  return el.search(query).then((data) => {
    const { buckets } = data.body.aggregations.genres;
    return map((b) => ({ label: b.key, value: b.doc_count }), buckets);
  });
};
export const elAggregationRelationsCount = (type, start, end, toTypes, fromId) => {
  const haveRange = start && end;
  const filters = [];
  if (haveRange) {
    filters.push({
      range: {
        first_seen: {
          gte: start,
          lte: end,
        },
      },
    });
  }
  filters.push({
    match_phrase: { 'connections.internal_id_key': fromId },
  });
  for (let index = 0; index < toTypes.length; index += 1) {
    filters.push({
      match_phrase: { 'connections.types': toTypes[index] },
    });
  }
  const query = {
    index: INDEX_STIX_RELATIONS,
    body: {
      size: 10000,
      query: {
        bool: {
          must: filters,
          should: [{ match_phrase: { relationship_type: type } }, { match_phrase: { parent_types: type } }],
          minimum_should_match: 1,
        },
      },
      aggs: {
        genres: {
          terms: {
            field: `connections.types.keyword`,
            size: 100,
          },
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] aggregationRelationsCount > ${JSON.stringify(query)}`);
  return el.search(query).then((data) => {
    // First need to find all types relations to the fromId
    const types = pipe(
      map((h) => h._source.connections),
      flatten(),
      filter((c) => c.internal_id_key !== fromId),
      filter((c) => toTypes.length === 0 || includes(head(toTypes), c.types)),
      map((e) => e.types),
      flatten(),
      uniq(),
      filter((f) => !includes(f, virtualTypes)),
      map((u) => u.toLowerCase())
    )(data.body.hits.hits);
    const { buckets } = data.body.aggregations.genres;
    const filteredBuckets = filter((b) => includes(b.key, types), buckets);
    return map((b) => ({ label: b.key, value: b.doc_count }), filteredBuckets);
  });
};
export const elHistogramCount = async (type, field, interval, start, end, filters) => {
  // const tzStart = moment.parseZone(start).format('Z');
  const histoFilters = map((f) => {
    // eslint-disable-next-line no-nested-ternary
    const key = f.isRelation
      ? f.type
        ? `rel_${f.type}.internal_id_key`
        : 'rel_*.internal_id_key'
      : `${f.type}.keyword`;
    return {
      multi_match: {
        fields: [key],
        type: 'phrase',
        query: f.value,
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
      throw new Error('Unsupported interval, please choose between year, month or day');
  }
  const query = {
    index: PLATFORM_INDICES,
    _source_excludes: '*', // Dont need to get anything
    body: {
      query: {
        bool: {
          must: concat(
            [
              {
                bool: {
                  should: [{ match_phrase: { entity_type: type } }, { match_phrase: { parent_types: type } }],
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
            histoFilters
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
  logger.debug(`[ELASTICSEARCH] histogramCount > ${JSON.stringify(query)}`);
  return el.search(query).then((data) => {
    const { buckets } = data.body.aggregations.count_over_time;
    const dataToPairs = toPairs(buckets);
    return map((b) => ({ date: head(b), value: last(b).doc_count }), dataToPairs);
  });
};

// region relation reconstruction
// relationsMap = [V1324] = { alias, internal_id_key, role }
const elBuildRelation = (type, connection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.grakn_id,
    [`${type}InternalId`]: connection.internal_id_key,
    [`${type}Role`]: connection.role,
    [`${type}Types`]: connection.types,
  };
};
const elMergeRelation = (concept, fromConnection, toConnection) => {
  if (!fromConnection || !toConnection) {
    throw new Error(`[ELASTIC] Something fail in reconstruction of the relation ${concept.grakn_id}`);
  }
  const from = elBuildRelation('from', fromConnection);
  const to = elBuildRelation('to', toConnection);
  return mergeAll([concept, from, to]);
};
export const elReconstructRelation = (concept, relationsMap = null, forceNatural = false) => {
  const naturalDirections = resolveNaturalRoles(concept.relationship_type);
  const bindingByAlias = invertObj(naturalDirections);
  const { connections } = concept;
  // Need to rebuild the from and the to.
  let toConnection;
  let fromConnection;
  if (relationsMap === null || relationsMap.size === 0) {
    // We dont know anything, force from and to from roles map
    fromConnection = Rfind((connection) => connection.role === bindingByAlias.from, connections);
    toConnection = Rfind((connection) => connection.role === bindingByAlias.to, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  // If map is specified, decide the resolution.
  const relationValues = Array.from(relationsMap.values());
  const queryFrom = Rfind((v) => v.alias === 'from', relationValues);
  const queryTo = Rfind((v) => v.alias === 'to', relationValues);
  // If map contains a key filtering
  if (queryFrom && queryFrom.internalIdKey && forceNatural !== true) {
    fromConnection = Rfind((connection) => connection.internal_id_key === queryFrom.internalIdKey, connections);
    toConnection = Rfind((connection) => connection.internal_id_key !== queryFrom.internalIdKey, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  if (queryTo && queryTo.internalIdKey && forceNatural !== true) {
    fromConnection = Rfind((connection) => connection.internal_id_key !== queryTo.internalIdKey, connections);
    toConnection = Rfind((connection) => connection.internal_id_key === queryTo.internalIdKey, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  // If map contains a role filtering.
  // Only need to check on one side, the 2 roles are provisioned in this case.
  if (queryFrom && queryFrom.role && forceNatural !== true) {
    fromConnection = Rfind((connection) => connection.role === queryFrom.role, connections);
    toConnection = Rfind((connection) => connection.role === queryTo.role, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  // If nothing in map to reconstruct
  fromConnection = Rfind((connection) => connection.role === bindingByAlias.from, connections);
  toConnection = Rfind((connection) => connection.role === bindingByAlias.to, connections);
  return elMergeRelation(concept, fromConnection, toConnection);
};
// endregion

// region elastic common loader.
export const specialElasticCharsEscape = (query) => {
  return query.replace(/([+|\-*()~={}[\]:?\\])/g, '\\$1');
};
export const elPaginate = async (indexName, options = {}) => {
  const {
    first = 200,
    after,
    types = null,
    filters = [],
    search = null,
    orderBy = null,
    orderMode = 'asc',
    relationsMap = null,
    forceNatural = false,
    connectionFormat = true, // TODO @Julien Refactor that
  } = options;
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
      finalSearch = pipe(
        map((n) => `*${n}*`),
        join(' ')
      )(splitSearch);
    }
    must = append(
      {
        query_string: {
          query: finalSearch,
          analyze_wildcard: true,
          fields: ['name^5', '*'],
        },
      },
      must
    );
  } else {
    must = append({ match_all: {} }, must);
  }
  if (types !== null && types.length > 0) {
    const should = flatten(
      types.map((typeValue) => {
        return [{ match_phrase: { entity_type: typeValue } }, { match_phrase: { parent_types: typeValue } }];
      })
    );
    must = append({ bool: { should, minimum_should_match: 1 } }, must);
  }
  const validFilters = filter((f) => f && f.values.length > 0, filters || []);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const { key, values, operator = 'eq' } = validFilters[index];
      for (let i = 0; i < values.length; i += 1) {
        if (values[i] === null) {
          mustnot = append({ exists: { field: key } }, mustnot);
        } else if (values[i] === 'EXISTS') {
          valuesFiltering.push({ exists: { field: key } });
        } else if (operator === 'eq' || operator === 'match') {
          valuesFiltering.push({
            match_phrase: {
              [`${
                dateFields.includes(key) || numberFields.includes(key) || operator === 'match' ? key : `${key}.keyword`
              }`]: values[i].toString(),
            },
          });
        } else {
          valuesFiltering.push({ range: { [key]: { [operator]: values[i] } } });
        }
      }
      must = append({ bool: { should: valuesFiltering, minimum_should_match: 1 } }, must);
    }
  }
  if (orderBy !== null && orderBy.length > 0) {
    const order = {};
    const orderKeyword =
      dateFields.includes(orderBy) || numberFields.includes(orderBy) ? orderBy : `${orderBy}.keyword`;
    order[orderKeyword] = orderMode;
    ordering = append(order, ordering);
    must = append({ exists: { field: orderKeyword } }, must);
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
  logger.debug(`[ELASTICSEARCH] paginate > ${JSON.stringify(query)}`);
  return el
    .search(query)
    .then((data) => {
      const dataWithIds = map((n) => {
        const loadedElement = pipe(assoc('id', n._source.internal_id_key), assoc('_index', n._index))(n._source);
        if (loadedElement.relationship_type) {
          return elReconstructRelation(loadedElement, relationsMap, forceNatural);
        }
        return loadedElement;
      }, data.body.hits.hits);
      if (connectionFormat) {
        const nodeHits = map((n) => ({ node: n }), dataWithIds);
        return buildPagination(first, offset, nodeHits, data.body.hits.total.value);
      }
      return dataWithIds;
    })
    .catch(
      /* istanbul ignore next */ (err) => {
        // Because we create the mapping at element creation
        // We log the error only if its not a mapping not found error
        const numberOfCauses = err.meta.body.error.root_cause.length;
        const invalidMappingCauses = pipe(
          map((r) => r.reason),
          filter((r) => includes('No mapping found for', r))
        )(err.meta.body.error.root_cause);
        // If uncontrolled error, log and propagate
        if (numberOfCauses > invalidMappingCauses.length) {
          logger.error(`[ELASTICSEARCH] Paginate fail > ${err}`);
          throw err;
        } else {
          return connectionFormat ? buildPagination(0, 0, [], 0) : [];
        }
      }
    );
};
export const elLoadByTerms = async (terms, relationsMap, indices = PLATFORM_INDICES) => {
  const query = {
    index: indices,
    _source_excludes: `${REL_INDEX_PREFIX}*`,
    body: {
      query: {
        bool: {
          must: map((x) => ({ term: x }), terms),
        },
      },
    },
  };
  logger.debug(`[ELASTICSEARCH] loadByTerms > ${JSON.stringify(query)}`);
  const data = await el.search(query);
  const total = data.body.hits.total.value;
  /* istanbul ignore if */
  if (total > 1) {
    throw new Error(`[ELASTIC] Expect only one response expected for ${terms}`);
  }
  const response = total === 1 ? head(data.body.hits.hits) : null;
  if (!response) return response;
  const loadedElement = assoc('_index', response._index, response._source);
  if (loadedElement.relationship_type) {
    return elReconstructRelation(loadedElement, relationsMap);
  }
  return loadedElement;
};
// endregion

export const elLoadById = (id, type = null, relationsMap = null, indices = PLATFORM_INDICES) => {
  const terms = [{ 'internal_id_key.keyword': id }];
  if (type) {
    terms.push({ 'parent_types.keyword': type });
  }
  return elLoadByTerms(terms, relationsMap, indices);
};
export const elLoadByStixId = (id, type = null, relationsMap = null, indices = PLATFORM_INDICES) => {
  const terms = [{ 'stix_id_key.keyword': id }];
  if (type) {
    terms.push({ 'parent_types.keyword': type });
  }
  return elLoadByTerms(terms, relationsMap, indices);
};
export const elLoadByGraknId = (id, type = null, relationsMap = null, indices = PLATFORM_INDICES) => {
  const terms = [{ 'grakn_id.keyword': id }];
  if (type) {
    terms.push({ 'parent_types.keyword': type });
  }
  return elLoadByTerms(terms, relationsMap, indices);
};

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
  const internalId = documentBody.internal_id_key;
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  logger.debug(`[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}`);
  await el.index({
    index: indexName,
    id: documentBody.grakn_id,
    refresh,
    timeout: '60m',
    body: dissoc('_index', documentBody),
  });
  return documentBody;
};
/* istanbul ignore next */
export const elUpdate = (indexName, documentId, documentBody, retry = 2) => {
  return el.update({
    id: documentId,
    index: indexName,
    retry_on_conflict: retry,
    timeout: '60m',
    refresh: true,
    body: dissoc('_index', documentBody),
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
export const elDeleteInstanceIds = async (ids, indexesToHandle = PLATFORM_INDICES) => {
  logger.debug(`[ELASTICSEARCH] elDeleteInstanceIds > ${ids}`);
  const terms = map((id) => ({ term: { 'internal_id_key.keyword': id } }), ids);
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
  const relation = await elLoadById(relationId);
  const from = await elLoadByGraknId(relation.fromId);
  const to = await elLoadByGraknId(relation.toId);
  const type = `${REL_INDEX_PREFIX + relation.relationship_type}.internal_id_key`;
  // Update the from entity
  await elUpdate(from._index, from.grakn_id, {
    script: {
      source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: to.internal_id_key,
      },
    },
  });
  // Update to to entity
  await elUpdate(to._index, to.grakn_id, {
    script: {
      source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: from.internal_id_key,
      },
    },
  });
};

const prepareIndexing = async (elements) => {
  return Promise.all(
    map(async (element) => {
      // Ensure empty list are not indexed
      const thing = {};
      Object.keys(element).forEach((key) => {
        const value = element[key];
        if (Array.isArray(value)) {
          const filteredArray = value.filter((i) => i);
          thing[key] = filteredArray.length > 0 ? filteredArray : [];
        } else {
          thing[key] = value;
        }
      });
      // For relation, index a list of connections.
      if (thing.relationship_type) {
        if (thing.fromRole === undefined || thing.toRole === undefined) {
          throw new Error(
            `[ELASTIC] Cant index relation ${thing.grakn_id} connections without from (${thing.fromId}) or to (${thing.toId})`
          );
        }
        const connections = [];
        const [from, to] = await Promise.all([
          elLoadByGraknId(thing.fromId), //
          elLoadByGraknId(thing.toId),
        ]);
        connections.push({
          grakn_id: thing.fromId,
          internal_id_key: from.internal_id_key,
          types: thing.fromTypes,
          role: thing.fromRole,
        });
        connections.push({
          grakn_id: thing.toId,
          internal_id_key: to.internal_id_key,
          types: thing.toTypes,
          role: thing.toRole,
        });
        return pipe(
          assoc('connections', connections),
          // Dissoc from
          dissoc('from'),
          dissoc('fromId'),
          dissoc('fromRole'),
          // Dissoc to
          dissoc('to'),
          dissoc('toId'),
          dissoc('toRole')
        )(thing);
      }
      return thing;
    }, elements)
  );
};
export const elIndexElements = async (elements, retry = 2) => {
  // 00. Relations must be transformed before indexing.
  const transformedElements = await prepareIndexing(elements);
  // 01. Bulk the indexing of row elements
  const body = transformedElements.flatMap((doc) => [
    { index: { _index: inferIndexFromConceptTypes(doc.parent_types), _id: doc.grakn_id } },
    dissoc('_index', doc),
  ]);
  if (body.length > 0) {
    await elBulk({ refresh: true, body });
  }
  // 02. If relation, generate impacts for from and to sides
  const impactedEntities = pipe(
    filter((e) => e.relationship_type !== undefined),
    map((e) => {
      const { fromRole, toRole } = e;
      const relationshipType = e.relationship_type;
      const impacts = [];
      // We impact target entities of the relation only if not global entities like
      // MarkingDefinition (marking) / KillChainPhase (kill_chain_phase) / Tag (tagging)
      if (!includes(fromRole, UNIMPACTED_ENTITIES_ROLE)) impacts.push({ from: e.fromId, relationshipType, to: e.toId });
      if (!includes(toRole, UNIMPACTED_ENTITIES_ROLE)) impacts.push({ from: e.toId, relationshipType, to: e.fromId });
      return impacts;
    }),
    flatten,
    groupBy((i) => i.from)
  )(elements);
  const elementsToUpdate = await Promise.all(
    // For each from, generate the
    map(async (entityGraknId) => {
      const entity = await elLoadByGraknId(entityGraknId);
      const targets = impactedEntities[entityGraknId];
      // Build document fields to update ( per relation type )
      // rel_membership: [{ internal_id_key: ID, types: [] }]
      const targetsByRelation = groupBy((i) => i.relationshipType, targets);
      const targetsElements = await Promise.all(
        map(async (relType) => {
          const data = targetsByRelation[relType];
          const resolvedData = await Promise.all(
            map(async (d) => {
              const resolvedTarget = await elLoadByGraknId(d.to);
              return resolvedTarget.internal_id_key;
            }, data)
          );
          return { relation: relType, elements: resolvedData };
        }, Object.keys(targetsByRelation))
      );
      // Create params and scripted update
      const params = {};
      const sources = map((t) => {
        const field = `${REL_INDEX_PREFIX + t.relation}.internal_id_key`;
        const createIfNotExist = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
        const addAllElements = `ctx._source['${field}'].addAll(params['${field}'])`;
        return `${createIfNotExist} ${addAllElements}`;
      }, targetsElements);
      const source = sources.length > 1 ? join(';', sources) : `${head(sources)};`;
      for (let index = 0; index < targetsElements.length; index += 1) {
        const targetElement = targetsElements[index];
        params[`${REL_INDEX_PREFIX + targetElement.relation}.internal_id_key`] = targetElement.elements;
      }
      // eslint-disable-next-line no-underscore-dangle
      return { _index: entity._index, id: entityGraknId, data: { script: { source, params } } };
    }, Object.keys(impactedEntities))
  );
  const bodyUpdate = elementsToUpdate.flatMap((doc) => [
    // eslint-disable-next-line no-underscore-dangle
    { update: { _index: doc._index, _id: doc.id, retry_on_conflict: retry } },
    dissoc('_index', doc.data),
  ]);
  if (bodyUpdate.length > 0) {
    await elBulk({ refresh: true, timeout: '60m', body: bodyUpdate });
  }
  return transformedElements.length;
};
