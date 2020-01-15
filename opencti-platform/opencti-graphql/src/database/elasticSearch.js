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
  head,
  includes,
  invertObj,
  join,
  last,
  map,
  mergeAll,
  pipe,
  toPairs,
  uniq
} from 'ramda';
import { buildPagination } from './utils';
import conf, { logger } from '../config/conf';
import { rolesMap } from './graknRoles';

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
  'observable_date'
];
const numberFields = ['object_status', 'phase_order', 'level', 'weight'];
const virtualTypes = ['Identity', 'Email', 'File', 'Stix-Domain-Entity', 'Stix-Domain', 'Stix-Observable'];

export const REL_INDEX_PREFIX = 'rel_';
export const INDEX_STIX_OBSERVABLE = 'stix_observables';
export const INDEX_STIX_ENTITIES = 'stix_domain_entities';
export const INDEX_STIX_RELATIONS = 'stix_relations';
export const INDEX_WORK_JOBS = 'work_jobs_index';
export const PLATFORM_INDICES = [INDEX_STIX_ENTITIES, INDEX_STIX_RELATIONS, INDEX_STIX_OBSERVABLE, INDEX_WORK_JOBS];

export const forceNoCache = () => conf.get('elasticsearch:noQueryCache') || false;
export const el = new Client({ node: conf.get('elasticsearch:url') });

export const elIsAlive = async () => {
  try {
    await el.info().then(info => {
      if (info.meta.connection.status !== 'alive') {
        logger.error(`[ELASTICSEARCH] Seems down`);
        throw new Error('elastic seems down');
      }
      return true;
    });
  } catch (e) {
    logger.error(`[ELASTICSEARCH] Seems down`);
    throw new Error('elastic seems down');
  }
};
export const elVersion = () => {
  return el
    .info()
    .then(info => info.body.version.number)
    .catch(() => 'Disconnected');
};
export const elCreateIndexes = async () => {
  return Promise.all(
    PLATFORM_INDICES.map(index => {
      return el.indices.exists({ index }).then(result => {
        if (result.body === false) {
          return el.indices.create({
            index,
            body: {
              settings: {
                index: {
                  max_result_window: 100000
                },
                analysis: {
                  normalizer: {
                    string_normalizer: {
                      type: 'custom',
                      filter: ['lowercase', 'asciifolding']
                    }
                  }
                }
              },
              mappings: {
                dynamic_templates: [
                  {
                    integers: {
                      match_mapping_type: 'long',
                      mapping: {
                        type: 'integer'
                      }
                    }
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
                            ignore_above: 512
                          }
                        }
                      }
                    }
                  }
                ],
                properties: {
                  created_at_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true
                  },
                  first_seen_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true
                  },
                  last_seen_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true
                  },
                  expiration_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true
                  },
                  published_month: {
                    type: 'date',
                    format: 'strict_year_month',
                    ignore_malformed: true
                  }
                }
              }
            }
          });
        }
        return result;
      });
    })
  );
};
export const elDeleteIndexes = async (indexesToDelete = PLATFORM_INDICES) => {
  return Promise.all(
    indexesToDelete.map(index => {
      return el.indices.delete({ index }).catch(err => {
        logger.error(`[ELASTICSEARCH] Delete indices fail > ${err}`);
      });
    })
  );
};

export const elDeleteByField = async (indexName, fieldName, value) => {
  const query = {
    match: { [fieldName]: value }
  };
  await el.deleteByQuery({
    index: indexName,
    body: { query }
  });
  return value;
};
export const elDeleteInstanceIds = async ids => {
  logger.debug(`[ELASTICSEARCH] elDeleteInstanceIds > ${ids}`);
  const terms = map(id => ({ term: { 'internal_id_key.keyword': id } }), ids);
  return el
    .deleteByQuery({
      index: PLATFORM_INDICES,
      refresh: true,
      body: {
        query: {
          bool: {
            should: terms
          }
        }
      }
    })
    .catch(err => {
      logger.error(`[ELASTICSEARCH] elDeleteInstanceIds > ${err}`);
    });
};

export const elCount = (indexName, options = {}) => {
  const { endDate = null, type = null, types = null } = options;
  let must = [];
  if (endDate !== null) {
    must = append(
      {
        range: {
          created_at: {
            format: 'strict_date_optional_time',
            lt: endDate
          }
        }
      },
      must
    );
  }
  if (type !== null && type.length > 0) {
    must = append(
      {
        match_phrase: {
          entity_type: {
            query: type
          }
        }
      },
      must
    );
  }
  if (types !== null && types.length > 0) {
    const should = types.map(typeValue => {
      return {
        match_phrase: {
          entity_type: typeValue
        }
      };
    });
    must = append(
      {
        bool: {
          should,
          minimum_should_match: 1
        }
      },
      must
    );
  }
  const query = {
    index: indexName,
    body: {
      query: {
        bool: {
          must
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] countEntities > ${JSON.stringify(query)}`);
  return el.count(query).then(data => {
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
          lte: end
        }
      }
    });
  }
  const histoFilters = map(f => {
    const key = f.isRelation ? 'rel_*.internal_id_key.keyword' : `${f.type}.keyword`;
    return {
      multi_match: {
        fields: [key],
        type: 'phrase',
        query: f.value
      }
    };
  }, filters);
  const query = {
    index: PLATFORM_INDICES,
    body: {
      query: {
        bool: {
          must: concat(dateFilter, histoFilters),
          should: [
            { match_phrase: { 'entity_type.keyword': type } },
            { match_phrase: { 'parent_types.keyword': type } }
          ],
          minimum_should_match: 1
        }
      },
      aggs: {
        genres: {
          terms: {
            field: `${aggregationField}.keyword`
          }
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] aggregationCount > ${JSON.stringify(query)}`);
  return el
    .search(query)
    .then(data => {
      const { buckets } = data.body.aggregations.genres;
      return map(b => ({ label: b.key, value: b.doc_count }), buckets);
    })
    .catch(err => {
      throw err;
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
          lte: end
        }
      }
    });
  }
  filters.push({
    match_phrase: { 'connections.internal_id_key': fromId }
  });
  for (let index = 0; index < toTypes.length; index += 1) {
    filters.push({
      match_phrase: { 'connections.types': toTypes[index] }
    });
  }
  const query = {
    index: INDEX_STIX_RELATIONS,
    body: {
      size: 500,
      query: {
        bool: {
          must: filters,
          should: [{ match_phrase: { relationship_type: type } }, { match_phrase: { parent_types: type } }],
          minimum_should_match: 1
        }
      },
      aggs: {
        genres: {
          terms: {
            field: `connections.types.keyword`,
            size: 100
          }
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] aggregationRelationsCount > ${JSON.stringify(query)}`);
  return el.search(query).then(data => {
    // First need to find all types relations to the fromId
    const types = pipe(
      map(h => h._source.connections),
      flatten(),
      filter(c => c.internal_id_key !== fromId && includes(head(toTypes), c.types)),
      map(e => e.types),
      flatten(),
      uniq(),
      filter(f => !includes(f, virtualTypes)),
      map(u => u.toLowerCase())
    )(data.body.hits.hits);
    const { buckets } = data.body.aggregations.genres;
    const filteredBuckets = filter(b => includes(b.key, types), buckets);
    return map(b => ({ label: b.key, value: b.doc_count }), filteredBuckets);
  });
};
export const elHistogramCount = (type, field, interval, start, end, filters) => {
  const histoFilters = map(f => {
    const key = f.isRelation ? 'rel_*.internal_id_key' : `${f.type}.keyword`;
    return {
      multi_match: {
        fields: [key],
        type: 'phrase',
        query: f.value
      }
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
    default:
      dateFormat = 'yyyy-MM-dd';
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
                range: {
                  created_at: {
                    gte: start,
                    lte: end
                  }
                }
              }
            ],
            histoFilters
          ),
          should: [{ match_phrase: { entity_type: type } }, { match_phrase: { parent_types: type } }],
          minimum_should_match: 1
        }
      },
      aggs: {
        count_over_time: {
          date_histogram: {
            field: `${field}_${interval}`,
            calendar_interval: interval,
            format: dateFormat,
            keyed: true
          }
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] histogramCount > ${JSON.stringify(query)}`);
  return el.search(query).then(data => {
    const { buckets } = data.body.aggregations.count_over_time;
    const dataToPairs = toPairs(buckets);
    return map(b => ({ date: head(b), value: last(b).doc_count }), dataToPairs);
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
    [`${type}Types`]: connection.types
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
const elReconstructRelation = (concept, relationsMap = null) => {
  const naturalDirections = rolesMap[concept.relationship_type];
  const bindingByAlias = invertObj(naturalDirections);
  const { connections } = concept;
  // Need to rebuild the from and the to.
  let toConnection;
  let fromConnection;
  if (relationsMap === null || relationsMap.size === 0) {
    // We dont know anything, force from and to from roles map
    fromConnection = Rfind(connection => connection.role === bindingByAlias.from, connections);
    toConnection = Rfind(connection => connection.role === bindingByAlias.to, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  // If map is specified, decide the resolution.
  const relationValues = Array.from(relationsMap.values());
  const queryFrom = Rfind(v => v.alias === 'from', relationValues);
  const queryTo = Rfind(v => v.alias === 'to', relationValues);
  // If map contains a key filtering
  if (queryFrom && queryFrom.internalIdKey) {
    fromConnection = Rfind(connection => connection.internal_id_key === queryFrom.internalIdKey, connections);
    toConnection = Rfind(connection => connection.internal_id_key !== queryFrom.internalIdKey, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  if (queryTo && queryTo.internalIdKey) {
    toConnection = Rfind(connection => connection.internal_id_key === queryTo.internalIdKey, connections);
    fromConnection = Rfind(connection => connection.internal_id_key !== queryTo.internalIdKey, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  // If map contains a role filtering.
  // Only need to check on one side, the 2 roles are provisioned in this case.
  if (queryFrom && queryFrom.role) {
    fromConnection = Rfind(connection => connection.role === queryFrom.role, connections);
    toConnection = Rfind(connection => connection.role === queryTo.role, connections);
    return elMergeRelation(concept, fromConnection, toConnection);
  }
  // If nothing in map to reconstruct
  fromConnection = Rfind(connection => connection.role === bindingByAlias.from, connections);
  toConnection = Rfind(connection => connection.role === bindingByAlias.to, connections);
  return elMergeRelation(concept, fromConnection, toConnection);
};
// endregion

// region elastic common loader.
export const elPaginate = async (indexName, options) => {
  const {
    first = 200,
    after,
    types = null,
    filters = [],
    isUser = null, // TODO @Sam refactor this to use filter
    search = null,
    orderBy = null,
    orderMode = 'asc',
    relationsMap = null,
    connectionFormat = true // TODO @Julien Refactor that
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
    const trimedSearch = decodedSearch.trim();
    let finalSearch;
    if (trimedSearch.startsWith('http://')) {
      finalSearch = `"*${trimedSearch.replace('http://', '')}*"`;
    } else if (trimedSearch.startsWith('https://')) {
      finalSearch = `"*${trimedSearch.replace('https://', '')}*"`;
    } else if (trimedSearch.startsWith('"')) {
      finalSearch = `${trimedSearch}`;
    } else {
      const splitSearch = decodedSearch.split(/[\s/\\]+/);
      finalSearch = pipe(
        map(n => `*${n}*`),
        join(' ')
      )(splitSearch);
    }
    must = append(
      {
        query_string: {
          query: `${finalSearch}`,
          analyze_wildcard: true,
          default_field: '*'
        }
      },
      must
    );
  } else {
    must = append({ match_all: {} }, must);
  }
  if (types !== null && types.length > 0) {
    const should = flatten(
      types.map(typeValue => {
        return [{ match_phrase: { entity_type: typeValue } }, { match_phrase: { parent_types: typeValue } }];
      })
    );
    must = append({ bool: { should, minimum_should_match: 1 } }, must);
  }
  if (isUser !== null && isUser === true) {
    must = append({ exists: { field: 'email' } }, must);
  }
  const validFilters = filter(f => f && f.values.length > 0, filters || []);
  if (validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const valuesFiltering = [];
      const { key, values, operator = 'eq' } = validFilters[index];
      if (values === null) {
        mustnot = append({ exists: { field: key } }, mustnot);
      } else {
        for (let i = 0; i < values.length; i += 1) {
          if (operator === 'eq') {
            valuesFiltering.push({
              match_phrase: { [`${dateFields.includes(key) ? key : `${key}.keyword`}`]: values[i] }
            });
          } else if (operator === 'match') {
            must = append({ match_phrase: { [`${dateFields.includes(key) ? key : `${key}`}`]: values[i] } }, must);
          } else {
            valuesFiltering.push({ range: { [key]: { [operator]: values[i] } } });
          }
        }
        must = append({ bool: { should: valuesFiltering, minimum_should_match: 1 } }, must);
      }
    }
  }
  if (orderBy !== null && orderBy.length > 0) {
    const order = {};
    order[dateFields.includes(orderBy) || numberFields.includes(orderBy) ? orderBy : `${orderBy}.keyword`] = orderMode;
    ordering = append(order, ordering);
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
          must_not: mustnot
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] paginate > ${JSON.stringify(query)}`);
  return el
    .search(query)
    .then(data => {
      const dataWithIds = map(n => {
        const loadedElement = pipe(assoc('id', n._source.internal_id_key), assoc('_index', n._index))(n._source);
        if (loadedElement.relationship_type) {
          return elReconstructRelation(loadedElement, relationsMap);
        }
        return loadedElement;
      }, data.body.hits.hits);
      if (connectionFormat) {
        const nodeHits = map(n => ({ node: n }), dataWithIds);
        return buildPagination(first, offset, nodeHits, data.body.hits.total.value);
      }
      return dataWithIds;
    })
    .catch(err => {
      logger.error(`[ELASTICSEARCH] Paginate fail > ${err}`);
      return buildPagination(0, 0, [], 0);
    });
};
export const elLoadByTerms = async (terms, relationsMap, indices = PLATFORM_INDICES) => {
  const query = {
    index: indices,
    _source_excludes: `${REL_INDEX_PREFIX}*`,
    body: {
      query: {
        bool: {
          should: map(x => ({ term: x }), terms)
        }
      }
    }
  };
  const data = await el.search(query).catch(err => {
    logger.error(`[ELASTICSEARCH] Load term fail > ${err}`);
  });
  const total = data.body.hits.total.value;
  if (total > 1) {
    throw new Error(`[ELASTIC] Expect only one response expected for ${terms}`);
  }
  const response = total === 1 ? head(data.body.hits.hits) : undefined;
  if (!response) return response;
  const loadedElement = assoc('_index', response._index, response._source);
  if (loadedElement.relationship_type) {
    return elReconstructRelation(loadedElement, relationsMap);
  }
  return loadedElement;
};
// endregion

export const elLoadById = (id, relationsMap, indices = PLATFORM_INDICES) => {
  return elLoadByTerms([{ 'internal_id_key.keyword': id }], relationsMap, indices);
};
export const elLoadByStixId = (id, relationsMap, indices = PLATFORM_INDICES) => {
  return elLoadByTerms([{ 'stix_id_key.keyword': id }], relationsMap, indices);
};
export const elLoadByGraknId = (id, relationsMap, indices = PLATFORM_INDICES) => {
  return elLoadByTerms([{ 'grakn_id.keyword': id }], relationsMap, indices);
};

export const elBulk = async args => {
  return el.bulk(args);
};
export const elReindex = async indexMaps => {
  return Promise.all(
    indexMaps.map(indexMap => {
      return el
        .reindex({
          timeout: '60m',
          body: {
            source: {
              index: indexMap.source
            },
            dest: {
              index: indexMap.dest
            }
          }
        })
        .catch(err => {
          logger.error(`[ELASTICSEARCH] Re index > fail ${err}`);
        });
    })
  );
};
export const elIndex = async (indexName, documentBody, refresh = true) => {
  const internalId = documentBody.internal_id_key;
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  logger.debug(`[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}`);
  await el
    .index({
      index: indexName,
      id: documentBody.grakn_id,
      refresh,
      timeout: '60m',
      body: dissoc('_index', documentBody)
    })
    .catch(err => {
      logger.error(`[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}, ${err}`);
    });
  return documentBody;
};
export const elUpdate = (indexName, documentId, documentBody, retry = 2) => {
  return el.update({
    id: documentId,
    index: indexName,
    retry_on_conflict: retry,
    timeout: '60m',
    refresh: true,
    body: documentBody
  });
};

export const elRemoveRelationConnection = async relationId => {
  const relation = await elLoadById(relationId);
  const from = await elLoadByGraknId(relation.fromId);
  const to = await elLoadByGraknId(relation.toId);
  const type = `${REL_INDEX_PREFIX + relation.relationship_type}.internal_id_key`;
  // Update the from entity
  await elUpdate(from._index, from.grakn_id, {
    script: {
      source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: to.internal_id_key
      }
    }
  });
  // Update to to entity
  await elUpdate(to._index, to.grakn_id, {
    script: {
      source: `if (ctx._source['${type}'] != null) ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: from.internal_id_key
      }
    }
  });
};
