/* eslint-disable no-underscore-dangle */
import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import {
  append,
  assoc,
  dissoc,
  filter,
  find as Rfind,
  flatten,
  head,
  invertObj,
  join,
  map,
  mergeAll,
  pipe,
  split
} from 'ramda';
import { buildPagination } from './utils';
import conf, { logger } from '../config/conf';
import { rolesMap } from './graknRoles';

const dateFields = ['created', 'modified', 'created_at', 'updated_at', 'first_seen', 'last_seen', 'published'];
const numberFields = ['object_status', 'phase_order'];

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
      return el.indices.delete({ index }).catch(() => {
        return false;
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
      return false;
    });
};

export const elCount = (indexName, options) => {
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

// region relation reconstruction
// relationsMap = [V1324] = { alias, internal_id_key, role }
const elBuildRelation = (type, connection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.grakn_id,
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
  if (relationsMap === null) {
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
    const trimedSearch = search.trim();
    let finalSearch;
    if (trimedSearch.startsWith('http://')) {
      finalSearch = `"*${trimedSearch.replace('http://', '')}*"`;
    } else if (trimedSearch.startsWith('https://')) {
      finalSearch = `"*${trimedSearch.replace('https://', '')}*"`;
    } else if (trimedSearch.startsWith('"')) {
      finalSearch = `${trimedSearch}`;
    } else {
      finalSearch = pipe(
        split(' '),
        map(n => `*${n}*`),
        join(' ')
      )(trimedSearch);
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
      const { key, values, operator = 'eq' } = validFilters[index];
      for (let i = 0; i < values.length; i += 1) {
        if (values[i] === null) {
          mustnot = append({ exists: { field: key } }, mustnot);
        } else if (operator === 'eq') {
          must = append({ match_phrase: { [key]: values[i] } }, must);
        } else {
          must = append({ range: { [key]: { [operator]: values[i] } } }, must);
        }
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
        const loadedElement = pipe(
          assoc('id', n._source.internal_id_key),
          assoc('_index', n._index)
        )(n._source);
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
    .catch(err => console.log('[ELASTIC] Paginate error', err));
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
  const data = await el.search(query).catch(err => console.log('[ELASTIC] loadTerm error', err));
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
        .catch(() => {
          return false;
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
      body: dissoc('_index', documentBody)
    })
    .catch(err => {
      logger.error(`[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}, ${err}`);
    });
  return documentBody;
};
export const elUpdate = (indexName, documentId, documentBody, retry = 0) => {
  return el.update({
    id: documentId,
    index: indexName,
    retry_on_conflict: retry,
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
      source: `ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: to.internal_id_key
      }
    }
  });
  // Update to to entity
  await elUpdate(to._index, to.grakn_id, {
    script: {
      source: `ctx._source['${type}'].removeIf(rel -> rel == params.key);`,
      params: {
        key: from.internal_id_key
      }
    }
  });
};
