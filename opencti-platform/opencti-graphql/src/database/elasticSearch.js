/* eslint-disable no-underscore-dangle */
import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import {
  map,
  dissoc,
  append,
  assoc,
  mapObjIndexed,
  pipe,
  split,
  join,
  head
} from 'ramda';
import { buildPagination } from './utils';
import conf, { logger } from '../config/conf';

const dateFields = [
  'created',
  'modified',
  'created_at',
  'updated_at',
  'first_seen',
  'last_seen',
  'published'
];

const numberFields = ['object_status'];

export const INDEX_STIX_OBSERVABLE = 'stix_observables';
export const defaultIndexes = [
  'stix_domain_entities',
  'stix_relations',
  INDEX_STIX_OBSERVABLE,
  'external_references',
  'work_jobs'
];

const indexedRelations = ['tags', 'createdByRef', 'markingDefinitions'];

export const el = new Client({ node: conf.get('elasticsearch:url') });

export const elasticIsAlive = async () => {
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

export const getElasticVersion = () => {
  return el
    .info()
    .then(info => info.body.version.number)
    .catch(() => 'Disconnected');
};

export const createIndexes = async () => {
  return Promise.all(
    defaultIndexes.map(index => {
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

export const deleteIndexes = async (indexes = null) => {
  let indexesToDelete = defaultIndexes;
  if (indexes !== null) {
    indexesToDelete = indexes;
  }
  return Promise.all(
    indexesToDelete.map(index => {
      return el.indices.delete({ index }).catch(() => {
        return false;
      });
    })
  );
};

export const reindex = async indexMaps => {
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

export const index = async (indexName, documentBody, refresh = true) => {
  const internalId = documentBody.internal_id_key;
  const entityType = documentBody.entity_type ? documentBody.entity_type : '';
  logger.debug(
    `[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}`
  );
  await el.index({
    index: indexName,
    id: documentBody.grakn_id,
    refresh,
    body: dissoc('_index', documentBody)
  });
  return documentBody;
};

export const elUpdate = (indexName, documentId, documentBody) => {
  return el.update({
    id: documentId,
    index: indexName,
    refresh: true,
    body: {
      doc: documentBody
    }
  });
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

export const deleteEntity = async (indexName, documentId) => {
  logger.debug(`[ELASTICSEARCH] deleteEntity > ${documentId} on ${indexName}`);
  // noinspection UnnecessaryLocalVariableJS
  const deletePromise = await el
    .delete({
      index: indexName,
      id: documentId,
      refresh: true
    })
    .catch(() => {
      return false;
    });
  return deletePromise;
};

export const countEntities = (indexName, options) => {
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

export const paginate = async (indexName, options) => {
  const {
    first = 200,
    after,
    type = null,
    types = null,
    reportClass = null,
    filters = null,
    isUser = null,
    search = null,
    orderBy = null,
    orderMode = 'asc',
    connectionFormat = true
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
    must = append(
      {
        match_all: {}
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
  if (reportClass !== null && reportClass.length > 0) {
    must = append(
      {
        match_phrase: {
          report_class: {
            query: reportClass
          }
        }
      },
      must
    );
  }
  if (filters !== null) {
    await mapObjIndexed((value, key) => {
      let finalKey = key;
      if (indexedRelations.includes(key)) {
        finalKey = `${key}_indexed`;
      }
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i += 1) {
          if (value[i] === null) {
            mustnot = append(
              {
                exists: {
                  field: finalKey
                }
              },
              mustnot
            );
            break;
          } else {
            must = append(
              {
                match_phrase: {
                  [finalKey]: {
                    query: value[i]
                  }
                }
              },
              must
            );
          }
        }
      } else if (value === null) {
        mustnot = append(
          {
            exists: {
              field: finalKey
            }
          },
          mustnot
        );
      } else {
        must = append(
          {
            match_phrase: {
              [finalKey]: {
                query: value
              }
            }
          },
          must
        );
      }
    }, filters);
  }
  if (isUser !== null && isUser === true) {
    must = append(
      {
        exists: {
          field: 'email'
        }
      },
      must
    );
  }
  if (orderBy !== null && orderBy.length > 0) {
    let finalOrderBy = orderBy;
    if (indexedRelations.includes(orderBy)) {
      finalOrderBy = `${orderBy}_indexed`;
    }
    const order = {};
    order[
      dateFields.includes(finalOrderBy) || numberFields.includes(finalOrderBy)
        ? finalOrderBy
        : `${finalOrderBy}.keyword`
    ] = orderMode;
    ordering = append(order, ordering);
  }

  const query = {
    index: indexName,
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
      const dataWithIds = map(
        n => assoc('id', n._source.internal_id_key, n._source),
        data.body.hits.hits
      );
      if (connectionFormat) {
        const nodeHits = map(n => ({ node: n }), dataWithIds);
        return buildPagination(
          first,
          offset,
          nodeHits,
          data.body.hits.total.value
        );
      }
      return dataWithIds;
    })
    .catch(() => {
      return connectionFormat ? buildPagination(first, offset, [], 0) : [];
    });
};

export const loadByTerms = async (terms, indices = defaultIndexes) => {
  const query = {
    index: indices,
    body: {
      query: {
        bool: {
          should: map(x => ({ term: x }), terms)
        }
      }
    }
  };
  const data = await el.search(query);
  const total = data.body.hits.total.value;
  const response = total > 0 ? head(data.body.hits.hits) : undefined;
  if (!response) return response;
  return assoc('_index', response._index, response._source);
};
/**
 *   // 01. If data need to be requested from the index cache system
 if (getIndex) {
    try {
      // eslint-disable-next-line prettier/prettier
      logger.debug(`[ELASTICSEARCH] refetchByConcept get > ${head(types)} ${id} on ${getIndex}`);
      const fromCache = await loadByGraknId(id, getIndex);
      return pipe(
        mapObjIndexed((value, key) =>
          Array.isArray(value) && !includes(key, multipleAttributes)
            ? head(value)
            : value
        ),
        assoc('id', elAttributes.internal_id_key),
        assoc('parent_type', parentTypeLabel)
      )(elAttributes);
    } catch (e) {
      // eslint-disable-next-line prettier/prettier
      logger.debug(`[ELASTICSEARCH] refetchByConcept missing > ${head(types)} ${id} on ${getIndex}`);
    }
  }
 */

export const loadById = (id, indices = defaultIndexes) => {
  return loadByTerms([{ 'internal_id_key.keyword': id }], indices);
};
export const loadByStixId = (id, indices = defaultIndexes) => {
  return loadByTerms([{ 'stix_id_key.keyword': id }], indices);
};
export const loadByGraknId = (id, indices = defaultIndexes) => {
  return loadByTerms([{ 'grakn_id.keyword': id }], indices);
};

export const findByTerms = async (terms, indices = defaultIndexes) => {
  const query = {
    index: indices,
    body: {
      query: {
        bool: {
          should: map(x => ({ term: x }), terms)
        }
      }
    }
  };
  return el.search(query).then(data => {
    return {
      edges: map(
        x => ({ node: assoc('_index', x._index, x._source) }),
        data.body.hits.hits
      ),
      pageInfo: {
        globalCount: data.body.hits.total.value
      }
    };
  });
};

/*
export const getAttributes = (indexName, id) => {
  return el
    .get({ id, index: indexName })
    .then(data => {
      return assoc('_index', indexName, data.body._source);
    })
    .catch(e => {
      if (e.meta.statusCode !== 404) {
        // If another error than not found.
        logger.error(`[ELASTICSEARCH] getAttributes > error getting ${id}`, e);
      }
      return null;
    });
};
*/
