/* eslint-disable no-underscore-dangle */
import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import { append, assoc, concat, dissoc, head, includes, join, map, pipe, split } from 'ramda';
import { buildPagination } from './utils';
import conf, { logger } from '../config/conf';

const dateFields = ['created', 'modified', 'created_at', 'updated_at', 'first_seen', 'last_seen', 'published'];
const numberFields = ['object_status'];

export const INDEX_STIX_OBSERVABLE = 'stix_observables';
export const INDEX_STIX_ENTITIES = 'stix_domain_entities';
export const INDEX_STIX_RELATIONS = 'stix_relations';
export const INDEX_WORK_JOBS = 'work_jobs_index';
export const PLATFORM_INDICES = [INDEX_STIX_ENTITIES, INDEX_STIX_RELATIONS, INDEX_STIX_OBSERVABLE, INDEX_WORK_JOBS];

/*
export const relationsToIndex = {
  'Stix-Domain': [
    {
      type: 'tagged',
      key: 'tags_indexed',
      query: 'match $t isa Tag, has internal_id_key $value; (so: $x, tagging: $t) isa tagged;'
    },
    {
      type: 'created_by_ref',
      key: 'createdByRef_indexed',
      query: 'match $i isa Identity, has internal_id_key $value; (so: $x, creator: $i) isa created_by_ref;'
    },
    {
      type: 'object_marking_refs',
      key: 'markingDefinitions_indexed',
      query:
        'match $m isa Marking-Definition, has internal_id_key $value; (so: $x, marking: $m) isa object_marking_refs;'
    }
  ],
  'Stix-Observable': [
    {
      type: 'tagged',
      key: 'tags_indexed',
      query: 'match $t isa Tag, has value $value; (so: $x, tagging: $t) isa tagged;'
    }
  ]
};
*/

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

export const elPaginate = async (indexName, options) => {
  const {
    first = 200,
    after,
    types = null,
    reportClass = null,
    filters = [],
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
  if (filters && filters.length > 0) {
    for (let index = 0; index < filters.length; index += 1) {
      const { key, values } = filters[index];
      for (let i = 0; i < values.length; i += 1) {
        if (values[i] === null) {
          mustnot = append(
            {
              exists: {
                field: key
              }
            },
            mustnot
          );
          break;
        } else if (includes('.', key)) {
          must = append(
            {
              exists: {
                field: `${key}.${values[i]}`
              }
            },
            must
          );
          break;
        } else {
          must = append(
            {
              match_phrase: {
                [key]: {
                  query: values[i]
                }
              }
            },
            must
          );
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
        n =>
          pipe(
            assoc('id', n._source.internal_id_key),
            assoc('_index', n._index)
          )(n._source),
        data.body.hits.hits
      );
      if (connectionFormat) {
        const nodeHits = map(n => ({ node: n }), dataWithIds);
        return buildPagination(first, offset, nodeHits, data.body.hits.total.value);
      }
      return dataWithIds;
    })
    .catch(() => {
      return connectionFormat ? buildPagination(first, offset, [], 0) : [];
    });
};

export const elLoadByTerms = async (terms, indices = PLATFORM_INDICES) => {
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
  const data = await el.search(query).catch(err => {
    console.log(err);
  });
  const total = data.body.hits.total.value;
  const response = total > 0 ? head(data.body.hits.hits) : undefined;
  if (!response) return response;
  return assoc('_index', response._index, response._source);
};
/**
 *   // 01. If data need to be requested from the elIndex cache system
 if (getIndex) {
    try {
      // eslint-disable-next-line prettier/prettier
      logger.debug(`[ELASTICSEARCH] refetchByConcept get > ${head(types)} ${id} on ${getIndex}`);
      const fromCache = await elLoadByGraknId(id, getIndex);
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
export const elLoadById = (id, indices = PLATFORM_INDICES) => {
  return elLoadByTerms([{ 'internal_id_key.keyword': id }], indices);
};
export const elLoadByStixId = (id, indices = PLATFORM_INDICES) => {
  return elLoadByTerms([{ 'stix_id_key.keyword': id }], indices);
};
export const elLoadByGraknId = (id, indices = PLATFORM_INDICES) => {
  return elLoadByTerms([{ 'grakn_id.keyword': id }], indices);
};

const elFindTerms = ({ terms, ranges }, type = 'should', indices) => {
  const mappedTerms = terms ? map(x => ({ term: x }), terms) : [];
  const mappedRanges = ranges ? map(x => ({ range: x }), ranges) : [];
  const query = {
    index: indices,
    body: {
      query: {
        bool: {
          [type]: concat(mappedTerms, mappedRanges)
        }
      }
    }
  };
  return el
    .search(query)
    .then(data => {
      const nodeHits = map(x => ({ node: assoc('_index', x._index, x._source) }), data.body.hits.hits);
      return buildPagination(0, 0, nodeHits, data.body.hits.total.value);
    })
    .catch(err => {
      console.log(err);
    });
};
export const elFindTermsOr = async (terms, indices = PLATFORM_INDICES) => {
  return elFindTerms({ terms }, 'should', indices);
};
export const elFindTermsAnd = async ({ terms, ranges }, indices = PLATFORM_INDICES) => {
  return elFindTerms({ terms, ranges }, 'must', indices);
};
export const elFindRelationAndTarget = async (fromStixId, relationType) => {
  const fromEntity = await elLoadById(fromStixId);
  const data = await elFindTermsAnd({
    terms: [{ 'fromId.keyword': fromEntity.grakn_id }, { 'relationship_type.keyword': relationType }]
  });
  const transform = await Promise.all(
    map(t => {
      return elLoadByGraknId(t.node.toId).then(node => ({
        node,
        relation: t.node
      }));
    }, data.edges)
  );
  return buildPagination(0, 0, transform, transform.length);
};
export const elLoadRelationAndTarget = async (fromStixId, relationType) => {
  const data = await elFindRelationAndTarget(fromStixId, relationType);
  return head(data.edges);
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
export const elUpdate = (indexName, documentId, documentBody) => {
  return el.update({
    id: documentId,
    index: indexName,
    refresh: true,
    body: documentBody
  });
};
export const elUpdateAddInnerRelation = async (internalId, relationType, targetId, relationId) => {
  const previousEntity = await elLoadById(internalId);
  const indexKey = `${relationType}.internal_id_key.${targetId}`;
  const doc = { [indexKey]: relationId };
  await elUpdate(previousEntity._index, previousEntity.grakn_id, { doc });
};
export const elUpdateRemoveInnerRelation = async (internalId, relationType, targetId) => {
  const previousEntity = await elLoadById(internalId);
  const scriptToExecute = `ctx._source.remove('${relationType}.internal_id_key.${targetId}')`;
  await elUpdate(previousEntity._index, previousEntity.grakn_id, { script: scriptToExecute });
};
