import { Client } from '@elastic/elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import { map, append, assoc } from 'ramda';
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

const defaultIndexes = [
  'stix_domain_entities',
  'stix_relations',
  'stix_observables',
  'external_references'
];

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

export const index = async (indexName, documentBody) => {
  const internalId = documentBody.internal_id;
  const entityType = documentBody.entity_type;
  logger.debug(
    `[ELASTICSEARCH] index > ${entityType} ${internalId} in ${indexName}`
  );
  await el.index({
    index: indexName,
    id: documentBody.grakn_id,
    refresh: true,
    body: documentBody
  });
  return documentBody;
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

export const paginate = (indexName, options) => {
  const {
    first = 200,
    after,
    type = null,
    types = null,
    reportClass = null,
    isUser = null,
    search = null,
    orderBy = null,
    orderMode = 'asc'
  } = options;
  const offset = after ? cursorToOffset(after) : 0;
  let must = [];
  let ordering = [];
  if (search !== null && search.length > 0) {
    const trimedSearch = search.trim();
    let finalSearch;
    if (trimedSearch.includes('http://') || trimedSearch.includes('https://')) {
      finalSearch = `"*${trimedSearch
        .replace('http://', '')
        .replace('https://', '')}*"`;
    } else if (!trimedSearch.startsWith('"')) {
      finalSearch = `*${trimedSearch}*`;
    } else {
      finalSearch = `${trimedSearch}`;
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
    const order = {};
    order[
      dateFields.includes(orderBy) || numberFields.includes(orderBy)
        ? orderBy
        : `${orderBy}.keyword`
    ] = orderMode;
    ordering = append(order, ordering);
  }

  /* eslint-disable no-underscore-dangle */
  const query = {
    index: indexName,
    body: {
      from: offset,
      size: first,
      sort: ordering,
      query: {
        bool: {
          must
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] paginate > ${JSON.stringify(query)}`);
  return el
    .search(query)
    .then(data => {
      const finalData = map(
        n => ({
          node: assoc('id', n._source.internal_id, n._source)
        }),
        data.body.hits.hits
      );
      return buildPagination(
        first,
        offset,
        finalData,
        data.body.hits.total.value
      );
    })
    .catch(() => {
      return buildPagination(first, offset, [], 0);
    });
  /* eslint-enable no-underscore-dangle */
};

export const getAttributes = (indexName, id) => {
  return el
    .get({ id, index: indexName })
    .then(data => {
      // eslint-disable-next-line no-underscore-dangle
      return data.body._source;
    })
    .catch(e => {
      if (e.meta.statusCode !== 404) {
        // If another error than not found.
        logger.error(`[ELASTICSEARCH] getAttributes > error getting ${id}`, e);
      }
      return null;
    });
};
