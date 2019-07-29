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

const defaultIndexes = [
  'stix_domain_entities',
  'stix_relations',
  'stix_observables',
  'external_references'
];

export const el = new Client({ node: conf.get('elasticsearch:url') });

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
      return el.indices.delete({ index });
    })
  );
};

export const reindex = async indexMaps => {
  return Promise.all(
    indexMaps.map(indexMap => {
      return el.reindex({
        timeout: '60m',
        body: {
          source: {
            index: indexMap.source
          },
          dest: {
            index: indexMap.dest
          }
        }
      });
    })
  );
};

export const index = (indexName, documentBody) => {
  logger.debug(`[ELASTICSEARCH] Indexing in ${indexName}`);
  el.index({
    index: indexName,
    id: documentBody.grakn_id,
    body: documentBody
  }).catch(() => {
    return false;
  });
};

export const deleteEntity = async (indexName, documentId) => {
  logger.debug(`[ELASTICSEARCH] deleteById ${documentId} on ${indexName}`);
  await el
    .delete({
      index: indexName,
      id: documentId
    })
    .catch(() => {
      return false;
    });
  return true;
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
  logger.debug(`[ELASTICSEARCH] ${JSON.stringify(query)}`);
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
    search = null,
    orderBy = null,
    orderMode = 'asc'
  } = options;
  const offset = after ? cursorToOffset(after) : 0;
  let must = [];
  let ordering = [];
  if (search !== null && search.length > 0) {
    let finalSearch;
    if (search.includes('http://') || search.includes('https://')) {
      finalSearch = `"*${search
        .replace('http://', '')
        .replace('https://', '')}*"`;
    } else if (!search.startsWith('"')) {
      finalSearch = `*${search}*`;
    } else {
      finalSearch = `${search}`;
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
  if (orderBy !== null && orderBy.length > 0) {
    const order = {};
    order[
      dateFields.includes(orderBy) ? orderBy : `${orderBy}.keyword`
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
          must
        }
      }
    }
  };
  logger.debug(`[ELASTICSEARCH] ${JSON.stringify(query)}`);
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
};

export const getAttributes = (indexName, id) => {
  logger.debug(`[ELASTICSEARCH] getById ${id} on ${indexName}`);
  return el
    .get({
      index: indexName,
      id
    })
    .then(data => {
      return data._source;
    })
    .catch(() => {
      return Promise.resolve({});
    });
};
