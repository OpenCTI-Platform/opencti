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
export const el = new Client({ node: conf.get('elasticsearch:url') });

export const createIndexes = () => {
  const indexes = [
    'stix-domain-entities',
    'stix-relations',
    'stix-observables',
    'external-references'
  ];
  indexes.map(index => {
    return el.indices.exists({ index }).then(result => {
      if (result === false) {
        return el.indices.create({
          index,
          body: {
            settings: {
              index: {
                max_result_window: 100000
              }
            }
          }
        });
      }
      return result;
    });
  });
};

export const index = (indexName, documentType, documentBody) => {
  logger.debug(`[ELASTICSEARCH] Indexing a ${documentType}`);
  el.index({
    index: indexName,
    id: documentBody.grakn_id,
    type: documentType,
    body: documentBody
  }).catch(() => {
    return false;
  });
};

export const deleteEntity = async (indexName, documentType, documentId) => {
  logger.debug(`[ELASTICSEARCH] deleteById ${documentId} on ${indexName}`);
  await el
    .delete({
      index: indexName,
      id: documentId,
      type: documentType
    })
    .catch(() => {
      return false;
    });
  return true;
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

export const getAttributes = (indexName, type, id) => {
  logger.debug(`[ELASTICSEARCH] getById ${id} on ${indexName}`);
  return el
    .get({
      index: indexName,
      type,
      id
    })
    .then(data => {
      return data._source;
    })
    .catch(() => {
      return Promise.resolve({});
    });
};
