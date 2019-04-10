import elasticsearch from 'elasticsearch';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import { pipe, map, append } from 'ramda';
import { buildPagination } from './grakn';
import conf, { isAppSearchable, logger } from '../config/conf';

export const el = isAppSearchable
  ? new elasticsearch.Client({
      host: `${conf.get('elasticsearch:hostname')}:${conf.get(
        'elasticsearch:port'
      )}`
    })
  : null;

export const createIndexes = () => {
  const indexes = [
    'stix-domain-entities',
    'stix-observables',
    'external-references'
  ];
  indexes.map(index => {
    return el.indices.exists({ index }).then(result => {
      if (result === false) {
        return el.indices.create({ index });
      }
      return result;
    });
  });
};

export const index = (indexName, documentType, documentBody) => {
  el.index({
    index: indexName,
    id: documentBody.id,
    type: documentType,
    body: documentBody
  });
};

export const paginate = (indexName, options) => {
  const {
    first = 200,
    after,
    type = null,
    reportClass = null,
    search = null,
    orderBy = null,
    orderMode = 'asc'
  } = options;
  const offset = after ? cursorToOffset(after) : 0;
  let must = [];
  let ordering = [];
  if (search !== null && search.length > 0) {
    must = append(
      {
        query_string: {
          query: search,
          analyze_wildcard: true,
          default_field: '*'
        }
      },
      must
    );
  } else {
    must = append({
      match_all: {}
    });
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
    order[orderBy] = orderMode;
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
      const finalData = pipe(
        map(n => ({
          node: n._source
        }))
      )(data.hits.hits);
      return buildPagination(first, offset, finalData, data.hits.total);
    })
    .catch(() => {
      return buildPagination(first, offset, [], 0);
    });
};
