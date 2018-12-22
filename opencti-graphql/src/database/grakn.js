import axios from 'axios';
import {
  assoc,
  chain,
  contains,
  groupBy,
  head,
  isEmpty,
  join,
  last,
  map,
  mapObjIndexed,
  pipe,
  pluck,
  toPairs,
  values
} from 'ramda';
import moment from 'moment';
import { offsetToCursor } from 'graphql-relay';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn';
import conf, { logger } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { pubsub } from './redis';

// Global variables
const gkDateFormat = 'YYYY-MM-DDTHH:mm:ss';
const gkDate = 'java.time.LocalDateTime';
const String = 'String';
export const now = () =>
  moment()
    .utc()
    .format(gkDateFormat); // Format that accept grakn

// Attributes key that can contains multiple values.
const multipleAttributes = ['stix_label', 'grant'];

// Instance of Axios to make Grakn API Calls.
const client = new Grakn(conf.get('grakn:driver'));
const axiosInstance = axios.create({
  baseURL: conf.get('grakn:baseURL'),
  timeout: conf.get('grakn:timeout')
});

export const notify = (topic, instance, user, context) => {
  pubsub.publish(topic, { instance, user, context });
  return instance;
};

/**
 * API Grakn call to get all attributes for an instance.
 * @param id
 * @returns {AxiosPromise}
 */
const attrByID = id =>
  axiosInstance({ method: 'get', url: `${id}/attributes` });

/**
 * Mapping function to generate a valid json objects base on Grakn response.
 * @param id
 * @param res
 * @param withType
 * @returns {Promise<any>}
 */
const attrMap = (id, res, withType = false) => {
  const transform = pipe(
    map(attr => {
      let transformedVal = attr.value;
      const type = attr['data-type'];
      if (type === gkDate) {
        // Patch for grakn LocalDate.
        transformedVal = `${moment(attr.value).format(gkDateFormat)}Z`;
      }
      return {
        [attr.type.label]: withType
          ? { type, val: transformedVal }
          : transformedVal
      };
    }), // Extract values
    chain(toPairs), // Convert to pairs for grouping
    groupBy(head), // Group by key
    map(pluck(1)), // Remove grouping boilerplate
    mapObjIndexed((num, key, obj) =>
      obj[key].length === 1 && !contains(key, multipleAttributes)
        ? head(obj[key])
        : obj[key]
    ) // Remove extra list then contains only 1 element
  )(res.data.attributes);
  return Promise.resolve(assoc('id', id, transform));
};

/**
 * Basic grakn query function
 * @param queryDef
 * @returns {Promise<AxiosResponse<any> | never>}
 */
export const qk = queryDef => {
  logger.debug(`Grakn query: ${queryDef}`);
  return axiosInstance({
    method: 'post',
    url: '/kb/grakn/graql',
    data: queryDef
  }).catch(error => {
    logger.error(`Grakn query error: ${queryDef}`, error.response.data);
    throw new FunctionalError({ message: error.response.data.exception });
  });
};

/**
 * Grakn query that generate json objects
 * @param queryDef the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const qkObj = (queryDef, key = 'x', relationKey) =>
  qk(queryDef).then(result => {
    if (result && result.data) {
      return Promise.all(
        map(line => ({
          node: attrByID(line[key]['@id']).then(res =>
            attrMap(line[key].id, res)
          ),
          relation: !relationKey
            ? null
            : attrByID(line[relationKey]['@id']).then(res =>
                attrMap(line[relationKey].id, res)
              )
        }))(result.data)
      );
    }
    return Promise.resolve([]);
  });

/**
 * Grakn query that fetch unique value like attribute count.
 * @param queryDef
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const qkSingleValue = queryDef =>
  qk(queryDef).then(result =>
    result && result.data.length > 0 ? head(result.data) : null
  );

/**
 * Grakn generic function to delete an instance.
 * @param id
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const deleteByID = id => {
  const delUser = qk(`match $x id ${id}; delete $x;`);
  return delUser.then(result => {
    if (isEmpty(result.data)) {
      throw new FunctionalError({ message: "Element doesn't exist" });
    } else {
      return id;
    }
  });
};

/**
 * Load any grakn instance with internal grakn ID.
 * @param id
 * @param withType
 * @returns {Promise<any[] | never>}
 */
export const loadByID = (id, withType = false) =>
  qk(`match $x id ${id}; get;`).then(
    result =>
      Promise.all(
        map(line =>
          attrByID(line.x['@id']).then(res => attrMap(id, res, withType))
        )(result.data)
      ).then(r => head(r)) // Return the unique result
  );

/**
 * Edit an attribute value.
 * @param id
 * @param input
 * @returns the complete instance
 */
export const editInputTx = async (id, input) => {
  const { key, value } = input;
  const session = await client.session('grakn');
  const wTx = await session.transaction(Grakn.txType.WRITE);
  const labelIterator = await wTx.query(
    `match $x label "${key}" sub attribute; get;`
  );
  const labelAnswer = await labelIterator.next();
  const type = await labelAnswer
    .map()
    .get('x')
    .dataType();
  // Delete the old value/values
  await wTx.query(`match $m id ${id}; $m has ${key} $del via $d; delete $d;`);
  // Setup the new attribute
  await wTx.query(
    `match $m id ${id}; insert $m ${join(
      ' ',
      map(val => `has ${key} ${type === String ? `"${val}"` : val}`, value)
    )};`
  );
  await wTx.commit();
  return loadByID(id);
};

/**
 * Create a relation between to element in the model without restriction.
 * @param id
 * @param input
 * @returns {Promise<any[] | never>}
 */
export const createRelation = (id, input) => {
  const createRel = qk(`match $from id ${id}; 
         $to id ${input.toId}; 
         insert (${input.fromRole}: $from, ${input.toRole}: $to) 
         isa ${input.through};`);
  return createRel.then(() => loadByID(id));
};

/**
 * Pure building of pagination expected format.
 * @param first
 * @param offset
 * @param instances
 * @param globalCount
 * @returns {{edges: *, pageInfo: *}}
 */
const buildPagination = (first, offset, instances, globalCount) => {
  const edges = pipe(
    mapObjIndexed((record, key) => {
      const { node } = record;
      const { relation } = record;
      const nodeOffset = offset + parseInt(key, 10) + 1;
      return { node, relation, cursor: offsetToCursor(nodeOffset) };
    }),
    values
  )(instances);
  const hasNextPage = first + offset < globalCount;
  const hasPreviousPage = offset > 0;
  const startCursor = edges.length > 0 ? head(edges).cursor : '';
  const endCursor = edges.length > 0 ? last(edges).cursor : '';
  const pageInfo = {
    startCursor,
    endCursor,
    hasNextPage,
    hasPreviousPage,
    globalCount
  };
  return { edges, pageInfo };
};

/**
 * Grakn generic pagination query.
 * @param query
 * @param options
 * @returns Promise
 */
export const paginate = (query, options) => {
  const { first = 200, after, orderBy = 'created_at', orderMode = 'asc' } = options;
  const offset = after ? cursorToOffset(after) : 0;
  const instanceKey = /match\s\$(\w+)\s/i.exec(query)[1]; // We need to resolve the key instance used in query.
  const findRelationVariable = /\$(\w+)\((\w+):\$(\w+),[\s\w:$]+\)/i.exec(
    query
  );
  const relationKey = findRelationVariable && findRelationVariable[1]; // Could be setup to get relation info
  const count = qkSingleValue(`${query}; aggregate count;`);
  const elements = qkObj(
    `${query}; $${instanceKey} has ${orderBy} $o; 
      order by $o ${orderMode}; offset ${offset}; limit ${first}; 
      get $${instanceKey}${relationKey ? `, $${relationKey}` : ''};`,
    instanceKey,
    relationKey
  );
  return Promise.all([count, elements]).then(data => {
    const globalCount = data ? head(data) : 0;
    const instances = data ? last(data) : [];
    return buildPagination(first, offset, instances, globalCount);
  });
};

export default axiosInstance;
