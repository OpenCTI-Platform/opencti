/* eslint-disable no-await-in-loop */
import axios from 'axios';
import {
  assoc,
  chain,
  includes,
  groupBy,
  head,
  join,
  last,
  map,
  mapObjIndexed,
  pipe,
  pluck,
  toPairs,
  values,
  uniqBy,
  path
} from 'ramda';
import moment from 'moment';
import { offsetToCursor } from 'graphql-relay';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn';
import conf, { logger } from '../config/conf';
import { pubsub } from './redis';

// Global variables
const gkDateFormat = 'YYYY-MM-DDTHH:mm:ss';
const gkDate = 'java.time.LocalDateTime';
const gkBoolean = 'java.lang.Boolean';
const String = 'String';
const Date = 'Date';
export const now = () =>
  moment()
    .utc()
    .format(gkDateFormat); // Format that accept grakn
export const prepareDate = date =>
  moment(date)
    .utc()
    .format(gkDateFormat);
export const yearFormat = date => moment(date).format('YYYY');
export const monthFormat = date => moment(date).format('YYYY-MM');
export const dayFormat = date => moment(date).format('YYYY-MM-DD');
export const prepareString = s =>
  s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '';

export const fillTimeSeries = (startDate, endDate, interval, data) => {
  const startDateParsed = moment(startDate);
  const endDateParsed = moment(endDate);
  let dateFormat = null;

  switch (interval) {
    case 'year':
      dateFormat = 'YYYY';
      break;
    case 'month':
      dateFormat = 'YYYY-MM';
      break;
    default:
      dateFormat = 'YYYY-MM-DD';
  }

  const elementsOfInterval = endDateParsed.diff(
    startDateParsed,
    `${interval}s`,
    false
  );

  const newData = [];
  for (let i = 0; i <= elementsOfInterval; i++) {
    let value = 0;
    for (let j = 0; j < data.length; j++) {
      if (data[j].date === startDateParsed.format(dateFormat)) {
        value = data[j].value;
      }
    }
    newData[i] = {
      date: startDateParsed.endOf(interval).format(),
      value
    };
    startDateParsed.add(1, `${interval}s`);
  }
  return newData;
};

export const later = delay =>
  new Promise(resolve => {
    setTimeout(resolve, delay);
  });

export const randomKey = number => {
  let key = '';
  for (let i = 0; i < number; i++) {
    key += Math.floor(Math.random() * 10).toString();
  }
  return key;
};

// Attributes key that can contains multiple values.
export const multipleAttributes = [
  'stix_label',
  'alias',
  'grant',
  'graph_data'
];
// TODO Remove this after https://github.com/graknlabs/grakn/issues/4828
export const lowerCaseAttributes = [
  'name', // Standard
  'description', // Standard
  'stix_label', // Standard
  'alias', // Standard
  'source_name', // External Reference
  'external_id' // External Reference
];
export const statsDateAttributes = [
  'first_seen', // Standard
  'last_seen', // Standard
  'published' // Standard
];

// Instance of Axios to make Grakn API Calls.
const client = new Grakn(conf.get('grakn:driver'));
const axiosInstance = axios.create({
  baseURL: conf.get('grakn:baseURL'),
  timeout: conf.get('grakn:timeout')
});

export const takeTx = async () => {
  const session = await client.session('grakn');
  const wTx = await session.transaction(Grakn.txType.WRITE);
  return wTx;
};

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
      if (type === gkBoolean) {
        transformedVal = attr.value === 'true';
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
      obj[key].length === 1 && !includes(key, multipleAttributes)
        ? head(obj[key])
        : obj[key]
    ) // Remove extra list then contains only 1 element
  )(res.data.attributes);
  return Promise.resolve(assoc('id', id, transform));
};

/**
 * Basic grakn query function
 * @param queryDef
 * @param infer
 * @returns {Promise<AxiosResponse<any> | never>}
 */
export const qk = (queryDef, infer = false) => {
  logger.debug(`Grakn query: ${queryDef}`);
  return axiosInstance({
    method: 'post',
    url: `/kb/grakn/graql${infer ? '?infer=true' : ''}`,
    data: queryDef
  }).catch(async error => {
    logger.error(`Grakn query error: ${queryDef}`, error.response.data);
    // TODO: Workaround to avoid concurrency error on Grakn
    if (infer && error.response.data.exception === null) {
      await later(50);
      return qk(queryDef, infer);
    }
    return false;
  });
};

/**
 * Grakn query that generate json objects
 * @param queryDef the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const qkObj = (queryDef, key = 'x', relationKey, infer = false) =>
  qk(queryDef, infer).then(result => {
    if (result && result.data) {
      return Promise.all(
        map(line => {
          const nodePromise = attrByID(line[key]['@id']).then(res =>
            attrMap(line[key].id, res)
          );
          const relationPromise = !relationKey
            ? Promise.resolve(null)
            : line[relationKey].inferred
            ? Promise.resolve({
                id: line[relationKey].id,
                type: 'stix_relation',
                relationship_type: line[relationKey].type.label,
                inferred: true
              })
            : attrByID(line[relationKey]['@id'])
                .then(res => attrMap(line[relationKey].id, res))
                .then(data => assoc('inferred', false, data));
          return Promise.all([nodePromise, relationPromise]).then(
            ([node, relation]) => ({
              node,
              relation
            })
          );
        })(result.data)
      );
    }
    return Promise.resolve([]);
  });

/**
 * Grakn query that generate json objects for relations
 * @param queryDef the query to process
 * @param key the instance key to get id from.
 * @param fromKey the key to bind relation result.
 * @param toKey the key to bind relation result.
 * @param infer (get inferred relationships)
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const qkRel = (
  queryDef,
  key = 'rel',
  fromKey = 'from',
  toKey = 'to',
  extraRelKey,
  infer
) =>
  // return queryTx(queryDef);
  qk(queryDef, infer).then(result => {
    if (result && result.data) {
      return Promise.all(
        map(line => {
          const relationPromise = line[key].inferred
            ? Promise.resolve({
                id: Buffer.from(line[key]['explanation-query']).toString(
                  'base64'
                ),
                type: 'stix_relation',
                relationship_type: line[key].type.label,
                inferred: true
              })
            : attrByID(line[key]['@id'])
                .then(res => attrMap(line[key].id, res))
                .then(data => assoc('inferred', false, data));
          const fromPromise = attrByID(line[fromKey]['@id']).then(res =>
            attrMap(line[fromKey].id, res)
          );
          const toPromise = attrByID(line[toKey]['@id']).then(res =>
            attrMap(line[toKey].id, res)
          );
          const extraRelationPromise = !extraRelKey
            ? Promise.resolve(null)
            : attrByID(line[extraRelKey]['@id']).then(res =>
                attrMap(line[extraRelKey].id, res)
              );
          return Promise.all([
            relationPromise,
            fromPromise,
            toPromise,
            extraRelationPromise
          ]).then(([node, from, to, relation]) => {
            const finalResult = {
              node: pipe(
                assoc('from', from),
                assoc('to', to)
              )(node),
              relation
            };
            return finalResult;
          });
        })(result.data)
      );
    }
    return Promise.resolve([]);
  });

/**
 * Grakn query that generate json objects
 * @param queryDef the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const qkObjUnique = (queryDef, key = 'x', relationKey) =>
  qkObj(queryDef, key, relationKey).then(result => head(result));

/**
 * Grakn query that fetch unique value like attribute count.
 * @param queryDef
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const qkSingleValue = (queryDef, infer = false) =>
  qk(queryDef, infer).then(result =>
    result && result.data.length > 0 ? head(result.data) : null
  );

/**
 * Grakn generic function to delete an instance (and orphan relationships)
 * @param id
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const deleteByID = id => {
  const deleteQuery = qk(`match $x id ${id}; $z($x, $y); delete $z, $x;`);
  return deleteQuery.then(() => id);
};

/**
 * Grakn generic function to delete an entity by id
 * @param id
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const deleteOneById = id => {
  const deleteQuery = qk(`match $x id ${id}; delete $x;`);
  return deleteQuery.then(() => id);
};

/**
 * Load the first
 * @param type
 * @returns {Promise<any[] | never>}
 */
export const loadFirst = type =>
  qk(`match $x isa ${type}; offset 0; limit 1; get;`).then(
    result =>
      Promise.all(
        map(line =>
          attrByID(line.x['@id']).then(res => attrMap(line.x.id, res))
        )(result.data)
      ).then(r => head(r)) // Return the unique result
  );

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
 * Load any grakn relation with internal grakn ID.
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const loadRelationById = id =>
  qk(`match $x($from, $to); $x id ${id}; get;`).then(result => {
    if (result && result.data) {
      const line = head(result.data);
      const relationPromise = attrByID(line.x['@id'])
        .then(res => attrMap(line.x.id, res))
        .then(data => assoc('inferred', false, data));
      const fromPromise = attrByID(line.from['@id']).then(res =>
        attrMap(line.from.id, res)
      );
      const toPromise = attrByID(line.to['@id']).then(res =>
        attrMap(line.to.id, res)
      );
      return Promise.all([relationPromise, fromPromise, toPromise]).then(
        ([node, from, to]) => {
          const finalResult = pipe(
            assoc('from', to),
            assoc('to', from)
          )(node);
          return finalResult;
        }
      );
    }
    return Promise.resolve(null);
  });

export const loadRelationInferredById = async id => {
  const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
  let query;
  if (decodedQuery.endsWith('}')) {
    query = `match ${decodedQuery}; get;`;
  } else {
    query = `${decodedQuery.replace('(', '$rel (').slice(0, -1)}, $rel;`;
  }
  const queryRegex = /\([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\s[a-z_]+\s([\w-]+);/i.exec(
    query
  );
  const fromKey = queryRegex[1];
  const toKey = queryRegex[2];
  const relationType = queryRegex[3];
  const session = await client.session('grakn');
  const wTx = await session.transaction(Grakn.txType.WRITE);
  const answerIterator = await wTx.query(query);
  const answer = await answerIterator.next();
  const fromId = answer.map().get(fromKey).id;
  const toId = answer.map().get(toKey).id;
  const relationPromise = Promise.resolve({
    id,
    type: 'stix_relation',
    relationship_type: relationType,
    inferred: true
  });
  const fromPromise = attrByID(`/kb/grakn/concept/${fromId}`).then(res =>
    attrMap(fromId, res)
  );
  const toPromise = attrByID(`/kb/grakn/concept/${toId}`).then(res =>
    attrMap(toId, res)
  );
  const explanation = await answer.explanation();
  const explanationAnswers = await explanation.answers();
  const inferences = explanationAnswers.map(explanationAnswer => {
    const explanationAnswerExplanation = explanationAnswer.explanation();
    let inferenceQuery = explanationAnswerExplanation.queryPattern();
    const inferenceQueryRegex = /(\$(\d+)\s)?\([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\sisa\s([\w-]+);/i.exec(
      inferenceQuery
    );
    let relationKey;
    if (inferenceQueryRegex[2] !== undefined) {
      relationKey = inferenceQueryRegex[2];
    } else {
      relationKey = randomKey(5);
      inferenceQuery = inferenceQuery.replace('(', `$${relationKey} (`);
    }
    return {
      inferenceQuery,
      relationKey,
      fromKey: inferenceQueryRegex[3],
      toKey: inferenceQueryRegex[4],
      relationType: inferenceQueryRegex[5]
    };
  });
  const inferencesQueries = pluck('inferenceQuery', inferences);
  const inferencesQuery = `match {${join('; ', inferencesQueries)}; }; get;`;
  const inferencesAnswerIterator = await wTx.query(inferencesQuery);
  const inferencesAnswer = await inferencesAnswerIterator.next();
  const inferencesPromises = inferences.map(async inference => {
    const inferred = await inferencesAnswer
      .map()
      .get(inference.relationKey)
      .isInferred();
    const inferenceFromId = inferencesAnswer.map().get(inference.fromKey).id;
    const inferenceToId = inferencesAnswer.map().get(inference.toKey).id;
    const inferenceId = inferred
      ? Buffer.from(inference.inferenceQuery).toString('base64')
      : inferencesAnswer.map().get(inference.relationKey).id;
    return Promise.resolve({
      node: {
        id: inferenceId,
        inferred,
        relationship_type: inference.relationType,
        from: attrByID(`/kb/grakn/concept/${inferenceFromId}`).then(res =>
          attrMap(inferenceFromId, res)
        ),
        to: attrByID(`/kb/grakn/concept/${inferenceToId}`).then(res =>
          attrMap(inferenceToId, res)
        )
      }
    });
  });

  await wTx.close();
  await session.close();

  return Promise.all([
    relationPromise,
    fromPromise,
    toPromise,
    inferencesPromises
  ]).then(([node, from, to, relationInferences]) => {
    const finalResult = pipe(
      assoc('from', to),
      assoc('to', from),
      assoc('inferences', { edges: relationInferences })
    )(node);
    return finalResult;
  });
};

/**
 * Edit an attribute value.
 * @param id
 * @param input
 * @param transaction
 * @returns the complete instance
 */
export const editInputTx = async (id, input, transaction) => {
  const { key, value } = input; // value can be multi valued
  // 00. If the transaction already exist, just continue the process
  let wTx = transaction;
  if (!wTx) {
    const session = await client.session('grakn');
    wTx = await session.transaction(Grakn.txType.WRITE);
  }

  // 01. We need to fetch the type to quote the string if needed.
  const labelTypeQuery = `match $x label "${key}" sub attribute; get;`;
  const labelIterator = await wTx.query(labelTypeQuery);
  const labelAnswer = await labelIterator.next();
  // eslint-disable-next-line prettier/prettier
  const attrType = await labelAnswer.map().get('x').dataType();

  // 02. For each old values
  const getOldValueQuery = `match $x id ${id}; $x has ${key} $old; get $old;`;
  const oldValIterator = await wTx.query(getOldValueQuery);
  const oldValuesConcept = await oldValIterator.collectConcepts();
  for (let i = 0; i < oldValuesConcept.length; i += 1) {
    const oldValue = await oldValuesConcept[i].value();
    const typedOldValue =
      attrType === String
        ? `"${prepareString(oldValue)}"`
        : attrType === Date
        ? prepareDate(oldValue)
        : oldValue;
    // If the attribute is alone we can delete it, if not we need to remove the relation to it (via)
    const countRemainQuery = `match $x isa ${key}; $x == ${typedOldValue}; $rel($x); aggregate count;`;
    const countRemainIterator = await wTx.query(countRemainQuery);
    const countRemain = await countRemainIterator.next();
    const oldNumOfRef = await countRemain.number();
    // Start the delete phase
    let deleteQuery;
    if (oldNumOfRef > 1) {
      // In this case we need to remove the reference to the value
      deleteQuery = `match $m id ${id}; $m has ${key} $del via $d; $del == ${typedOldValue}; delete $d;`;
      await wTx.query(deleteQuery);
    } else {
      // In this case the instance of the attribute can be removed
      const attrGetQuery = `match $x isa ${key}; $x == ${typedOldValue}; $rel($x); get $x;`;
      const attrIterator = await wTx.query(attrGetQuery);
      const attrAnswer = await attrIterator.next();
      const attrId = await attrAnswer.map().get('x').id;
      deleteQuery = `match $attr id ${attrId}; delete $attr;`;
    }
    await wTx.query(deleteQuery);
  }

  // Setup the new attribute
  const typedValues = map(
    v => (attrType === String ? `"${prepareString(v)}"` : v),
    value
  );
  const graknValues = join(' ', map(val => `has ${key} ${val}`, typedValues));
  const createQuery = `match $m id ${id}; insert $m ${graknValues};`;
  await wTx.query(createQuery);

  // TODO Remove this after https://github.com/graknlabs/grakn/issues/4828
  if (includes(key, lowerCaseAttributes)) {
    const lowerValues = map(v => v.toLowerCase(), value);
    const joinedValues = join(' ', lowerValues);
    const newInput = { key: `${key}_lowercase`, value: [joinedValues] };
    return editInputTx(id, newInput, wTx);
  }
  if (includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(head(value));
    const monthValue = monthFormat(head(value));
    const yearValue = yearFormat(head(value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    editInputTx(id, dayInput, wTx);
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    editInputTx(id, monthInput, wTx);
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    return editInputTx(id, yearInput, wTx);
  }
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
         insert $rel(${input.fromRole}: $from, ${input.toRole}: $to) 
         isa ${input.through};`);
  return createRel.then(result => {
    const nodeData = loadByID(input.toId);
    const relationData = loadByID(head(result.data).rel.id);
    return Promise.all([nodeData, relationData]).then(
      ([nodeDataResult, relationDataResult]) => ({
        node: nodeDataResult,
        relation: relationDataResult
      })
    );
  });
};

/**
 * Grakn generic function to delete a relationship
 * @param id
 * @param relationID
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const deleteRelation = (id, relationId) => {
  // TODO : `match $x id ${relationId}; $z($x, $y); delete $z, $x;` is not working if $z doest not exists at all
  const deleteQuery = qk(`match $x id ${relationId}; delete $x;`);
  return deleteQuery.then(() =>
    loadByID(id).then(data => ({
      node: data,
      relation: { id: relationId }
    }))
  );
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
export const paginate = (
  query,
  options,
  ordered = true,
  relationOrderingKey = null,
  infer = false
) => {
  const {
    first = 200,
    after,
    orderBy = 'created_at',
    orderMode = 'asc'
  } = options;
  const offset = after ? cursorToOffset(after) : 0;
  const instanceKey = /match\s\$(\w+)\s/i.exec(query)[1]; // We need to resolve the key instance used in query.
  const findRelationVariable = /\$(\w+)\((\w+):\$(\w+),[\s\w:$]+\)/i.exec(
    query
  );
  const relationKey = findRelationVariable && findRelationVariable[1]; // Could be setup to get relation info
  const count = qkSingleValue(`${query}; aggregate count;`, infer);
  const ordering = relationOrderingKey
    ? `$${relationOrderingKey} has ${orderBy} $o; order by $o ${orderMode};`
    : `$${instanceKey} has ${orderBy} $o; order by $o ${orderMode};`;
  const elements = qkObj(
    `${query}; ${
      ordered ? ordering : ''
    } offset ${offset}; limit ${first}; get $${instanceKey}${
      relationKey ? `, $${relationKey}` : ''
    };`,
    instanceKey,
    relationKey,
    infer
  );
  return Promise.all([count, elements]).then(data => {
    const globalCount = data ? head(data) : 0;
    const instances = data ? last(data) : [];
    return buildPagination(first, offset, instances, globalCount);
  });
};

/**
 * Pure building of pagination expected format.
 * @param first
 * @param offset
 * @param instances
 * @param globalCount
 * @returns {{edges: *, pageInfo: *}}
 */
const buildPaginationRelationships = (
  first,
  offset,
  instances,
  globalCount
) => {
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
 * Grakn generic pagination query
 * @param query
 * @param options
 * @returns Promise
 */
export const paginateRelationships = (query, options, extraRel = null) => {
  const {
    fromId,
    toId,
    fromTypes,
    toTypes,
    firstSeenStart,
    firstSeenStop,
    lastSeenStart,
    lastSeenStop,
    weights,
    inferred,
    first = 200,
    after,
    orderBy,
    orderMode = 'asc'
  } = options;
  const offset = after ? cursorToOffset(after) : 0;
  const finalQuery = `${query}; ${fromId ? `$from id ${fromId};` : ''} ${
    toId ? `$to id ${toId};` : ''
  } ${
    fromTypes
      ? `${join(
          ' ',
          map(fromType => `{ $from isa ${fromType}; } or`, fromTypes)
        )} { $from isa ${head(fromTypes)}; };`
      : ''
  } ${
    toTypes
      ? `${join(
          ' ',
          map(toType => `{ $to isa ${toType}; } or`, toTypes)
        )} { $to isa ${head(toTypes)}; };`
      : ''
  } ${
    firstSeenStart
      ? `$rel has first_seen $fs; $fs > ${prepareDate(
          firstSeenStart
        )}; $fs < ${prepareDate(firstSeenStop)};`
      : ''
  } ${
    lastSeenStart
      ? `$rel has last_seen $ls; $ls > ${prepareDate(
          lastSeenStart
        )}; $ls < ${prepareDate(lastSeenStop)};`
      : ''
  } ${
    weights
      ? `$rel has weight $weight; ${join(
          ' ',
          map(weight => `{ $weight == ${weight}; } or`, weights)
        )} { $weight == 0; };`
      : ''
  }`;
  const count = qkSingleValue(`${finalQuery} aggregate count;`);
  const elements = qkRel(
    `${finalQuery} ${
      orderBy
        ? `${
            orderBy === 'first_seen' && firstSeenStart
              ? `order by $fs ${orderMode}`
              : `$rel has ${orderBy} $o; order by $o ${orderMode}`
          };`
        : ''
    } offset ${offset}; limit ${first}; get;`,
    'rel',
    'from',
    'to',
    extraRel,
    inferred
  );
  return Promise.all([count, elements]).then(data => {
    const globalCount = data ? head(data) : 0;
    const instances = data ? last(data) : [];
    return buildPaginationRelationships(first, offset, instances, globalCount);
  });
};

/**
 * Grakn generic timeseries
 * @param query
 * @param options
 * @returns Promise
 */
export const timeSeries = (query, options) => {
  const { startDate, endDate, operation, field, interval } = options;
  const finalQuery = `${query}; $x has ${field}_${interval} $g; aggregate group $g ${operation};`;
  return qk(finalQuery, true).then(result => {
    const data = result.data.map(n => ({
      date: /Value\s\[([\d-]+)\]/i.exec(head(head(toPairs(n))))[1],
      value: head(last(head(toPairs(n))))
    }));
    return fillTimeSeries(startDate, endDate, interval, data);
  });
};

/**
 * Grakn generic distribution
 * @param query
 * @param options
 * @returns Promise
 */
export const distribution = (query, options) => {
  const { operation, field } = options;
  const finalQuery = `${query}; $x has ${field} $g; aggregate group $g ${operation};`;
  return qk(finalQuery, true).then(result => {
    const data = result.data.map(n => ({
      label: /Value\s\[(.*)\]/i.exec(head(head(toPairs(n))))[1],
      value: head(last(head(toPairs(n))))
    }));
    return data;
  });
};

export default axiosInstance;
