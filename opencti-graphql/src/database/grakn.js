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
  values
} from 'ramda';
import moment from 'moment';
import { offsetToCursor } from 'graphql-relay';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn';
import conf, { logger } from '../config/conf';
import { pubsub } from './redis';
import { fillTimeSeries, randomKey, later } from './utils';

// Global variables
const dateFormat = 'YYYY-MM-DDTHH:mm:ss';
const String = 'String';
const Date = 'Date';
const Boolean = 'Boolean';
export const now = () =>
  moment()
    .utc()
    .format(dateFormat); // Format that accept grakn
export const prepareDate = date =>
  moment(date)
    .utc()
    .format(dateFormat);
export const yearFormat = date => moment(date).format('YYYY');
export const monthFormat = date => moment(date).format('YYYY-MM');
export const dayFormat = date => moment(date).format('YYYY-MM-DD');
export const prepareString = s =>
  s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '';

// Attributes key that can contains multiple values.
export const multipleAttributes = [
  'stix_label',
  'alias',
  'grant',
  'platform',
  'required_permission'
];
export const statsDateAttributes = [
  'first_seen', // Standard
  'last_seen', // Standard
  'published' // Standard
];

// Instance of Axios to make Grakn API Calls.
const client = new Grakn(
  `${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`
);
const session = client.session('grakn');

export const takeReadTx = async () => {
  return session.transaction(Grakn.txType.READ);
};

export const takeWriteTx = async () => {
  return session.transaction(Grakn.txType.WRITE);
};

export const notify = (topic, instance, user, context) => {
  if (pubsub) pubsub.publish(topic, { instance, user, context });
  return instance;
};

export const write = async query => {
  const wTx = await takeWriteTx();
  await wTx.query(query);
  await wTx.commit();
};

/**
 * Load any grakn instance with internal grakn ID.
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const getById = async id => {
  logger.debug(`Grakn getById: ${id}`);
  const rTx = await takeReadTx();
  const concept = await rTx.getConcept(id);
  const attributesIterator = await concept.attributes();
  const attributes = await attributesIterator.collect();
  const attributesPromises = attributes.map(async attribute => {
    const attributeType = await attribute.type();
    return {
      'data-type': await attributeType.dataType(),
      type: await attributeType.label(),
      value: await attribute.value()
    };
  });
  const conceptResult = await Promise.all(attributesPromises).then(
    attributesData => {
      const transform = pipe(
        map(attribute => {
          let transformedVal = attribute.value;
          const type = attribute['data-type'];
          if (type === Date) {
            transformedVal = `${moment(attribute.value).format(dateFormat)}Z`;
          }
          if (type === Boolean) {
            transformedVal = attribute.value === 'true';
          }
          return { [attribute.type]: transformedVal };
        }), // Extract values
        chain(toPairs), // Convert to pairs for grouping
        groupBy(head), // Group by key
        map(pluck(1)), // Remove grouping boilerplate
        mapObjIndexed((num, key, obj) =>
          obj[key].length === 1 && !includes(key, multipleAttributes)
            ? head(obj[key])
            : obj[key]
        ) // Remove extra list then contains only 1 element
      )(attributesData);
      return Promise.resolve(assoc('id', id, transform));
    }
  );
  await rTx.close();
  return conceptResult;
};

/**
 * Grakn generic function to delete an instance (and orphan relationships)
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteEntityById = async id => {
  logger.debug(`Grakn deleteEntityById: ${id}`);
  const wTx = await takeWriteTx();
  wTx.query(`match $x id ${id}; $z($x, $y); delete $z, $x;`);
  await wTx.commit();
  return Promise.resolve(id);
};

/**
 * Grakn generic function to delete an entity by id
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteById = async id => {
  logger.debug(`Grakn deleteById: ${id}`);
  const wTx = await takeWriteTx();
  wTx.query(`match $x id ${id}; delete $x;`);
  await wTx.commit();
  return Promise.resolve(id);
};

/**
 * Get a single value from a Grakn query
 * @param query
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getSingleValue = async (query, infer = false) => {
  logger.debug(`Grakn query [infer: ${infer}]: ${query}`);
  const rTx = await takeReadTx();
  const iterator = await rTx.query(query, { infer });
  const answers = await iterator.collect();
  await rTx.close();
  return Promise.resolve(answers[0]);
};

/**
 * Grakn query that generate json objects
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @returns {Promise<any[] | never>}
 */
export const getObjects = async (
  query,
  key = 'x',
  relationKey,
  infer = false
) => {
  const rTx = await takeReadTx();
  const iterator = await rTx.query(query, { infer });
  const answers = await iterator.collect();
  const answersPromises = await Promise.all(
    answers.map(answer => {
      console.log(answer);
      const answerData = answer.map();
      console.log(answerData);
      const nodePromise = getById(answer.id);
    })
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
 * @param ordered
 * @param relationOrderingKey
 * @param infer
 * @returns Promise
 */
export const paginate = (
  query,
  options,
  ordered = true,
  relationOrderingKey = null,
  infer = false
) => {
  const { first = 200, after, orderBy = null, orderMode = 'asc' } = options;
  const offset = after ? cursorToOffset(after) : 0;
  const instanceKey = /match\s\$(\w+)\s/i.exec(query)[1]; // We need to resolve the key instance used in query.
  const findRelationVariable = /\$(\w+)\((\w+):\$(\w+),[\s\w:$]+\)/i.exec(
    query
  );
  const relationKey = findRelationVariable && findRelationVariable[1]; // Could be setup to get relation info
  const count = getSingleValue(`${query}; aggregate count;`, infer).then(
    result => result.number()
  );
  const ordering = relationOrderingKey
    ? `$${relationOrderingKey} has ${orderBy} $o; order by $o ${orderMode};`
    : `$${instanceKey} has ${orderBy} $o; order by $o ${orderMode};`;
  const elements = getObjects(
    `${query}; ${
      ordered && orderBy ? ordering : ''
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
  const wTx = await takeWriteTx();
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
    const inferenceQueryRegex = /(\$(\d+|rel)\s)?\([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\sisa\s([\w-]+);/i.exec(
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
 * @returns the complete instance
 */
export const editInputTx = async (id, input) => {
  const { key, value } = input; // value can be multi valued
  // 00. If the transaction already exist, just continue the process
  const wTx = await takeWriteTx();

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
    let deleteQuery = null;
    if (oldNumOfRef > 1) {
      // In this case we need to remove the reference to the value
      deleteQuery = `match $m id ${id}; $m has ${key} $del via $d; $del == ${typedOldValue}; delete $d;`;
      await wTx.query(deleteQuery);
    } else {
      // In this case the instance of the attribute can be removed
      const attrGetQuery = `match $x isa ${key}; $x == ${typedOldValue}; $rel($x); get $x;`;
      const attrIterator = await wTx.query(attrGetQuery);
      const attrAnswer = await attrIterator.next();
      if (attrAnswer) {
        const attrId = await attrAnswer.map().get('x').id;
        deleteQuery = `match $attr id ${attrId}; delete $attr;`;
      }
    }
    if (deleteQuery) {
      await wTx.query(deleteQuery);
    }
  }

  // Setup the new attribute
  const typedValues = map(
    v => (attrType === String ? `"${prepareString(v)}"` : v),
    value
  );
  const graknValues = join(' ', map(val => `has ${key} ${val}`, typedValues));
  const createQuery = `match $m id ${id}; insert $m ${graknValues};`;
  await wTx.query(createQuery);
  await wTx.commit();

  if (includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(head(value));
    const monthValue = monthFormat(head(value));
    const yearValue = yearFormat(head(value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    await editInputTx(id, dayInput);
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    await editInputTx(id, monthInput);
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    return editInputTx(id, yearInput);
  }
  return getById(id);
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
    const nodeData = getById(input.toId);
    const relationData = getById(head(result.data).rel.id);
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
    getById(id).then(data => ({
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
export const buildPaginationRelationships = (
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
export const paginateRelationships = (
  query,
  options,
  extraRel = null,
  pagination = true
) => {
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
      : ''.catch
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
    } offset ${offset}; limit ${first}; get $rel, $from, $to ${
      extraRel !== null ? `, $${extraRel}` : ''
    };`,
    'rel',
    'from',
    'to',
    extraRel,
    inferred
  );
  if (pagination) {
    return Promise.all([count, elements]).then(data => {
      const globalCount = data ? head(data) : 0;
      const instances = data ? last(data) : [];
      return buildPaginationRelationships(
        first,
        offset,
        instances,
        globalCount
      );
    });
  }
  return Promise.all([count, elements]).then(data => {
    const globalCount = data ? head(data) : 0;
    const instances = data ? last(data) : [];
    return { globalCount, instances };
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
  const { operation, field, inferred } = options;
  const finalQuery = `${query}; $x has ${field} $g; aggregate group $g ${operation};`;
  return qk(finalQuery, inferred).then(result => {
    const data = result.data.map(n => ({
      label: /Value\s\[(.*)\]/i.exec(head(head(toPairs(n))))[1],
      value: head(last(head(toPairs(n))))
    }));
    return data;
  });
};

// TODO: REMOVE (DEPRECATED)
const gkDateFormat = 'YYYY-MM-DDTHH:mm:ss';
const gkDate = 'java.time.LocalDateTime';
const gkBoolean = 'java.lang.Boolean';

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
export const qk = async (queryDef, infer = false) => {
  logger.debug(`Grakn query: ${queryDef}`);
  return axiosInstance({
    method: 'post',
    url: `/kb/grakn/graql${infer ? '?infer=true' : ''}`,
    data: queryDef
  }).catch(async error => {
    logger.error(`Grakn query error: ${queryDef}`, error);
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
export const qkObjSimple = (queryDef, key = 'x', relationKey, infer = false) =>
  qk(queryDef, infer).then(result => {
    if (result && result.data) {
      return Promise.all(
        map(line => {
          const nodePromise = Promise.resolve({
            id: line[key].id
          });
          const relationPromise = !relationKey
            ? Promise.resolve(null)
            : line[relationKey].inferred
            ? Promise.resolve({
                id: line[relationKey].id,
                type: 'stix_relation',
                relationship_type: line[relationKey].type.label,
                inferred: true
              })
            : Promise.resolve({
                id: line[relationKey].id,
                type: 'stix_relation',
                relationship_type: line[relationKey].type.label,
                inferred: false
              });
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

const axiosInstance = axios.create({
  baseURL: conf.get('grakn:baseURL'),
  timeout: conf.get('grakn:timeout')
});
export default axiosInstance;
