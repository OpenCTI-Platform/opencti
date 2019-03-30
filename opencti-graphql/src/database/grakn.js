/* eslint-disable no-await-in-loop */
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
  fromPairs,
  toPairs,
  values
} from 'ramda';
import moment from 'moment';
import { offsetToCursor } from 'graphql-relay';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn';
import conf, { logger } from '../config/conf';
import { pubsub } from './redis';
import { fillTimeSeries, randomKey } from './utils';
import { Unknown } from '../config/errors';

// Global variables
const dateFormat = 'YYYY-MM-DDTHH:mm:ss';
const String = 'String';
const Date = 'Date';
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

// TODO Change after migration to READ for inferences
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
  const rTx = await takeReadTx();
  try {
    logger.debug(`[GRAKN - infer: false] getConcept(${id});`);
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
    const resultPromise = Promise.all(attributesPromises).then(
      attributesData => {
        const transform = pipe(
          map(attribute => {
            let transformedVal = attribute.value;
            const type = attribute['data-type'];
            if (type === Date) {
              transformedVal = `${moment(attribute.value).format(dateFormat)}Z`;
            }
            return { [attribute.type]: transformedVal };
          }), // Extract values
          chain(toPairs), // Convert to pairs for grouping
          groupBy(head), // Group by key
          map(pluck(1)), // Remove grouping boilerplate
          mapObjIndexed((num, key, obj) =>
            obj[key].length === 1 && !includes(key, multipleAttributes)
              ? head(obj[key])
              : head(obj[key]) && head(obj[key]).length > 0
              ? obj[key]
              : []
          ) // Remove extra list then contains only 1 element
        )(attributesData);
        return Promise.resolve(assoc('id', id, transform));
      }
    );
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve({});
  }
};

/**
 * Query and get entities of the first row
 * @param query
 * @param entities
 * @returns {Promise<any[] | never>}
 */
export const queryOne = async (query, entities) => {
  const rTx = await takeReadTx();
  try {
    logger.debug(`[GRAKN - infer: false] ${query}`);
    const iterator = await rTx.query(query);
    const answer = await iterator.next();
    const entitiesPromises = await entities.map(async entity => {
      return [entity, await getById(answer.map().get(entity).id)];
    });
    const resultPromise = Promise.all(entitiesPromises).then(data => {
      return fromPairs(data);
    });
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve({});
  }
};

/**
 * Query and get entities
 * @param query
 * @param entities
 * @returns {Promise<any[] | never>}
 */
export const queryMultiple = async (query, entities) => {
  const rTx = await takeReadTx();
  try {
    logger.debug(`[GRAKN - infer: false] ${query}`);
    const iterator = await rTx.query(query);
    const answers = await iterator.collect();
    const resultPromise = Promise.all(
      answers.map(async answer => {
        const entitiesPromises = await entities.map(async entity => {
          return [entity, await getById(answer.map().get(entity).id)];
        });
        return Promise.all(entitiesPromises).then(data => {
          return fromPairs(data);
        });
      })
    );
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve([]);
  }
};

/**
 * Load any grakn relation with internal grakn ID.
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const getRelationById = async id => {
  const rTx = await takeReadTx();
  try {
    const query = `match $x($from, $to); $x id ${id}; get;`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    const iterator = await rTx.query(query);
    const answer = await iterator.next();
    const relationPromise = await getById(answer.map().get('x').id).then(
      result => assoc('inferred', false, result)
    );
    const fromPromise = await getById(answer.map().get('from').id);
    const toPromise = await getById(answer.map().get('to').id);
    const resultPromise = Promise.all([
      relationPromise,
      fromPromise,
      toPromise
    ]).then(([relation, from, to]) => {
      return pipe(
        assoc('from', to),
        assoc('to', from)
      )(relation);
    });
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve({});
  }
};

/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const getRelationInferredById = async id => {
  const rTx = await takeWriteTx();
  try {
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
    logger.debug(`[GRAKN - infer: true] ${query}`);
    const answerIterator = await rTx.query(query);
    console.log(query);
    const answer = await answerIterator.next();
    const rel = answer.map().get('rel');
    const relationType = await rel.type();
    const relationTypeValue = await relationType.label();
    const fromId = answer.map().get(fromKey).id;
    const toId = answer.map().get(toKey).id;
    const relationPromise = Promise.resolve({
      id,
      type: 'stix_relation',
      relationship_type: relationTypeValue,
      inferred: true
    });
    const fromPromise = getById(fromId);
    const toPromise = getById(toId);
    const explanation = await answer.explanation();
    const explanationAnswers = await explanation.answers();
    const inferences = explanationAnswers.map(explanationAnswer => {
      const explanationAnswerExplanation = explanationAnswer.explanation();
      let inferenceQuery = explanationAnswerExplanation.queryPattern();
      console.log(inferenceQuery);
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
    console.log(inferencesQueries);
    const inferencesQuery = `match {${join('; ', inferencesQueries)}; }; get;`;
    const inferencesAnswerIterator = await rTx.query(inferencesQuery);
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
          from: await getById(inferenceFromId),
          to: await getById(inferenceToId)
        }
      });
    });

    const resultPromise = Promise.all([
      relationPromise,
      fromPromise,
      toPromise,
      inferencesPromises
    ]).then(([node, from, to, relationInferences]) => {
      return pipe(
        assoc('from', to),
        assoc('to', from),
        assoc('inferences', { edges: relationInferences })
      )(node);
    });
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve({});
  }
};

/**
 * Get a single value from a Grakn query
 * @param query
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getSingleValue = async (query, infer = false) => {
  logger.debug(`[GRAKN - infer: ${infer}] ${query}`);
  const rTx = await (infer ? takeWriteTx() : takeReadTx());
  try {
    const iterator = await rTx.query(query, { infer });
    const answer = await iterator.next();
    const result = await Promise.resolve(answer);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve({});
  }
};

/**
 * Get a single value number
 * @param query
 * @param infer
 * @returns number
 */
export const getSingleValueNumber = async (query, infer = false) => {
  try {
    return getSingleValue(query, infer).then(data => data.number());
  } catch (error) {
    return Promise.resolve(null);
  }
};

/**
 * Grakn query that generate json objects
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getObjects = async (
  query,
  key = 'x',
  relationKey,
  infer = false
) => {
  const rTx = await (infer ? takeWriteTx() : takeReadTx());
  try {
    logger.debug(`[GRAKN - infer: ${infer}] ${query}`);
    const iterator = await rTx.query(query, { infer });
    const answers = await iterator.collect();
    const resultPromise = Promise.all(
      answers.map(async answer => {
        const nodePromise = await getById(answer.map().get(key).id);
        let relationPromise = await Promise.resolve(null);
        if (relationKey) {
          if (
            answer
              .map()
              .get(relationKey)
              .isInferred()
          ) {
            const relationType = await answer
              .map()
              .get(relationKey)
              .type();
            relationPromise = await Promise.resolve({
              id: answer.map().get(relationKey).id,
              type: 'stix_relation',
              relationship_type: relationType.label(),
              inferred: true
            });
          } else {
            const relationData = await getById(
              answer.map().get(relationKey).id
            ).then(data => assoc('inferred', false, data));
            relationPromise = await Promise.resolve(relationData);
          }
        }
        return Promise.all([nodePromise, relationPromise]).then(
          ([node, relation]) => ({
            node,
            relation
          })
        );
      })
    );
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve([]);
  }
};

/**
 * Grakn query that generate json objects for GraphQL
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getObjectsWithoutAttributes = async (
  query,
  key = 'x',
  relationKey,
  infer = false
) => {
  const rTx = await (infer ? takeWriteTx() : takeReadTx());
  try {
    logger.debug(`[GRAKN - infer: ${infer}] ${query}`);
    const iterator = await rTx.query(query, { infer });
    const answers = await iterator.collect();
    const resultPromise = Promise.all(
      answers.map(async answer => {
        const nodePromise = await Promise.resolve({
          id: answer.map().get(key).id
        });
        let relationPromise = await Promise.resolve(null);
        if (relationKey) {
          const relationType = await answer
            .map()
            .get(relationKey)
            .type();
          relationPromise = await Promise.resolve({
            id: answer.map().get(relationKey).id,
            type: 'stix_relation',
            relationship_type: relationType.label(),
            inferred: await answer
              .map()
              .get(relationKey)
              .isInferred()
          });
        }
        return Promise.all([nodePromise, relationPromise]).then(
          ([node, relation]) => ({
            node,
            relation
          })
        );
      })
    );
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve([]);
  }
};

/**
 * Grakn query that generate a json object for GraphQL
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getObject = (query, key = 'x', relationKey, infer = false) =>
  getObjects(query, key, relationKey, infer).then(result => head(result));

/**
 * Pure building of pagination expected format.
 * @param first
 * @param offset
 * @param instances
 * @param globalCount
 * @returns {{edges: *, pageInfo: *}}
 */
export const buildPagination = (first, offset, instances, globalCount) => {
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
 * @returns {Promise<any[] | never>}
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
  const count = getSingleValueNumber(`${query}; aggregate count;`, infer);
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
 * Grakn query that generate json objects for relations
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param fromKey the key to bind relation result.
 * @param toKey the key to bind relation result.
 * @param extraRelKey the key of the relation pointing the relation
 * @param infer (get inferred relationships)
 * @returns {Promise<any[] | never>}
 */
export const getRelations = async (
  query,
  key = 'rel',
  fromKey = 'from',
  toKey = 'to',
  extraRelKey,
  infer = false
) => {
  const rTx = await (infer ? takeWriteTx() : takeReadTx());
  try {
    logger.debug(`[GRAKN - infer: ${infer}] ${query}`);
    const iterator = await rTx.query(query, { infer });
    const answers = await iterator.collect();
    const resultPromise = Promise.all(
      answers.map(async answer => {
        const relationObject = await answer.map().get(key);
        const relationType = await relationObject.type();
        const relationIsInferred = await relationObject.isInferred();
        let relationPromise = await Promise.resolve(null);
        if (relationIsInferred) {
          const explanation = await answer.explanation();
          let queryPattern = await explanation.queryPattern();
          queryPattern = queryPattern.replace(
            `$from id ${answer.map().get(fromKey).id};`,
            `$from id ${answer.map().get(fromKey).id}; $to id ${
              answer.map().get(toKey).id
            };`
          );
          relationPromise = await Promise.resolve({
            id: Buffer.from(queryPattern).toString('base64'),
            type: 'stix_relation',
            relationship_type: await relationType.label(),
            inferred: true
          });
        } else {
          const relationData = await getById(answer.map().get(key).id).then(
            data => assoc('inferred', false, data)
          );
          relationPromise = await Promise.resolve(relationData);
        }
        const fromPromise = getById(answer.map().get(fromKey).id);
        const toPromise = getById(answer.map().get(toKey).id);
        const extraRelationPromise = !extraRelKey
          ? Promise.resolve(null)
          : getById(answer.map().get(extraRelKey).id);

        return Promise.all([
          relationPromise,
          fromPromise,
          toPromise,
          extraRelationPromise
        ]).then(([node, from, to, relation]) => {
          return {
            node: pipe(
              assoc('from', from),
              assoc('to', to)
            )(node),
            relation
          };
        });
      })
    );
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve([]);
  }
};

/**
 * Grakn generic pagination query
 * @param query
 * @param options
 * @param extraRel
 * @param pagination
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
      : ''
  } ${
    orderBy
      ? `${
          orderBy === 'first_seen' && firstSeenStart
            ? `order by $fs ${orderMode}`
            : `$rel has ${orderBy} $o; order by $o ${orderMode}`
        };`
      : ''
  }`;
  const count = getSingleValueNumber(`${finalQuery} aggregate count;`);
  const elements = getRelations(
    `${finalQuery} offset ${offset}; limit ${first}; get $rel, $from, $to ${
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
      return buildPagination(first, offset, instances, globalCount);
    });
  }
  return Promise.all([count, elements]).then(data => {
    const globalCount = data ? head(data) : 0;
    const instances = data ? last(data) : [];
    return { globalCount, instances };
  });
};

/**
 * Create a relation between to element in the model without restriction.
 * @param id
 * @param input
 * @returns {Promise<any[] | never>}
 */
export const createRelation = async (id, input) => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $from id ${id}; $to id ${input.toId}; insert $rel(${
      input.fromRole
    }: $from, ${input.toRole}: $to) isa ${input.through};`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    const iterator = await wTx.query(query);
    const answer = await iterator.next();
    const createdRelationId = await answer.map().get('rel').id;
    await wTx.commit();
    const nodePromise = await getById(input.toId);
    const relationPromise = await getById(createdRelationId);
    return Promise.all([nodePromise, relationPromise]).then(
      ([node, relation]) => ({
        node,
        relation
      })
    );
  } catch (error) {
    if (wTx) {
      wTx.close();
    }
    throw new Unknown();
  }
};

/**
 * Edit an attribute value.
 * @param id
 * @param input
 * @returns the complete instance
 */
export const updateAttribute = async (id, input) => {
  const { key, value } = input; // value can be multi valued
  // 00. If the transaction already exist, just continue the process
  const wTx = await takeWriteTx();

  try {
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
    let typedValues = map(
      v => (attrType === String ? `"${prepareString(v)}"` : v),
      value
    );
    if (typedValues.length === 0) {
      typedValues = [attrType === String ? '""' : ''];
    }
    const graknValues = join(' ', map(val => `has ${key} ${val}`, typedValues));
    const createQuery = `match $m id ${id}; insert $m ${graknValues};`;
    await wTx.query(createQuery);
    await wTx.commit();

    if (includes(key, statsDateAttributes)) {
      const dayValue = dayFormat(head(value));
      const monthValue = monthFormat(head(value));
      const yearValue = yearFormat(head(value));
      const dayInput = { key: `${key}_day`, value: [dayValue] };
      await updateAttribute(id, dayInput);
      const monthInput = { key: `${key}_month`, value: [monthValue] };
      await updateAttribute(id, monthInput);
      const yearInput = { key: `${key}_year`, value: [yearValue] };
      return updateAttribute(id, yearInput);
    }
    return getById(id);
  } catch (error) {
    if (wTx) {
      wTx.close();
    }
    throw new Unknown();
  }
};

/**
 * Grakn generic function to delete an instance (and orphan relationships)
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteEntityById = async id => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $x id ${id}; $z($x, $y); delete $z, $x;`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    await wTx.query(query);
    await wTx.commit();
    return Promise.resolve(id);
  } catch (error) {
    if (wTx) {
      wTx.close();
    }
    throw new Unknown();
  }
};

/**
 * Grakn generic function to delete an entity by id
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteById = async id => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $x id ${id}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    await wTx.query(query);
    await wTx.commit();
    return Promise.resolve(id);
  } catch (error) {
    if (wTx) {
      wTx.close();
    }
    throw new Unknown();
  }
};

/**
 * Grakn generic function to delete a relationship
 * @param id
 * @param relationId
 * @returns {Promise<AxiosResponse<any> | never | never>}
 */
export const deleteRelationById = async (id, relationId) => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $x id ${relationId}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] ${query}`);
    await wTx.query(query);
    await wTx.commit();
    return getById(id).then(data => ({
      node: data,
      relation: { id: relationId }
    }));
  } catch (error) {
    if (wTx) {
      wTx.close();
    }
    throw new Unknown();
  }
};

/**
 * Grakn generic timeseries
 * @param query
 * @param options
 * @returns Promise
 */
export const timeSeries = async (query, options) => {
  const {
    startDate,
    endDate,
    operation,
    field,
    interval,
    inferred = true
  } = options;
  const rTx = await (inferred ? takeWriteTx() : takeReadTx());
  try {
    const finalQuery = `${query}; $x has ${field}_${interval} $g; aggregate group $g ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] ${finalQuery}`);
    const iterator = await rTx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    const resultPromise = Promise.all(
      answer.map(async n => {
        const date = await n.owner().value();
        const number = await n.answers()[0].number();
        return { date, value: number };
      })
    ).then(result => fillTimeSeries(startDate, endDate, interval, result));
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve([]);
  }
};

/**
 * Grakn generic distribution
 * @param query
 * @param options
 * @returns Promise
 */
export const distribution = async (query, options) => {
  const { operation, field, inferred = false } = options;
  const rTx = await (inferred ? takeWriteTx() : takeReadTx());
  try {
    const finalQuery = `${query}; $x has ${field} $g; aggregate group $g ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] ${finalQuery}`);
    const iterator = await rTx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    const resultPromise = Promise.all(
      answer.map(async n => {
        const label = await n.owner().value();
        const number = await n.answers()[0].number();
        return { label, value: number };
      })
    );
    const result = await Promise.resolve(resultPromise);
    await rTx.close();
    return result;
  } catch (error) {
    if (rTx) {
      rTx.close();
    }
    return Promise.resolve([]);
  }
};
