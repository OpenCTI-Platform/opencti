import uuid from 'uuid/v4';
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
  tail
} from 'ramda';
import moment from 'moment';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn-client';
import conf, { logger } from '../config/conf';
import { pubsub } from './redis';
import { fillTimeSeries, randomKey, buildPagination } from './utils';
import { isInversed } from './graknRoles';
import { getAttributes as elGetAttributes, index } from './elasticSearch';

// Global variables
const indexableTypes = [
  'Stix-Observable',
  'Stix-Domain-Entity',
  'External-Reference',
  'Stix-Observable',
  'stix_relation'
];
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
export const escape = s =>
  s && typeof s === 'string'
    ? s
        .replace(/\\/g, '\\\\')
        .replace(/;/g, '\\;')
        .replace(/,/g, '\\,')
    : s;
export const escapeString = s =>
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
  'published', // Standard
  'expiration' // Standard
];

const client = new Grakn(
  `${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`
);
let session = null;

export const takeReadTx = async (retry = false) => {
  if (session === null) {
    session = await client.session('grakn');
  }
  try {
    const tx = await session.transaction().read();
    return { session, tx };
  } catch (err) {
    logger.error('[GRAKN] TakeReadTx error > ', err);
    if (retry === false) {
      session = null;
      return takeReadTx(true);
    }
    return null;
  }
};

export const closeReadTx = async rTx => {
  try {
    await rTx.tx.close();
  } catch (err) {
    logger.error('[GRAKN] CloseReadTx error > ', err);
  }
};

export const graknIsAlive = async () => {
  try {
    const rtx = await takeReadTx();
    await closeReadTx(rtx);
  } catch (e) {
    logger.error(`[GRAKN] Seems down`);
    throw new Error('Grakn seems down');
  }
};

export const takeWriteTx = async (retry = false) => {
  if (session === null) {
    session = await client.session('grakn');
  }
  try {
    const tx = await session.transaction().write();
    return { session, tx };
  } catch (err) {
    logger.error('[GRAKN] TakeWriteTx error > ', err);
    if (retry === false) {
      session = null;
      return takeWriteTx(true);
    }
    return null;
  }
};

export const commitWriteTx = async wTx => {
  try {
    await wTx.tx.commit();
  } catch (err) {
    logger.error('[GRAKN] CommitWriteTx error > ', err);
  }
};

export const closeWriteTx = async wTx => {
  try {
    await wTx.tx.close();
  } catch (err) {
    logger.error('[GRAKN] CloseWriteTx error > ', err);
  }
};

export const notify = (topic, instance, user, context) => {
  if (pubsub) pubsub.publish(topic, { instance, user, context });
  return instance;
};

export const read = async query => {
  const rTx = await takeReadTx();
  try {
    await rTx.tx.query(query);
  } catch (err) {
    logger.error('[GRAKN] Read error > ', err);
  }
  await closeReadTx(rTx);
};

export const write = async query => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query(query);
    await commitWriteTx(wTx);
  } catch (err) {
    logger.error('[GRAKN] Write error > ', err);
  }
};

/**
 * Get the Grakn ID from internal id
 * @param internalId
 * @returns {Promise<any[] | never>}
 */
export const getId = async internalId => {
  const rTx = await takeReadTx();
  try {
    const query = `match $x has internal_id "${escapeString(
      internalId
    )}"; get $x;`;
    logger.debug(`[GRAKN - infer: false] getGraknId > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answer = await iterator.next();
    const concept = answer.map().get('x');
    await closeReadTx(rTx);
    return concept.id;
  } catch (err) {
    logger.error('[GRAKN] getId error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};

/**
 * Query and get attribute values
 * @param type
 * @returns {{edges: *}}
 */
export const queryAttributeValues = async type => {
  const rTx = await takeReadTx();
  try {
    const query = `match $x isa ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValues > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async answer => {
        const attribute = answer.map().get('x');
        const attributeType = await attribute.type();
        const value = await attribute.value();
        const attributeTypeLabel = await attributeType.label();
        const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        return {
          node: {
            id: attribute.id,
            type: attributeTypeLabel,
            value: replacedValue
          }
        };
      })
    );
    await closeReadTx(rTx);
    return buildPagination(5000, 0, result, 5000);
  } catch (err) {
    logger.error('[GRAKN] queryAttributeValues error > ', err);
    await closeReadTx('[GRAKN] getAttributeValues error > ', rTx);
    return {};
  }
};

/**
 * Query and get attribute values
 * @param id
 * @returns {{edges: *}}
 */
export const queryAttributeValueById = async id => {
  const rTx = await takeReadTx();
  try {
    const query = `match $x id ${escape(id)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValueById > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answer = await iterator.next();
    const attribute = answer.map().get('x');
    const attributeType = await attribute.type();
    const value = await attribute.value();
    const attributeTypeLabel = await attributeType.label();
    const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    await closeReadTx(rTx);
    return {
      id: attribute.id,
      type: attributeTypeLabel,
      value: replacedValue
    };
  } catch (err) {
    logger.error('[GRAKN] queryAttributeValueById error > ', err);
    await closeReadTx(rTx);
    return { edges: [] };
  }
};

/**
 * Grakn generic function to delete an instance (and orphan relationships)
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteAttributeById = async id => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $x id ${escape(id)}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteAttributeById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    await commitWriteTx(wTx);
    return id;
  } catch (err) {
    logger.error('[GRAKN] deleteAttributeById error > ', err);
    await closeWriteTx(wTx);
    return null;
  }
};

/**
 * Recursive fetch of every types of a concept
 * @param concept the element
 * @param currentType the current type
 * @param acc the recursive accumulator
 * @returns {Promise<Array>}
 */
export const conceptTypes = async (concept, currentType = null, acc = []) => {
  if (currentType === null) {
    const conceptType = await concept.type();
    const conceptLabel = await conceptType.label();
    acc.push(conceptLabel);
    return conceptTypes(concept, conceptType, acc);
  }
  const parentType = await currentType.sup();
  if (parentType === null) return acc;
  const conceptLabel = await parentType.label();
  acc.push(conceptLabel);
  if (conceptLabel === 'entity' || includes(conceptLabel, indexableTypes))
    return acc;
  return conceptTypes(concept, parentType, acc);
};

/**
 * Compute the index related to concept types
 * @param types
 * @returns {Promise<string|null>}
 */
const inferIndexFromConceptTypes = async types => {
  if (includes('Stix-Observable', types)) return 'stix_observables';
  if (includes('Stix-Domain-Entity', types)) return 'stix_domain_entities';
  if (includes('External-Reference', types)) return 'external_references';
  if (includes('Stix-Observable', types)) return 'stix_observables';
  if (includes('stix_relation', types)) return 'stix_relations';
  return undefined;
};

/**
 * Load any grakn instance with internal grakn ID.
 * @param concept the concept to get attributes from
 * @param forceReindex if index need to be updated
 * @returns {Promise}
 */
export const getAttributes = async (concept, forceReindex = false) => {
  const { id } = concept;
  const types = await conceptTypes(concept);
  const getIndex = await inferIndexFromConceptTypes(types);
  const parentTypeLabel = last(types);
  let shouldBeReindex = forceReindex && getIndex !== undefined;
  // 01. If data need to be requested from the index cache system
  if (getIndex && !shouldBeReindex) {
    try {
      logger.debug(
        `[ELASTICSEARCH] getAttributes get > ${head(
          types
        )} ${id} on ${getIndex}`
      );
      const elAttributes = await elGetAttributes(getIndex, id);
      return pipe(
        mapObjIndexed((value, key) =>
          Array.isArray(value) && !includes(key, multipleAttributes)
            ? head(value)
            : value
        ),
        assoc('id', elAttributes.internal_id),
        assoc('parent_type', parentTypeLabel)
      )(elAttributes);
    } catch (e) {
      // Just after creation, the data is not yet indexed.
      logger.debug(
        `[ELASTICSEARCH] getAttributes missing > ${head(
          types
        )} ${id} on ${getIndex}`
      );
      shouldBeReindex = true;
    }
  }
  // 02. If nothing found in elastic, do the request in grakn
  logger.debug(`[GRAKN - infer: false] getAttributes > ${head(types)} ${id}`);
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
  return Promise.all(attributesPromises)
    .then(attributesData => {
      const transform = pipe(
        map(attribute => {
          let transformedVal = attribute.value;
          const type = attribute['data-type'];
          if (type === Date) {
            transformedVal = `${moment(attribute.value).format(dateFormat)}Z`;
          }
          if (type === String) {
            transformedVal = attribute.value
              .replace(/\\"/g, '"')
              .replace(/\\\\/g, '\\');
          }
          return { [attribute.type]: transformedVal };
        }), // Extract values
        chain(toPairs), // Convert to pairs for grouping
        groupBy(head), // Group by key
        map(pluck(1)), // Remove grouping boilerplate
        mapObjIndexed((num, key, obj) =>
          // eslint-disable-next-line no-nested-ternary
          Array.isArray(obj[key]) && !includes(key, multipleAttributes)
            ? head(obj[key])
            : head(obj[key]) && head(obj[key]).length > 0
            ? obj[key]
            : []
        ) // Remove extra list then contains only 1 element
      )(attributesData);
      return pipe(
        assoc('id', transform.internal_id),
        assoc('grakn_id', concept.id),
        assoc('parent_type', parentTypeLabel)
      )(transform);
    })
    .then(data => {
      // If data was fetched from db but should be indexed
      if (shouldBeReindex) return index(getIndex, data);
      return data;
    });
};

/**
 * Load any grakn instance with internal ID.
 * @param id element id to get
 * @param forceReindex if index need to be updated
 * @returns {Promise<any[] | never>}
 */
export const getById = async (id, forceReindex = false) => {
  const rTx = await takeReadTx();
  try {
    const query = `match $x has internal_id "${escapeString(id)}"; get $x;`;
    const iterator = await rTx.tx.query(query);
    const answer = await iterator.next();
    const concept = answer.map().get('x');
    const result = await getAttributes(concept, forceReindex);
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] getById error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};

/**
 * Query and get entities
 * @param query
 * @param entities
 * @returns {Promise<any[] | never>}
 */
export const find = async (query, entities) => {
  const rTx = await takeReadTx();
  try {
    logger.debug(`[GRAKN - infer: false] Find > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async answer => {
        const entitiesPromises = await entities.map(async entity => {
          return [entity, await getAttributes(answer.map().get(entity))];
        });
        return Promise.all(entitiesPromises).then(data => {
          return fromPairs(data);
        });
      })
    );
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] find error > ', err);
    await closeReadTx(rTx);
    return [];
  }
};

/**
 * Query and get entities of the first row
 * @param query
 * @param entities
 * @returns {Promise<any[] | never>}
 */
export const load = async (query, entities) => {
  const data = await find(query, entities);
  return head(data);
};

/**
 * Load any grakn relation with internal grakn ID.
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const getRelationById = async id => {
  const rTx = await takeReadTx();
  try {
    const query = `match $x($from, $to) isa relation; $x has internal_id "${escapeString(
      id
    )}"; get;`;
    logger.debug(`[GRAKN - infer: false] getRelationById > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answer = await iterator.next();
    const relationObject = answer.map().get('x');
    const relationPromise = await getAttributes(relationObject).then(result =>
      assoc('inferred', false, result)
    );
    const rolePlayersMap = await relationObject.rolePlayersMap();
    const roles = rolePlayersMap.keys();
    const fromRole = roles.next().value;
    const fromObject = rolePlayersMap
      .get(fromRole)
      .values()
      .next().value;
    const fromRoleLabel = await fromRole.label();
    const toRole = roles.next().value;
    const toObject = rolePlayersMap
      .get(toRole)
      .values()
      .next().value;
    const toRoleLabel = await toRole.label();
    const fromPromise = await getAttributes(fromObject);
    const toPromise = await getAttributes(toObject);
    const resultPromise = Promise.all([
      relationPromise,
      fromPromise,
      toPromise
    ]).then(([relation, from, to]) => {
      if (isInversed(relation.relationship_type, fromRoleLabel)) {
        return pipe(
          assoc('from', to),
          assoc('fromRole', toRoleLabel),
          assoc('to', from),
          assoc('toRole', fromRoleLabel)
        )(relation);
      }
      return pipe(
        assoc('from', from),
        assoc('fromRole', fromRoleLabel),
        assoc('to', to),
        assoc('toRole', toRoleLabel)
      )(relation);
    });
    const result = await Promise.resolve(resultPromise);
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] getRelationById error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};

/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @returns {Promise}
 */
export const getRelationInferredById = async id => {
  const rTx = await takeReadTx();
  try {
    const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
    const query = `match ${decodedQuery} get;`;
    const queryRegex = /\$([a-z_\d]+)\s?[([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\s[a-z_]+\s([\w-]+);/i.exec(
      query
    );
    if (queryRegex === null) return {};
    const relKey = queryRegex[1];
    logger.debug(`[GRAKN - infer: true] getRelationInferredById > ${query}`);
    const answerIterator = await rTx.tx.query(query);
    const answer = await answerIterator.next();
    const rel = answer.map().get(relKey);
    const relationType = await rel.type();
    const relationTypeValue = await relationType.label();
    const rolePlayersMap = await rel.rolePlayersMap();
    const roles = rolePlayersMap.keys();
    const fromRole = roles.next().value;
    // eslint-disable-next-line prettier/prettier
    const fromObject = rolePlayersMap
      .get(fromRole)
      .values()
      .next().value;
    const fromRoleLabel = await fromRole.label();
    const toRole = roles.next().value;
    // eslint-disable-next-line prettier/prettier
    const toObject = rolePlayersMap
      .get(toRole)
      .values()
      .next().value;
    const toRoleLabel = await toRole.label();
    const relation = {
      id,
      entity_type: 'stix_relation',
      relationship_type: relationTypeValue,
      inferred: true
    };
    const fromPromise = getAttributes(fromObject);
    const toPromise = getAttributes(toObject);
    const explanation = answer.explanation();
    const explanationAnswers = explanation.answers();
    const inferences = explanationAnswers.map(explanationAnswer => {
      const explanationAnswerExplanation = explanationAnswer.explanation();
      let inferenceQuery = explanationAnswerExplanation.queryPattern();
      const inferenceQueryRegex = /(\$(\d+|rel)\s)?\([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\sisa\s([\w-]+);/i.exec(
        inferenceQuery
      );
      let relationKey;
      const [, , inferReferenceRelationKey] = inferenceQueryRegex;
      if (inferReferenceRelationKey !== undefined) {
        relationKey = inferReferenceRelationKey;
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
    const inferencesQuery = `match {${join(' ', inferencesQueries)} }; get;`;
    logger.debug(
      `[GRAKN - infer: true] getRelationInferredById - getInferences > ${inferencesQuery}`
    );
    const inferencesAnswerIterator = await rTx.tx.query(inferencesQuery);
    const inferencesAnswer = await inferencesAnswerIterator.next();
    const inferencesPromises = Promise.all(
      inferences.map(async inference => {
        const inferred = await inferencesAnswer
          .map()
          .get(inference.relationKey)
          .isInferred();
        const inferenceFrom = inferencesAnswer.map().get(inference.fromKey);
        const inferenceTo = inferencesAnswer.map().get(inference.toKey);
        let inferenceId;
        if (inferred) {
          const inferenceQueryRegex = /\$([a-z_\d]+)\s\([a-z_:]+\s\$([a-z_]+),\s[a-z_:]+\s\$([a-z_]+)\)/i.exec(
            inference.inferenceQuery
          );
          const entityFromKey = inferenceQueryRegex[2];
          const entityToKey = inferenceQueryRegex[3];
          const regexFromString = `\\$${entityFromKey}\\sid\\s(V\\d+);`;
          const regexFrom = new RegExp(regexFromString, 'i');
          const inferenceQueryRegexFrom = inference.inferenceQuery.match(
            regexFrom
          );
          const regexToString = `\\$${entityToKey}\\sid\\s(V\\d+);`;
          const regexTo = new RegExp(regexToString, 'i');
          const inferenceQueryRegexTo = inference.inferenceQuery.match(regexTo);

          const regexFromTypeString = `\\$${entityFromKey}\\sisa\\s[\\w-_]+;`;
          const regexFromType = new RegExp(regexFromTypeString, 'ig');
          const regexToTypeString = `\\$${entityToKey}\\sisa\\s[\\w-_]+;`;
          const regexToType = new RegExp(regexToTypeString, 'ig');

          let extractedInferenceQuery;
          if (inferenceQueryRegexFrom && inferenceQueryRegexTo) {
            extractedInferenceQuery = inference.inferenceQuery;
          } else if (inferenceQueryRegexFrom) {
            const existingId = inferenceQueryRegexFrom[1];
            extractedInferenceQuery = inference.inferenceQuery.replace(
              `$${entityFromKey} id ${existingId};`,
              `$${entityFromKey} id ${existingId}; $${entityToKey} id ${
                existingId === inferenceFrom.id
                  ? inferenceTo.id
                  : inferenceFrom.id
              };`
            );
          } else if (inferenceQueryRegexTo) {
            const existingId = inferenceQueryRegexTo[1];
            extractedInferenceQuery = inference.inferenceQuery.replace(
              `$${entityToKey} id ${existingId};`,
              `$${entityToKey} id ${existingId}; $${entityFromKey} id ${
                existingId === inferenceFrom.id
                  ? inferenceTo.id
                  : inferenceFrom.id
              };`
            );
          } else {
            extractedInferenceQuery = inference.inferenceQuery;
          }
          const finalInferenceQuery = extractedInferenceQuery
            .replace(regexFromType, '')
            .replace(regexToType, '');
          inferenceId = Buffer.from(finalInferenceQuery).toString('base64');
        } else {
          const inferenceAttributes = await getAttributes(
            inferencesAnswer.map().get(inference.relationKey)
          );
          inferenceId = inferenceAttributes.internal_id;
        }
        const fromAttributes = await getAttributes(inferenceFrom);
        const toAttributes = await getAttributes(inferenceTo);
        return {
          node: {
            id: inferenceId,
            inferred,
            relationship_type: inference.relationType,
            from: fromAttributes,
            to: toAttributes
          }
        };
      })
    );
    const result = await Promise.all([
      fromPromise,
      toPromise,
      inferencesPromises
    ]).then(([fromResult, toResult, relationInferences]) => {
      if (isInversed(relation.relationship_type, fromRoleLabel)) {
        return pipe(
          assoc('from', toResult),
          assoc('fromRole', toRoleLabel),
          assoc('to', fromResult),
          assoc('toRole', fromRoleLabel),
          assoc('inferences', { edges: relationInferences })
        )(relation);
      }
      return pipe(
        assoc('from', fromResult),
        assoc('fromRole', fromRoleLabel),
        assoc('to', toResult),
        assoc('toRole', toRoleLabel),
        assoc('inferences', { edges: relationInferences })
      )(relation);
    });
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] getRelationInferredById error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};

/**
 * Get a single value from a Grakn query
 * @param query
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getSingleValue = async (query, infer = false) => {
  const rTx = await takeReadTx();
  try {
    logger.debug(`[GRAKN - infer: ${infer}] getSingleValue > ${query}`);
    const iterator = await rTx.tx.query(query, { infer });
    const answer = await iterator.next();
    const result = await Promise.resolve(answer);
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] getSingleValue error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};

/**
 * Get a single value number
 * @param query
 * @param infer
 * @returns number
 */
export const getSingleValueNumber = async (query, infer = false) => {
  return getSingleValue(query, infer).then(data => data.number());
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
  relationKey = null,
  infer = false
) => {
  const rTx = await takeReadTx();
  try {
    const iterator = await rTx.tx.query(query, { infer });
    const answers = await iterator.collect();
    logger.debug(
      `[GRAKN - infer: ${infer}] ${answers.length} GetObjects > ${query}`
    );
    const result = await Promise.all(
      answers.map(async answer => {
        let relation = null;
        const node = await getAttributes(answer.map().get(key));
        if (relationKey) {
          const inferred = await answer
            .map()
            .get(relationKey)
            .isInferred();
          if (inferred) {
            const relationType = await answer
              .map()
              .get(relationKey)
              .type();
            relation = {
              id: uuid(),
              entity_type: 'stix_relation',
              relationship_type: relationType.label(),
              inferred: true
            };
          } else {
            relation = await getAttributes(answer.map().get(relationKey)).then(
              data => assoc('inferred', false, data)
            );
          }
        }
        return { node, relation };
      })
    );
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] getObjects error > ', err);
    await closeReadTx(rTx);
    return [];
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
 * Grakn generic pagination query.
 * @param query
 * @param options
 * @param ordered
 * @param relationOrderingKey
 * @param infer
 * @param computeCount
 * @returns {Promise<any[] | never>}
 */
export const paginate = (
  query,
  options,
  ordered = true,
  relationOrderingKey = null,
  infer = false,
  computeCount = true
) => {
  try {
    const { first = 200, after, orderBy = null, orderMode = 'asc' } = options;
    const offset = after ? cursorToOffset(after) : 0;
    const instanceKey = /match\s(?:\$|{\s\$)(\w+)[\s]/i.exec(query)[1]; // We need to resolve the key instance used in query.
    const findRelationVariable = /\$(\w+)\((\w+):\$(\w+),[\s\w:$]+\)/i.exec(
      query
    );
    const relationKey = findRelationVariable && findRelationVariable[1]; // Could be setup to get relation info
    const orderingKey = relationOrderingKey
      ? `$${relationOrderingKey} has ${orderBy} $o;`
      : `$${instanceKey} has ${orderBy} $o;`;

    let count = first;
    if (computeCount === true) {
      count = getSingleValueNumber(
        `${query}; ${
          ordered && orderBy ? orderingKey : ''
        } get $${instanceKey}${relationKey ? `, $${relationKey}` : ''}${
          ordered && orderBy ? ', $o' : ''
        }; count;`,
        infer
      );
    }
    const elements = getObjects(
      `${query}; ${ordered && orderBy ? orderingKey : ''} get $${instanceKey}${
        relationKey ? `, $${relationKey}` : ''
      }${ordered && orderBy ? ', $o' : ''}; ${
        ordered && orderBy ? `sort $o ${orderMode};` : ''
      } offset ${offset}; limit ${first};`,
      instanceKey,
      relationKey,
      infer
    );
    return Promise.all([count, elements]).then(data => {
      const globalCount = data ? head(data) : 0;
      const instances = data ? last(data) : [];
      return buildPagination(first, offset, instances, globalCount);
    });
  } catch (err) {
    logger.error('[GRAKN] paginate error > ', err);
    return Promise.resolve(null);
  }
};

/**
 * Grakn query that generate json objects for relations
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param fromKey the key to bind relation result.
 * @param toKey the key to bind relation result.
 * @param extraRelKey the key of the relation pointing the relation
 * @param infer (get inferred relationships)
 * @param enforceDirection enforce relation direction
 * @returns {Promise<any[] | never>}
 */
export const getRelations = async (
  query,
  key = 'rel',
  fromKey = 'from',
  toKey = 'to',
  extraRelKey,
  infer = false,
  enforceDirection = true
) => {
  const rTx = await takeReadTx();
  try {
    logger.debug(`[GRAKN - infer: ${infer}] getRelations > ${query}`);
    const iterator = await rTx.tx.query(query, { infer });
    const answers = await iterator.collect();
    const resultPromise = Promise.all(
      answers.map(async answer => {
        const relationObject = answer.map().get(key);
        const relationType = await relationObject.type();
        const relationTypeLabel = await relationType.label();
        const rolePlayersMap = await relationObject.rolePlayersMap();
        const roles = rolePlayersMap.keys();
        const fromRole = roles.next().value;
        const fromObject = rolePlayersMap
          .get(fromRole)
          .values()
          .next().value;
        const fromRoleLabel = await fromRole.label();
        const toRole = roles.next().value;
        const toObject = rolePlayersMap
          .get(toRole)
          .values()
          .next().value;
        const toRoleLabel = await toRole.label();
        const relationIsInferred = await relationObject.isInferred();
        let relationPromise = null;
        if (relationIsInferred) {
          const queryPattern = `{ $rel(${fromRoleLabel}: $from, ${toRoleLabel}: $to) isa ${relationTypeLabel}; $from id ${fromObject.id}; $to id ${toObject.id}; };`;
          relationPromise = Promise.resolve({
            id: Buffer.from(queryPattern).toString('base64'),
            entity_type: 'stix_relation',
            relationship_type: relationTypeLabel,
            inferred: true
          });
        } else {
          relationPromise = Promise.resolve(
            getAttributes(answer.map().get(key)).then(data =>
              assoc('inferred', false, data)
            )
          );
        }
        const fromPromise = getAttributes(
          enforceDirection ? fromObject : answer.map().get(fromKey)
        );
        const toPromise = getAttributes(
          enforceDirection ? toObject : answer.map().get(toKey)
        );
        const extraRelationPromise = !extraRelKey
          ? Promise.resolve(null)
          : getAttributes(answer.map().get(extraRelKey));

        return Promise.all([
          relationPromise,
          fromPromise,
          toPromise,
          extraRelationPromise
        ]).then(([node, from, to, relation]) => {
          if (
            enforceDirection &&
            isInversed(node.relationship_type, fromRoleLabel)
          ) {
            return {
              node: pipe(
                assoc('from', to),
                assoc('fromRole', toRoleLabel),
                assoc('to', from),
                assoc('toRole', fromRoleLabel)
              )(node),
              relation
            };
          }
          return {
            node: pipe(
              assoc('from', from),
              assoc('fromRole', fromRoleLabel),
              assoc('to', to),
              assoc('toRole', toRoleLabel)
            )(node),
            relation
          };
        });
      })
    );
    const result = await Promise.resolve(resultPromise);
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] getRelations error > ', err);
    await closeReadTx(rTx);
    return Promise.resolve(null);
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
  try {
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
    const finalQuery = `
  ${query};
  ${fromId ? `$from has internal_id "${escapeString(fromId)}";` : ''}
  ${toId ? `$to has internal_id "${escapeString(toId)}";` : ''} ${
      fromTypes && fromTypes.length > 0
        ? `${join(
            ' ',
            map(fromType => `{ $from isa ${fromType}; } or`, fromTypes)
          )} { $from isa ${head(fromTypes)}; };`
        : ''
    } ${
      toTypes && toTypes.length > 0
        ? `${join(' ', map(toType => `{ $to isa ${toType}; } or`, toTypes))}
  { $to isa ${head(toTypes)}; };`
        : ''
    } ${firstSeenStart || firstSeenStop ? `$rel has first_seen $fs; ` : ''} ${
      firstSeenStart ? `$fs > ${prepareDate(firstSeenStart)}; ` : ''
    } ${firstSeenStop ? `$fs < ${prepareDate(firstSeenStop)}; ` : ''} ${
      lastSeenStart || lastSeenStop ? `$rel has last_seen $ls; ` : ''
    } ${lastSeenStart ? `$ls > ${prepareDate(lastSeenStart)}; ` : ''} ${
      lastSeenStop ? `$ls < ${prepareDate(lastSeenStop)}; ` : ''
    } ${
      weights
        ? `$rel has weight $weight; ${join(
            ' ',
            map(weight => `{ $weight == ${weight}; } or`, weights)
          )} { $weight == 0; };`
        : ''
    }`;
    const orderingKey = orderBy ? `$rel has ${orderBy} $o;` : '';
    const count = getSingleValueNumber(
      `${finalQuery} ${orderingKey} get $rel, $from, $to ${
        extraRel ? `, $${extraRel}` : ''
      }${orderBy ? ', $o' : ''}; count;`,
      inferred
    );
    const elements = getRelations(
      `${finalQuery} ${orderingKey} get $rel, $from, $to${
        extraRel ? `, $${extraRel}` : ''
      }${orderBy ? ', $o' : ''}; ${
        orderBy ? `sort $o ${orderMode};` : ''
      } offset ${offset}; limit ${first};`,
      'rel',
      'from',
      'to',
      extraRel,
      inferred,
      !(fromId || toId)
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
  } catch (err) {
    logger.error('[GRAKN] paginateRelationships error > ', err);
    return null;
  }
};

/**
 * Create a relation between to element in the model without restriction.
 * @param id
 * @param input
 */
export const createRelation = async (id, input) => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $from has internal_id "${escapeString(id)}";
      $to has internal_id "${escapeString(input.toId)}"; 
      insert $rel(${escape(input.fromRole)}: $from, ${escape(
      input.toRole
    )}: $to) isa ${input.through}, has internal_id "${uuid()}" ${
      input.stix_id
        ? `, has relationship_type "${escapeString(input.through)}"`
        : ''
    }
        ${
          // eslint-disable-next-line no-nested-ternary
          input.stix_id
            ? input.stix_id === 'create'
              ? `, has stix_id "relationship--${uuid()}"`
              : `, has stix_id "${escapeString(input.stix_id)}"`
            : ''
        } ${
      input.first_seen
        ? `, has first_seen ${prepareDate(input.first_seen)}`
        : ''
    } ${
      input.last_seen ? `, has last_seen ${prepareDate(input.last_seen)}` : ''
    } ${input.weight ? `, has weight ${escape(input.weight)}` : ''};`;
    logger.debug(`[GRAKN - infer: false] createRelation > ${query}`);
    const node = await getById(input.toId);
    const iterator = await wTx.tx.query(query);
    const answer = await iterator.next();
    const createdRelation = await answer.map().get('rel');
    const relation = await getAttributes(createdRelation);
    await commitWriteTx(wTx);
    return { node, relation };
  } catch (err) {
    logger.error('[GRAKN] createRelation error > ', err);
    await closeWriteTx(wTx);
    return null;
  }
};

/**
 * Edit an attribute value.
 * @param id
 * @param input
 * @param tx
 * @returns the complete instance
 */
export const updateAttribute = async (id, input, tx = null) => {
  const wTx = tx === null ? await takeWriteTx() : tx;
  try {
    const { key, value } = input; // value can be multi valued
    const escapedKey = escape(key);
    const labelTypeQuery = `match $x type ${escapedKey}; get;`;
    const labelIterator = await wTx.tx.query(labelTypeQuery);
    const labelAnswer = await labelIterator.next();
    /* eslint-disable prettier/prettier */
    const attrType = await labelAnswer
      .map()
      .get('x')
      .dataType();
    const deleteQuery = `match $x has internal_id "${escapeString(
      id
    )}", has ${escapedKey} $del via $d; delete $d;`;
    /* eslint-enable prettier/prettier */
    logger.debug(
      `[GRAKN - infer: false] updateAttribute - delete > ${deleteQuery}`
    );
    await wTx.tx.query(deleteQuery);
    let typedValues = map(
      v => (attrType === String ? `"${escapeString(v)}"` : escape(v)),
      value
    );
    if (typedValues.length === 0) {
      typedValues = [attrType === String ? '""' : ''];
    }
    let graknValues;
    if (typedValues.length === 1) {
      graknValues = `has ${escapedKey} ${head(typedValues)}`;
    } else {
      graknValues = `${join(
        ' ',
        map(val => `has ${escapedKey} ${val},`, tail(typedValues))
      )} has ${escapedKey} ${head(typedValues)}`;
    }
    const createQuery = `match $m has internal_id "${escapeString(
      id
    )}"; insert $m ${graknValues};`;
    logger.debug(
      `[GRAKN - infer: false] updateAttribute - insert > ${createQuery}`
    );
    await wTx.tx.query(createQuery);
    // Adding dates elements
    if (includes(key, statsDateAttributes)) {
      const dayValue = dayFormat(head(value));
      const monthValue = monthFormat(head(value));
      const yearValue = yearFormat(head(value));
      const dayInput = { key: `${key}_day`, value: [dayValue] };
      await updateAttribute(id, dayInput, wTx);
      const monthInput = { key: `${key}_month`, value: [monthValue] };
      await updateAttribute(id, monthInput, wTx);
      const yearInput = { key: `${key}_year`, value: [yearValue] };
      await updateAttribute(id, yearInput, wTx);
    }
    // In case of recursive function, just return after adding extra updates.
    if (tx !== null) return tx;
    // Then commit the data
    await commitWriteTx(wTx);
    // Return the final result
    return await getById(id, true);
  } catch (err) {
    logger.error('[GRAKN] updateAttribute error > ', err);
    await closeWriteTx(wTx);
    return null;
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
    const query = `match $x has internal_id "${escapeString(
      id
    )}"; $z($x, $y); delete $z, $x;`;
    logger.debug(`[GRAKN - infer: false] deleteEntityById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    await commitWriteTx(wTx);
    return id;
  } catch (err) {
    logger.error('[GRAKN] deleteEntityById error > ', err);
    await closeWriteTx(wTx);
    return null;
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
    const query = `match $x has internal_id "${escapeString(id)}"; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    await commitWriteTx(wTx);
    return id;
  } catch (err) {
    logger.error('[GRAKN] deleteById error > ', err);
    await closeWriteTx(wTx);
    return null;
  }
};

/**
 * Grakn generic function to delete a relationship
 * @param id
 * @param relationId
 * @returns {Promise<any[] | never>}
 */
export const deleteRelationById = async (id, relationId) => {
  const wTx = await takeWriteTx();
  try {
    const query = `match $x has internal_id "${escapeString(
      relationId
    )}"; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteRelationById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    await commitWriteTx(wTx);
    return getById(id).then(data => ({
      node: data,
      relation: { id: relationId }
    }));
  } catch (err) {
    logger.error('[GRAKN] deleteRelationById error > ', err);
    await closeWriteTx(wTx);
    return null;
  }
};

/**
 * Grakn generic timeseries
 * @param query
 * @param options
 * @returns Promise
 */
export const timeSeries = async (query, options) => {
  const rTx = await takeReadTx();
  try {
    const {
      startDate,
      endDate,
      operation,
      field,
      interval,
      inferred = true
    } = options;
    const finalQuery = `${query}; $x has ${field}_${interval} $g; get; group $g; ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] timeSeries > ${finalQuery}`);
    const iterator = await rTx.tx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    const resultPromise = Promise.all(
      answer.map(async n => {
        const date = await n.owner().value();
        const number = await n.answers()[0].number();
        return { date, value: number };
      })
    ).then(result => fillTimeSeries(startDate, endDate, interval, result));
    const result = await Promise.resolve(resultPromise);
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] timeSeries error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};

/**
 * Grakn generic distribution
 * @param query
 * @param options
 * @returns Promise
 */
export const distribution = async (query, options) => {
  const rTx = await takeReadTx();
  try {
    const { startDate, endDate, operation, field, inferred = false } = options;
    const finalQuery = `${query}; ${
      startDate && endDate
        ? `$rel has first_seen $fs; $fs > ${prepareDate(
            startDate
          )}; $fs < ${prepareDate(endDate)};`
        : ''
    } $x has ${field} $g; get; group $g; ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] distribution > ${finalQuery}`);
    const iterator = await rTx.tx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    const resultPromise = Promise.all(
      answer.map(async n => {
        const label = await n.owner().value();
        const number = await n.answers()[0].number();
        return { label, value: number };
      })
    );
    const result = await Promise.resolve(resultPromise);
    await closeReadTx(rTx);
    return result;
  } catch (err) {
    logger.error('[GRAKN] distribution error > ', err);
    await closeReadTx(rTx);
    return null;
  }
};
