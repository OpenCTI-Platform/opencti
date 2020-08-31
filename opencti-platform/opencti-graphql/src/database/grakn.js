import moment from 'moment';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn-client';
import * as R from 'ramda';
import { __ } from 'ramda';
import {
  DatabaseError,
  DuplicateEntryError,
  FunctionalError,
  MissingReferenceError,
  TYPE_DUPLICATE_ENTRY,
  TYPE_LOCK_ERROR,
  UnsupportedError,
} from '../config/errors';
import conf, { logger } from '../config/conf';
import { buildPagination, fillTimeSeries, inferIndexFromConceptType, utcDate } from './utils';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elBulk,
  elDeleteInstanceIds,
  elFindByIds,
  elHistogramCount,
  elIndexElements,
  elLoadByIds,
  elPaginate,
  elRemoveRelationConnection,
  elUpdate,
  ENTITIES_INDICES,
  prepareElementForIndexing,
  REL_INDEX_PREFIX,
  RELATIONSHIPS_INDICES,
  useCache,
} from './elasticSearch';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_UPDATE,
  EVENT_TYPE_UPDATE_ADD,
  EVENT_TYPE_UPDATE_REMOVE,
  sendLog,
} from './rabbitmq';
import { generateInternalId, generateStandardId, isFieldContributingToStandardId } from '../schema/identifier';
import { lockResource } from './redis';
import { STIX_SPEC_VERSION } from './stix';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  isAbstract,
} from '../schema/general';
import { getParentTypes, isAnId } from '../schema/schemaUtils';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { isDatedInternalObject, isInternalObject } from '../schema/internalObject';
import { isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isStixRelationShipExceptMeta } from '../schema/stixRelationship';
import {
  dictAttributes,
  multipleAttributes,
  statsDateAttributes,
  isDictionaryAttribute,
  isMultipleAttribute,
} from '../schema/fieldDataAdapter';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_CONTAINER_REPORT, isStixDomainObject } from '../schema/stixDomainObject';
import { ENTITY_TYPE_LABEL, isStixMetaObject } from '../schema/stixMetaObject';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';

// region global variables
export const FROM_START = 0; // "1970-01-01T00:00:00.000Z"
export const UNTIL_END = 100000000000000; // "5138-11-16T09:46:40.000Z"
const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';
const GraknString = 'String';
const GraknDate = 'Datetime';

export const REL_CONNECTED_SUFFIX = 'CONNECTED';
const INFERRED_RELATION_KEY = 'rel';

export const now = () => utcDate().toISOString();
export const sinceNowInMinutes = (lastModified) => {
  const diff = utcDate().diff(utcDate(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};
export const prepareDate = (date) => utcDate(date).format(dateFormat);
export const yearFormat = (date) => utcDate(date).format('YYYY');
export const monthFormat = (date) => utcDate(date).format('YYYY-MM');
export const dayFormat = (date) => utcDate(date).format('YYYY-MM-DD');

export const escape = (chars) => {
  const toEscape = chars && typeof chars === 'string';
  if (toEscape) {
    return chars.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,');
  }
  return chars;
};
export const escapeString = (s) => (s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '');

// region client
const client = new Grakn(`${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`);
let session = null;
// endregion

// region basic commands
const closeTx = async (gTx) => {
  if (gTx.isOpen()) {
    return gTx.close().catch(
      /* istanbul ignore next */ (err) => {
        throw DatabaseError('[GRAKN] CloseReadTx error', { grakn: err.details });
      }
    );
  }
  return true;
};

const takeReadTx = async () => {
  if (session === null) session = await client.session('grakn');
  return session
    .transaction()
    .read()
    .catch(
      /* istanbul ignore next */ (err) => {
        if (err.code === 2 && session) {
          session = null;
          return takeReadTx();
        }
        throw DatabaseError('[GRAKN] TakeReadTx error', { grakn: err.details });
      }
    );
};
export const executeRead = async (executeFunction) => {
  const rTx = await takeReadTx();
  try {
    const result = await executeFunction(rTx);
    await closeTx(rTx);
    return result;
  } catch (err) {
    await closeTx(rTx);
    /* istanbul ignore next */
    throw err;
  }
};

const takeWriteTx = async () => {
  if (session === null) session = await client.session('grakn');
  return session
    .transaction()
    .write()
    .catch(
      /* istanbul ignore next */ (err) => {
        if (err.code === 2 && session) {
          session = null;
          return takeWriteTx();
        }
        throw DatabaseError('[GRAKN] TakeWriteTx error', { grakn: err.details });
      }
    );
};
const commitWriteTx = async (wTx) => {
  return wTx.commit().catch(
    /* istanbul ignore next */ (err) => {
      if (err.code === 3) {
        const errorDetail = R.split('\n', err.details)[1];
        // In grakn, its not possible yet to have structured errors.
        // We need to extract the information from the message.
        // There is more than one thing of type [XX] that owns the key [XX] of type [XX].
        const messageRegExp = /.*more than one thing.*owns the key \[([a-z0-9\\-]+)\] of type \[([a-z_]+)\]/;
        const duplicateMatcher = errorDetail.match(messageRegExp);
        if (duplicateMatcher) {
          const message = 'Element already exists (grakn)';
          throw DuplicateEntryError(message, { id: duplicateMatcher[1], field: duplicateMatcher[2] });
        }
      }
      throw DatabaseError('[GRAKN] CommitWriteTx error', { grakn: err.details });
    }
  );
};

export const executeWrite = async (executeFunction) => {
  const wTx = await takeWriteTx();
  try {
    const result = await executeFunction(wTx);
    await commitWriteTx(wTx);
    return result;
  } catch (err) {
    await closeTx(wTx);
    /* istanbul ignore next */
    throw err;
  }
};
export const internalDirectWrite = async (query) => {
  const wTx = await takeWriteTx();
  return wTx
    .query(query)
    .then(() => commitWriteTx(wTx))
    .catch(
      /* istanbul ignore next */ async (err) => {
        await closeTx(wTx);
        logger.error('[GRAKN] Write error', { error: err });
        throw err;
      }
    );
};

export const graknIsAlive = async () => {
  return executeRead(() => {})
    .then(() => true)
    .catch(
      /* istanbul ignore next */ () => {
        throw DatabaseError('Grakn seems down');
      }
    );
};
export const getGraknVersion = () => {
  // It seems that Grakn server does not expose its version yet:
  // https://github.com/graknlabs/client-nodejs/issues/47
  return '1.8.1';
};

const getAliasInternalIdFilter = (query, alias) => {
  const reg = new RegExp(`\\$${alias}[\\s]*has[\\s]*internal_id[\\s]*"([0-9a-z-_]+)"`, 'gi');
  const keyVars = Array.from(query.matchAll(reg));
  return keyVars.length > 0 ? R.last(R.head(keyVars)) : undefined;
};
/**
 * Extract all vars from a grakn query
 * @param query
 */
export const extractQueryVars = (query) => {
  const vars = R.uniq(R.map((m) => ({ alias: m.replace('$', '') }), query.match(/\$[a-z_]+/gi)));
  const varWithKey = R.map((v) => ({ alias: v.alias, internalIdKey: getAliasInternalIdFilter(query, v.alias) }), vars);
  const relationsVars = Array.from(query.matchAll(/\(([a-z_\-\s:$]+),([a-z_\-\s:$]+)\)[\s]*isa[\s]*([a-z_-]+)/g));
  const roles = R.flatten(
    R.map((r) => {
      const [, left, right, relationshipType] = r;
      const [leftRole, leftAlias] = R.includes(':', left) ? left.trim().split(':') : [null, left];
      const [rightRole, rightAlias] = R.includes(':', right) ? right.trim().split(':') : [null, right];
      const roleForLeft =
        leftRole || (rightRole && rightRole.includes('_from') ? `${relationshipType}_to` : `${relationshipType}_from`);
      const roleForRight =
        rightRole || (leftRole && leftRole.includes('_to') ? `${relationshipType}_from` : `${relationshipType}_to`);
      const lAlias = leftAlias.trim().replace('$', '');
      const lKeyFilter = getAliasInternalIdFilter(query, lAlias);
      const rAlias = rightAlias.trim().replace('$', '');
      const rKeyFilter = getAliasInternalIdFilter(query, rAlias);
      // If one filtering key is specified, just return the duo with no roles
      if (lKeyFilter || rKeyFilter) {
        return [
          { alias: lAlias, internalIdKey: lKeyFilter },
          { alias: rAlias, internalIdKey: rKeyFilter },
        ];
      }
      return [
        { role: roleForLeft.trim(), alias: lAlias },
        { role: roleForRight.trim(), alias: rAlias },
      ];
    }, relationsVars)
  );
  return R.map((v) => {
    const associatedRole = R.find((r) => r.alias === v.alias, roles);
    return R.pipe(
      R.assoc('internalIdKey', associatedRole ? associatedRole.internalIdKey : v.internalIdKey),
      R.assoc('role', associatedRole ? associatedRole.role : undefined)
    )(v);
  }, varWithKey);
};
// endregion

// region Loader common
export const querySubTypes = async (type, includeParents = false) => {
  return executeRead(async (rTx) => {
    const query = `match $x sub ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] querySubTypes`, { query });
    const iterator = await rTx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async (answer) => {
        const subType = answer.map().get('x');
        const subTypeLabel = await subType.label();
        return {
          id: subType.id,
          label: subTypeLabel,
        };
      })
    );
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('label')));
    const finalResult = R.pipe(
      R.filter((n) => n.label !== type && (includeParents || !isAbstract(n.label))),
      sortByLabel,
      R.map((n) => ({ node: n }))
    )(result);
    return buildPagination(5000, 0, finalResult, 5000);
  });
};
export const queryAttributes = async (type) => {
  return executeRead(async (rTx) => {
    const query = `match $x type ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] querySubTypes`, { query });
    const iterator = await rTx.query(query);
    const answer = await iterator.next();
    const attributeIterator = await answer.map().get('x').attributes();
    const attributeAnswers = await attributeIterator.collect();
    const result = await Promise.all(
      attributeAnswers.map(async (attributeAnswer) => {
        return attributeAnswer.label();
      })
    );
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('label')));
    const finalResult = R.pipe(
      sortByLabel,
      R.map((n) => ({ node: n }))
    )(result);
    return buildPagination(5000, 0, finalResult, 5000);
  });
};
export const queryAttributeValues = async (type) => {
  return executeRead(async (rTx) => {
    const query = `match $x isa ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValues`, { query });
    const iterator = await rTx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async (answer) => {
        const attribute = answer.map().get('x');
        const attributeType = await attribute.type();
        const value = await attribute.value();
        const attributeTypeLabel = await attributeType.label();
        const replacedValue = typeof value === 'string' ? value.replace(/\\"/g, '"').replace(/\\\\/g, '\\') : value;
        return {
          node: {
            id: attribute.id,
            type: attributeTypeLabel,
            value: replacedValue,
          },
        };
      })
    );
    return buildPagination(5000, 0, result, 5000);
  });
};
export const attributeExists = async (attributeLabel) => {
  return executeRead(async (rTx) => {
    const checkQuery = `match $x sub ${attributeLabel}; get;`;
    logger.debug(`[GRAKN - infer: false] attributeExists`, { query: checkQuery });
    await rTx.query(checkQuery);
    return true;
  }).catch(() => false);
};
export const queryAttributeValueByGraknId = async (id) => {
  return executeRead(async (rTx) => {
    const query = `match $x id ${escape(id)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValueById`, { query });
    const iterator = await rTx.query(query);
    const answer = await iterator.next();
    const attribute = answer.map().get('x');
    const attributeType = await attribute.type();
    const value = await attribute.value();
    const attributeTypeLabel = await attributeType.label();
    const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    return {
      id: attribute.id,
      type: attributeTypeLabel,
      value: replacedValue,
    };
  });
};

const resolveInternalIdOfConcept = async (tx, conceptId, internalIdAttribute) => {
  const resolveConcept = await tx.getConcept(conceptId);
  const roleConceptRemote = await (await resolveConcept.attributes(internalIdAttribute)).collect();
  return R.head(roleConceptRemote).value();
};
/**
 * Load any grakn instance with internal grakn ID.
 * @param tx the transaction
 * @param concept the concept to get attributes from
 * @param args
 * @returns {Promise}
 */
const loadConcept = async (tx, concept, args = {}) => {
  const { internalId } = args;
  const conceptBaseType = concept.baseType;
  // const types = await conceptTypes(tx, concept);
  const remoteConceptType = await concept.type();
  const conceptType = await remoteConceptType.label();
  const internalIdAttribute = await tx.getSchemaConcept('internal_id');
  const index = inferIndexFromConceptType(conceptType);
  // 01. Return the data in elastic if not explicitly asked in grakn
  // eslint-disable-next-line no-underscore-dangle
  if (!concept._inferred && useCache(args)) {
    // Sometimes we already know the internal id because we specify it in the query.
    const conceptInternalId = internalId || (await resolveInternalIdOfConcept(tx, concept.id, internalIdAttribute));
    const conceptFromCache = await elLoadByIds(conceptInternalId, null, [index]);
    if (!conceptFromCache) {
      /* istanbul ignore next */
      logger.info(`[ELASTIC] ${conceptInternalId} not indexed yet, loading with Grakn`);
    } else {
      // Need to associate the grakn id for result rebinding
      return R.assoc('grakn_id', concept.id, conceptFromCache);
    }
  }
  // 02. If not found continue the process.
  const attributesIterator = await concept.asRemote(tx).attributes();
  const attributes = await attributesIterator.collect();
  const attributesPromises = attributes.map(async (attribute) => {
    const attributeType = await attribute.type();
    const attributeLabel = await attributeType.label();
    return {
      dataType: await attributeType.valueType(),
      label: attributeLabel,
      value: await attribute.value(),
    };
  });
  return Promise.all(attributesPromises)
    .then((attributesData) => {
      const transform = R.pipe(
        R.map((attribute) => {
          let transformedVal = attribute.value;
          const { dataType, label } = attribute;
          if (dataType === GraknDate) {
            transformedVal = moment(attribute.value).utc().toISOString();
          } else if (dataType === GraknString) {
            transformedVal = attribute.value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
          }
          // Dict is encoded as string, so must be string transform first when parse to JSON
          if (isDictionaryAttribute(attribute.label)) {
            transformedVal = JSON.parse(transformedVal);
          }
          return { [label]: transformedVal };
        }), // Extract values
        R.chain(R.toPairs), // Convert to pairs for grouping
        R.groupBy(R.head), // Group by key
        R.map(R.pluck(1)), // Remove grouping boilerplate
        R.mapObjIndexed((num, key, obj) =>
          // eslint-disable-next-line no-nested-ternary
          Array.isArray(obj[key]) && !R.includes(key, multipleAttributes)
            ? R.head(obj[key])
            : R.head(obj[key]) && R.head(obj[key]) !== ''
            ? obj[key]
            : []
        ) // Remove extra list then contains only 1 element
      )(attributesData);
      return R.pipe(
        R.assoc('_index', index),
        R.assoc('id', transform.internal_id),
        R.assoc('grakn_id', concept.id),
        R.assoc('base_type', conceptBaseType),
        R.assoc('parent_types', transform.entity_type ? getParentTypes(transform.entity_type) : null)
      )(transform);
    })
    .then(async (entityData) => {
      if (entityData.base_type !== BASE_TYPE_RELATION) return entityData;
      const isInferredPromise = concept.isInferred();
      const rolePlayers = await concept.asRemote(tx).rolePlayersMap();
      const roleEntries = Array.from(rolePlayers.entries());
      const rolesPromises = Promise.all(
        R.map(async (roleItem) => {
          const targetRole = R.last(roleItem).values().next();
          const targetId = targetRole.value.id;
          const roleInternalId = await resolveInternalIdOfConcept(tx, targetId, internalIdAttribute);
          const remoteTargetType = await targetRole.value.type();
          const roleType = await remoteTargetType.label();
          // eslint-disable-next-line prettier/prettier
          return R.head(roleItem)
            .label()
            .then(async (roleLabel) => {
              const [, useAlias] = roleLabel.split('_');
              return {
                [useAlias]: null, // With be use lazily
                [`${useAlias}Id`]: roleInternalId,
                [`${useAlias}GraknId`]: targetId, // Only for internal usage in inference case
                [`${useAlias}Role`]: roleLabel,
                [`${useAlias}Type`]: roleType,
              };
            });
        }, roleEntries)
      );
      // Wait for all promises before building the result
      return Promise.all([isInferredPromise, rolesPromises]).then(([isInferred, roles]) => {
        return R.pipe(
          R.assoc('id', entityData.id),
          R.assoc('inferred', isInferred),
          R.assoc('entity_type', entityData.entity_type),
          R.mergeRight(R.mergeAll(roles))
        )(entityData);
      });
    })
    .then(async (relationData) => {
      // Then change the id if relation is inferred
      if (relationData.inferred) {
        const { fromGraknId, fromRole, toGraknId, toRole } = relationData;
        // Pattern need to be forge with graknId / Grakn courtesy.
        const pattern = `{ $${INFERRED_RELATION_KEY}(${fromRole}: $from, ${toRole}: $to) isa ${conceptType}; 
          $from id ${fromGraknId}; $to id ${toGraknId}; };`;
        const queryTime = now();
        const inferenceId = Buffer.from(pattern).toString('base64');
        return R.pipe(
          R.assoc('id', inferenceId),
          R.assoc('internal_id', inferenceId),
          R.assoc('entity_type', conceptType),
          R.assoc('relationship_type', conceptType),
          R.assoc('parent_types', getParentTypes(conceptType)),
          R.assoc('created', queryTime),
          R.assoc('modified', queryTime),
          R.assoc('created_at', queryTime),
          R.assoc('updated_at', queryTime)
        )(relationData);
      }
      return relationData;
    });
};
const getConcepts = async (tx, answers, conceptQueryVars, entities, conceptOpts = {}) => {
  const { infer = false, noCache = false } = conceptOpts;
  const plainEntities = R.filter((e) => !R.isEmpty(e) && !R.isNil(e), entities);
  if (answers.length === 0) return [];
  // 02. Query concepts and rebind the data
  const queryConcepts = await Promise.all(
    R.map(async (answer) => {
      // Create a map useful for relation roles binding
      const queryVarsToConcepts = await Promise.all(
        conceptQueryVars.map(async ({ alias, role, internalIdKey }) => {
          const concept = answer.map().get(alias);
          if (!concept || concept.baseType === 'ATTRIBUTE') return undefined; // If specific attributes are used for filtering, ordering, ...
          // If internal id of the element is not directly accessible
          // And the element is part of element needed for the result, ensure the key is asked in the query.
          const conceptType = await concept.type();
          const type = await conceptType.label();
          return {
            id: concept.id,
            internalId: internalIdKey,
            data: { concept, alias, role, type },
          };
        })
      );
      // Fetch every concepts of the answer
      const conceptsIndex = R.filter((e) => e, queryVarsToConcepts);
      const requestedConcepts = R.filter((r) => R.includes(r.data.alias, entities), conceptsIndex);
      return R.map((t) => {
        const { concept, internalId } = t.data;
        return {
          internalId,
          concept,
        };
      }, requestedConcepts);
    }, answers)
  );
  // 03. Fetch every unique concepts
  const uniqConceptsLoading = R.pipe(
    R.flatten,
    R.uniqBy((e) => e.concept.id),
    R.map((l) => loadConcept(tx, l.concept, { internalId: l.internalId, noCache, infer }))
  )(queryConcepts);
  const resolvedConcepts = await Promise.all(uniqConceptsLoading);
  // 04. Create map from concepts
  const conceptCache = new Map(R.map((c) => [c.grakn_id, c], resolvedConcepts));
  // 05. Bind all row to data entities
  return answers.map((answer) => {
    const dataPerEntities = plainEntities.map((entity) => {
      const concept = answer.map().get(entity);
      const conceptData = concept && conceptCache.get(concept.id);
      return [entity, conceptData];
    });
    return R.fromPairs(dataPerEntities);
  });
};
export const find = async (query, entities, findOpts = {}) => {
  // Remove empty values from entities
  const { infer = false, paginationKey = null } = findOpts;
  return executeRead(async (rTx) => {
    const conceptQueryVars = extractQueryVars(query);
    logger.debug(`[GRAKN - infer: ${infer}] Find`, { query });
    const iterator = await rTx.query(query, { infer });
    // 01. Get every concepts to fetch (unique)
    const answers = await iterator.collect();
    const data = await getConcepts(rTx, answers, conceptQueryVars, entities, findOpts);
    if (paginationKey) {
      const edges = R.map((t) => ({ node: t[paginationKey] }), data);
      return buildPagination(0, 0, edges, edges.length);
    }
    return data;
  });
};
export const load = async (query, entities, options) => {
  const data = await find(query, entities, options);
  if (data.length > 1) {
    logger.debug('[GRAKN] Maybe you should use list instead for multiple results', { query });
  }
  return R.head(data);
};
// endregion

// region Loader list
const getSingleValue = (query, infer = false) => {
  return executeRead(async (rTx) => {
    logger.debug(`[GRAKN - infer: ${infer}] getSingleValue`, { query });
    const iterator = await rTx.query(query, { infer });
    return iterator.next();
  });
};
export const getSingleValueNumber = (query, infer = false) => {
  return getSingleValue(query, infer).then((data) => data.number());
};
export const listToEntitiesThroughRelation = (fromId, fromType, relationType, toEntityType) => {
  return find(
    `match $to isa ${toEntityType}; 
    $rel(${relationType}_from:$from, ${relationType}_to:$to) isa ${relationType};
    ${fromType ? `$from isa ${fromType};` : ''}
    $from has internal_id "${escapeString(fromId)}"; get;`,
    ['to'],
    { paginationKey: 'to' }
  );
};
export const listFromEntitiesThroughRelation = (toId, toType, relationType, fromEntityType) => {
  return find(
    `match $from isa ${fromEntityType}; 
    $rel(${relationType}_from:$from, ${relationType}_to:$to) isa ${relationType};
    ${toType ? `$to isa ${toType};` : ''}
    $to has internal_id "${escapeString(toId)}"; get;`,
    ['from'],
    { paginationKey: 'from' }
  );
};
const listElements = async (baseQuery, elementKey, first, offset, args) => {
  const { orderBy = null, orderMode = 'asc', inferred = false, noCache = false } = args;
  const countQuery = `${baseQuery} count;`;
  const paginateQuery = `offset ${offset}; limit ${first};`;
  const orderQuery = orderBy ? `sort $order ${orderMode};` : '';
  const query = `${baseQuery} ${orderQuery} ${paginateQuery}`;
  const countPromise = getSingleValueNumber(countQuery, inferred);
  const findOpts = { infer: inferred, noCache };
  const instancesPromise = find(query, [elementKey], findOpts);
  return Promise.all([instancesPromise, countPromise]).then(([instances, globalCount]) => {
    const edges = R.map((t) => ({ node: t[elementKey] }), instances);
    return buildPagination(first, offset, edges, globalCount);
  });
};
export const listEntities = async (entityTypes, searchFields, args = {}) => {
  // filters contains potential relations like, mitigates, tagged ...
  const { first = 1000, after, orderBy } = args;
  const { search, filters } = args;
  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && R.includes('.', orderBy);
  // Define if Elastic can support this query.
  // 01-2 Check the filters
  const validFilters = R.filter((f) => f && f.values.filter((n) => n).length > 0, filters || []);
  const unSupportedRelations =
    R.filter((k) => {
      // If the relation must be forced in a specific direction, ES cant support it.
      if (k.fromRole || k.toRole) return true;
      const isRelationFilter = R.includes('.', k.key);
      if (isRelationFilter) {
        // ES only support internal_id reference
        const [, field] = k.key.split('.');
        if (field !== 'internal_id') return true;
      }
      return false;
    }, validFilters).length > 0;
  // 01-3 Check the ordering
  const unsupportedOrdering = isRelationOrderBy && R.last(orderBy.split('.')) !== 'internal_id';
  const supportedByCache = !unsupportedOrdering && !unSupportedRelations;
  if (useCache(args) && supportedByCache) {
    return elPaginate(ENTITIES_INDICES, R.assoc('types', entityTypes, args));
  }
  logger.debug(`[GRAKN] ListEntities on Grakn, supportedByCache: ${supportedByCache}`);

  // 02. If not go with standard Grakn
  const relationsFields = [];
  const attributesFields = [];
  const attributesFilters = [];
  // Handle order by field
  if (isRelationOrderBy) {
    const [relation, field] = orderBy.split('.');
    const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
    relationsFields.push(
      `($elem, $${curatedRelation}) isa ${curatedRelation}; $${curatedRelation} has ${field} $order;`
    );
  } else if (orderBy) {
    attributesFields.push(`$elem has ${orderBy} $order;`);
  }
  // Handle filters
  if (validFilters && validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const filterKey = validFilters[index].key;
      const filterValues = validFilters[index].values;
      const isRelationFilter = R.includes('.', filterKey);
      if (isRelationFilter) {
        const [relation, field] = filterKey.split('.');
        const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
        const sourceRole = validFilters[index].fromRole ? `${validFilters[index].fromRole}:` : '';
        const toRole = validFilters[index].toRole ? `${validFilters[index].toRole}:` : '';
        const relId = `rel_${curatedRelation}`;
        relationsFields.push(`$${relId} (${sourceRole}$elem, ${toRole}$${curatedRelation}) isa ${curatedRelation};`);
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          // Apply filter on target.
          const val = filterValues[valueIndex];
          const preparedValue = R.type(val) === 'Boolean' ? val : `"${escapeString(val)}"`;
          // TODO @Julien Support more than only boolean and string filters
          attributesFields.push(`$${curatedRelation} has ${field} ${preparedValue};`);
        }
      } else {
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          const val = filterValues[valueIndex];
          if (val === 'EXISTS') {
            attributesFields.push(`$elem has ${filterKey} $${filterKey}_exist;`);
          } else {
            const preparedValue = R.type(val) === 'Boolean' ? val : `"${escapeString(val)}"`;
            attributesFields.push(`$elem has ${filterKey} ${preparedValue};`);
          }
        }
      }
    }
  }
  // Handle special case of search
  if (search) {
    for (let searchIndex = 0; searchIndex < searchFields.length; searchIndex += 1) {
      const searchFieldName = searchFields[searchIndex];
      attributesFields.push(`$elem has ${searchFieldName} $${searchFieldName};`);
    }
    const searchFilter = R.pipe(
      R.map((e) => `{ $${e} contains "${escapeString(search)}"; }`),
      R.join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  // build the final query
  const queryAttributesFields = R.join(' ', attributesFields);
  const queryAttributesFilters = R.join(' ', attributesFilters);
  const queryRelationsFields = R.join(' ', relationsFields);
  const headType = entityTypes.length === 1 ? R.head(entityTypes) : 'Basic-Object';
  const extraTypes =
    entityTypes.length > 1
      ? R.pipe(
          R.map((e) => `{ $elem isa ${e}; }`),
          R.join(' or '),
          R.concat(__, ';')
        )(entityTypes)
      : '';
  const baseQuery = `match $elem isa ${headType}, has internal_id $elem_id; ${extraTypes} ${queryRelationsFields} 
                      ${queryAttributesFields} ${queryAttributesFilters} get;`;
  return listElements(baseQuery, 'elem', first, offset, args);
};
export const listRelations = async (relationshipType, args) => {
  const searchFields = ['name', 'description'];
  const { first = 1000, after, orderBy, relationFilter, inferred = false } = args;
  let useInference = inferred;
  const { filters = [], search, elementId, fromId, fromRole, toId, toRole, fromTypes = [], toTypes = [] } = args;
  const {
    startTimeStart,
    startTimeStop,
    stopTimeStart,
    stopTimeStop,
    firstSeenStart,
    firstSeenStop,
    lastSeenStart,
    lastSeenStop,
    confidences = [],
  } = args;
  // Use $from, $to only if fromId or toId specified.
  // Else, just ask for the relation only.
  // fromType or toType only allow if fromId or toId available
  const definedRoles = !R.isNil(fromRole) || !R.isNil(toRole);
  const askForConnections = !R.isNil(elementId) || !R.isNil(fromId) || !R.isNil(toId) || definedRoles;
  const haveTargetFilters = filters && filters.length > 0; // For now filters only contains target to filtering
  const fromTypesFilter = fromTypes && fromTypes.length > 0;
  const toTypesFilter = toTypes && toTypes.length > 0;
  if (askForConnections === false && (haveTargetFilters || fromTypesFilter || toTypesFilter || search)) {
    throw DatabaseError('Cant list relation with types filtering or search if from or to id are not specified');
  }
  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && R.includes('.', orderBy);
  // Handle relation type(s)
  const relationToGet = relationshipType || 'stix-core-relationship';
  // 0 - Check if we can support the query by Elastic
  const unsupportedOrdering = isRelationOrderBy && R.last(orderBy.split('.')) !== 'internal_id';
  // Search is not supported because its only search on the relation to.
  const supportedByCache = !search && !unsupportedOrdering && !haveTargetFilters && !inferred && !definedRoles;
  if (useCache(args) && supportedByCache) {
    const finalFilters = [];
    if (relationFilter) {
      const { relation, id, relationId } = relationFilter;
      finalFilters.push({ key: `${REL_INDEX_PREFIX}${relation}.internal_id`, values: [id] });
      if (relationId) {
        finalFilters.push({ key: `internal_id`, values: [relationId] });
      }
    }
    if (elementId) {
      finalFilters.push({ key: 'connections.internal_id', values: [elementId] });
    }
    if (fromId) {
      finalFilters.push({ key: 'connections.internal_id', values: [fromId] });
    }
    if (toId) {
      finalFilters.push({ key: 'connections.internal_id', values: [toId] });
    }
    if (fromTypes && fromTypes.length > 0) finalFilters.push({ key: 'connections.types', values: fromTypes });
    if (toTypes && toTypes.length > 0) finalFilters.push({ key: 'connections.types', values: toTypes });
    if (startTimeStart) finalFilters.push({ key: 'start_time', values: [startTimeStart], operator: 'gt' });
    if (startTimeStop) finalFilters.push({ key: 'start_time', values: [startTimeStop], operator: 'lt' });
    if (stopTimeStart) finalFilters.push({ key: 'stop_time', values: [stopTimeStart], operator: 'gt' });
    if (stopTimeStop) finalFilters.push({ key: 'stop_time', values: [stopTimeStop], operator: 'lt' });
    if (firstSeenStart) finalFilters.push({ key: 'first_seen', values: [firstSeenStart], operator: 'gt' });
    if (firstSeenStop) finalFilters.push({ key: 'first_seen', values: [firstSeenStop], operator: 'lt' });
    if (lastSeenStart) finalFilters.push({ key: 'last_seen', values: [lastSeenStart], operator: 'gt' });
    if (lastSeenStop) finalFilters.push({ key: 'last_seen', values: [lastSeenStop], operator: 'lt' });
    if (confidences && confidences.length > 0) finalFilters.push({ key: 'confidence', values: confidences });
    const paginateArgs = R.pipe(R.assoc('types', [relationToGet]), R.assoc('filters', finalFilters))(args);
    return elPaginate(RELATIONSHIPS_INDICES, paginateArgs);
  }
  // 1- If not, use Grakn
  const queryFromTypes = fromTypesFilter
    ? R.pipe(
        R.map((e) => `{ $from isa ${e}; }`),
        R.join(' or '),
        R.concat(__, ';')
      )(fromTypes)
    : '';
  const queryToTypes = toTypesFilter
    ? R.pipe(
        R.map((e) => `{ $to isa ${e}; }`),
        R.join(' or '),
        R.concat(__, ';')
      )(toTypes)
    : '';
  // Search
  const relationsFields = [];
  const attributesFields = [];
  const attributesFilters = [];
  // Handle order by field
  if (isRelationOrderBy) {
    const [relation, field] = orderBy.split('.');
    const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
    if (curatedRelation.includes(REL_CONNECTED_SUFFIX)) {
      const finalCuratedRelation = curatedRelation.replace(REL_CONNECTED_SUFFIX, '');
      relationsFields.push(`$${finalCuratedRelation} has ${field} $order;`);
    } else {
      useInference = true;
      relationsFields.push(
        `($rel, $${curatedRelation}) isa ${curatedRelation}; $${curatedRelation} has ${field} $order;` +
          `not { ($rel, $compare) isa ${curatedRelation}; $compare has ${field} $conn-order; $conn-order > $order; };`
      );
    }
  } else if (orderBy) {
    attributesFields.push(`$rel has ${orderBy} $order;`);
  }
  // Handle every filters
  if (search) {
    for (let searchIndex = 0; searchIndex < searchFields.length; searchIndex += 1) {
      const searchFieldName = searchFields[searchIndex];
      attributesFields.push(`$to has ${searchFieldName} $${searchFieldName};`);
    }
    const searchFilter = R.pipe(
      R.map((e) => `{ $${e} contains "${escapeString(search)}"; }`),
      R.join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  if (elementId) attributesFilters.push(`$element has internal_id "${escapeString(elementId)}";`);
  if (fromId) attributesFilters.push(`$from has internal_id "${escapeString(fromId)}";`);
  if (toId) attributesFilters.push(`$to has internal_id "${escapeString(toId)}";`);
  if (startTimeStart || startTimeStop) {
    attributesFields.push(`$rel has start_time $fs;`);
    if (startTimeStart) attributesFilters.push(`$fs > ${prepareDate(startTimeStart)};`);
    if (startTimeStop) attributesFilters.push(`$fs < ${prepareDate(startTimeStop)};`);
  }
  if (stopTimeStart || stopTimeStop) {
    attributesFields.push(`$rel has stop_time $ls;`);
    if (stopTimeStart) attributesFilters.push(`$ls > ${prepareDate(stopTimeStart)};`);
    if (stopTimeStop) attributesFilters.push(`$ls < ${prepareDate(stopTimeStop)};`);
  }
  if (firstSeenStart || firstSeenStop) {
    attributesFields.push(`$rel has first_seen $fs;`);
    if (firstSeenStart) attributesFilters.push(`$fs > ${prepareDate(firstSeenStart)};`);
    if (firstSeenStop) attributesFilters.push(`$fs < ${prepareDate(firstSeenStop)};`);
  }
  if (lastSeenStart || lastSeenStop) {
    attributesFields.push(`$rel has last_seen $ls;`);
    if (lastSeenStart) attributesFilters.push(`$ls > ${prepareDate(lastSeenStart)};`);
    if (lastSeenStop) attributesFilters.push(`$ls < ${prepareDate(lastSeenStop)};`);
  }
  if (confidences && confidences.length > 0) {
    attributesFields.push(`$rel has confidence $confidence;`);
    // eslint-disable-next-line prettier/prettier
    attributesFilters.push(
      R.pipe(
        R.map((e) => `{ $confidence == ${e}; }`),
        R.join(' or '),
        R.concat(__, ';')
      )(confidences)
    );
  }
  const relationRef = relationFilter ? 'relationRef' : null;
  if (relationFilter) {
    // eslint-disable-next-line no-shadow
    const { relation, fromRole: fromRoleFilter, toRole: toRoleFilter, id, relationId } = relationFilter;
    const pEid = escapeString(id);
    const relationQueryPart = `$${relationRef}(${fromRoleFilter}:$rel, ${toRoleFilter}:$pointer) isa ${relation}; $pointer has internal_id "${pEid}";`;
    relationsFields.push(relationQueryPart);
    if (relationId) {
      attributesFilters.push(`$rel has internal_id "${escapeString(relationId)}";`);
    }
  }
  if (filters.length > 0) {
    // eslint-disable-next-line
    for (const f of filters) {
      if (!R.includes(REL_CONNECTED_SUFFIX, f.key)) {
        throw FunctionalError('Filters only support connected target filtering');
      }
      // eslint-disable-next-line prettier/prettier
      const filterKey = f.key.replace(REL_INDEX_PREFIX, '').replace(REL_CONNECTED_SUFFIX, '').split('.');
      const [key, val] = filterKey;
      const queryFilters = R.pipe(
        R.map((e) => `{ $${key} has ${val} ${f.operator === 'match' ? 'contains' : ''} "${escapeString(e)}"; }`),
        R.join(' or '),
        R.concat(__, ';')
      )(f.values);
      attributesFilters.push(queryFilters);
    }
  }
  // Build the query
  const queryAttributesFields = R.join(' ', attributesFields);
  const queryAttributesFilters = R.join(' ', attributesFilters);
  const queryRelationsFields = R.join(' ', relationsFields);
  let querySource;
  if (elementId) {
    querySource = `$rel($element)`;
  } else {
    querySource = askForConnections
      ? `$rel(${fromRole ? `${fromRole}:` : ''}$from, ${toRole ? `${toRole}:` : ''}$to)`
      : '$rel';
  }
  const baseQuery = `match ${querySource} isa ${relationToGet}; 
  ${queryFromTypes} ${queryToTypes} ${queryRelationsFields} ${queryAttributesFields} ${queryAttributesFilters} get;`;
  const listArgs = R.assoc('inferred', useInference, args);
  return listElements(baseQuery, 'rel', first, offset, listArgs);
};
// endregion

// region Loader element
const findElementById = async (ids, type, args = {}) => {
  const qType = type || 'thing';
  const workingIds = Array.isArray(ids) ? ids : [ids];
  const searchIds = R.map((id) => {
    const eid = escapeString(id);
    return `{ $x has internal_id "${eid}";} or { $x has standard_id "${eid}";} or { $x has stix_ids "${eid}";}`;
  }, workingIds);
  const attrIds = searchIds.join(' or ');
  const query = `match $x isa ${qType}; ${attrIds}; get;`;
  const elements = await find(query, ['x'], args);
  return R.map((t) => t.x, elements);
};
const loadElementById = async (ids, type, args = {}) => {
  const elements = await findElementById(ids, type, args);
  if (elements.length > 1) {
    throw DatabaseError('Expect only one response', { ids, type, hits: elements.length });
  }
  return R.head(elements);
};
const internalFindByIds = (ids, args = {}) => {
  const { type } = args;
  if (useCache(args)) return elFindByIds(ids, type);
  return findElementById(ids, type, args);
};
export const internalLoadById = (id, args = {}) => {
  const { type } = args;
  if (useCache(args)) return elLoadByIds(id, type);
  return loadElementById(id, type, args);
};
export const loadById = async (id, type, args = {}) => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError(`You need to specify a type when loading a element`);
  }
  const loadArgs = R.assoc('type', type, args);
  return internalLoadById(id, loadArgs);
};
// endregion

// region Indexer
export const reindexAttributeValue = async (queryType, type, value) => {
  const index = inferIndexFromConceptType(queryType);
  const readQuery = `match $x isa ${queryType}, has ${escape(type)} $a, has internal_id $x_id; $a "${escapeString(
    value
  )}"; get;`;
  logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: readQuery });
  const elementIds = await executeRead(async (rTx) => {
    const iterator = await rTx.query(readQuery, { infer: false });
    const answer = await iterator.collect();
    return answer.map((n) => n.get('x_id').value());
  });
  let body;
  if (R.includes(type, multipleAttributes)) {
    body = elementIds.flatMap((id) => [{ update: { _index: index, _id: id } }, { doc: { [type]: [value] } }]);
  } else {
    body = elementIds.flatMap((id) => [{ update: { _index: index, _id: id } }, { doc: { [type]: value } }]);
  }
  if (body.length > 0) {
    await elBulk({ refresh: true, body });
  }
};
// endregion

// region Graphics
const buildAggregationQuery = (entityType, filters, options) => {
  const { operation, field, interval, startDate, endDate } = options;
  let baseQuery = `match $from isa ${entityType}; ${startDate || endDate ? `$from has ${field} $created;` : ''}`;
  if (startDate) baseQuery = `${baseQuery} $created > ${prepareDate(startDate)};`;
  if (endDate) baseQuery = `${baseQuery} $created < ${prepareDate(endDate)};`;
  const filterQuery = R.pipe(
    R.map((filterElement) => {
      const { isRelation, value, start, end, type } = filterElement;
      const eValue = `${escapeString(value)}`;
      if (isRelation) {
        const fromRole = `${type}_from`;
        const toRole = `${type}_to`;
        const dateRange =
          start && end
            ? `$rel_${type} has start_time $fs; $fs > ${prepareDate(start)}; $fs < ${prepareDate(end)};`
            : '';
        const relation = `$rel_${type}(${fromRole}:$from, ${toRole}:$${type}_to) isa ${type};`;
        return `${relation} ${dateRange} $${type}_to has internal_id "${eValue}";`;
      }
      return `$from has ${type} "${eValue}";`;
    }),
    R.join('')
  )(filters);
  const groupField = interval ? `${field}_${interval}` : field;
  const groupingQuery = `$from has ${groupField} $g; get; group $g; ${operation};`;
  return `${baseQuery} ${filterQuery} ${groupingQuery}`;
};
const graknTimeSeries = (query, keyRef, valueRef, inferred) => {
  return executeRead(async (rTx) => {
    logger.debug(`[GRAKN - infer: ${inferred}] timeSeries`, { query });
    const iterator = await rTx.query(query, { infer: inferred });
    const answer = await iterator.collect();
    return Promise.all(
      answer.map(async (n) => {
        const owner = await n.owner().value();
        const value = await n.answers()[0].number();
        return { [keyRef]: owner, [valueRef]: value };
      })
    );
  });
};
export const timeSeriesEntities = async (entityType, filters, options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid } ]
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, operation, field, interval, noCache = false, inferred = false } = options;
  // Check if can be supported by ES
  let histogramData;
  if (!noCache && operation === 'count' && !inferred) {
    histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);
  } else {
    // If not compatible, do it with grakn
    const finalQuery = buildAggregationQuery(entityType, filters, options);
    histogramData = await graknTimeSeries(finalQuery, 'date', 'value', inferred);
  }
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesRelations = async (options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid }
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, operation, relationship_type: relationshipType, field, interval } = options;
  const { fromId, noCache = false, inferred = false } = options;
  // Check if can be supported by ES
  let histogramData;
  const entityType = relationshipType ? escape(relationshipType) : 'stix-relationship';
  if (!noCache && operation === 'count' && inferred === false) {
    const filters = [];
    if (fromId) filters.push({ isRelation: false, type: 'connections.internal_id', value: fromId });
    histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);
  } else {
    const query = `match $x ${fromId ? '($from)' : ''} isa ${entityType}; ${
      fromId ? `$from has internal_id "${escapeString(fromId)}";` : ''
    }`;
    const finalQuery = `${query} $x has ${field}_${interval} $g; get; group $g; ${operation};`;
    histogramData = await graknTimeSeries(finalQuery, 'date', 'value', inferred);
  }
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionEntities = async (entityType, filters = [], options) => {
  // filters: { isRelation: true, type: stix_relation, start: date, end: date, value: uuid }
  const { noCache = false, inferred = false, limit = 10, order = 'asc' } = options;
  const { startDate, endDate, field, operation } = options;
  let distributionData;
  // Unsupported in cache: const { isRelation, value, from, to, start, end, type };
  if (field.includes('.')) {
    throw FunctionalError('Distribution entities doesnt support relation aggregation field');
  }
  const supportedFilters = R.filter((f) => f.start || f.end || f.from || f.to, filters).length === 0;
  if (!noCache && operation === 'count' && supportedFilters && inferred === false) {
    distributionData = await elAggregationCount(entityType, field, startDate, endDate, filters);
  } else {
    const finalQuery = buildAggregationQuery(entityType, filters, options);
    distributionData = await graknTimeSeries(finalQuery, 'label', 'value', inferred);
  }
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionRelations = async (options) => {
  const { field, operation } = options; // Mandatory fields
  const { fromId = null, limit = 50, order, noCache = false, inferred = false } = options;
  const { startDate, endDate, relationship_type: relationshipType, toTypes = [] } = options;
  let distributionData;
  const entityType = relationshipType ? escape(relationshipType) : ABSTRACT_STIX_RELATIONSHIP;
  let dateAttribute = 'start_time';
  if (isStixMetaRelationship(entityType)) {
    dateAttribute = 'created_at';
  }
  // Using elastic can only be done if the distribution is a count on types
  if (!noCache && field === 'entity_type' && operation === 'count' && inferred === false) {
    distributionData = await elAggregationRelationsCount(entityType, startDate, endDate, toTypes, fromId);
  } else {
    const query = `match $rel($from, $to) isa ${entityType}; ${
      toTypes && toTypes.length > 0
        ? `${R.join(
            ' ',
            R.map((toType) => `{ $to isa ${escape(toType)}; } or`, toTypes)
          )} { $to isa ${escape(R.head(toTypes))}; };`
        : ''
    } ${fromId ? ` $from has internal_id "${escapeString(fromId)}"; ` : ''}
    ${
      startDate && endDate
        ? `$rel has ${dateAttribute} $fs; $fs > ${prepareDate(startDate)}; $fs < ${prepareDate(endDate)};`
        : ''
    }
      $to has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
    distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  }
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field === 'internal_id') {
    const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
    return R.map((n) => R.assoc('entity', internalLoadById(n.label), n), data);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionEntitiesThroughRelations = async (options) => {
  const { limit = 10, order, inferred = false } = options;
  const { relationshipType, remoteRelationshipType, toType, fromId, field, operation } = options;
  let query = `match $rel($from, $to) isa ${relationshipType}; $to isa ${toType};`;
  query += `$from has internal_id "${escapeString(fromId)}";`;
  query += `$rel2($to, $to2) isa ${remoteRelationshipType};`;
  query += `$to2 has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
  const distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
// endregion

// region mutation common
const prepareAttribute = (key, value) => {
  if (isDictionaryAttribute(key)) return `"${escapeString(JSON.stringify(value))}"`;
  // Attribute is coming from GraphQL
  if (value instanceof Date) return prepareDate(value);
  // Attribute is coming from internal
  if (Date.parse(value) > 0 && new Date(value).toISOString() === value) return prepareDate(value);
  // TODO @Sam Delete that
  if (/^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z)$/.test(value))
    return prepareDate(value);
  if (/^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\dZ$/.test(value)) return prepareDate(value);
  if (typeof value === 'string') return `"${escapeString(value)}"`;
  return escape(value);
};
const flatAttributesForObject = (data) => {
  const elements = Object.entries(data);
  return R.pipe(
    R.map((elem) => {
      const key = R.head(elem);
      const value = R.last(elem);
      if (Array.isArray(value)) {
        return R.map((iter) => ({ key, value: iter }), value);
      }
      // Some dates needs to detailed for search
      if (value && R.includes(key, statsDateAttributes)) {
        return [
          { key, value },
          { key: `${key}_day`, value: dayFormat(value) },
          { key: `${key}_month`, value: monthFormat(value) },
          { key: `${key}_year`, value: yearFormat(value) },
        ];
      }
      return { key, value };
    }),
    R.flatten,
    R.filter((f) => f.value !== undefined)
  )(elements);
};
const depsKeys = [
  { src: 'fromId', dst: 'from' },
  { src: 'toId', dst: 'to' },
  { src: 'createdBy' },
  { src: 'objectMarking' },
  { src: 'objectLabel' },
  { src: 'killChainPhases' },
  { src: 'externalReferences' },
  { src: 'objects' },
];
const inputResolveRefs = async (input) => {
  const deps = [];
  let expectedSize = 0;
  for (let index = 0; index < depsKeys.length; index += 1) {
    const { src, dst } = depsKeys[index];
    const destKey = dst || src;
    let id = input[src];
    if (!R.isNil(id) && !R.isEmpty(id)) {
      const isListing = Array.isArray(id);
      if (isListing) id = R.uniq(id); // We can have duplicate due to id generaton (external ref for example)
      expectedSize += isListing ? id.length : 1;
      // Handle specific case of object label that can be directly the value instead of the key.
      if (src === 'objectLabel') {
        id = R.map((label) => (isAnId(label) ? label : generateStandardId(ENTITY_TYPE_LABEL, { value: label })), id);
      }
      const keyPromise = isListing ? internalFindByIds(id) : internalLoadById(id);
      const dataPromise = keyPromise.then((data) => ({ [destKey]: data }));
      deps.push(dataPromise);
    }
  }
  const resolved = await Promise.all(deps);
  const resolvedCount = R.sum(
    R.map((r) => {
      const [, val] = R.head(Object.entries(r));
      if (!val || val.length === 0) return 0;
      return Array.isArray(val) ? R.uniq(val).length : 1;
    }, resolved)
  );
  const patch = R.mergeAll(resolved);
  if (expectedSize !== resolvedCount) {
    throw MissingReferenceError({ input, resolved });
  }
  return R.mergeRight(input, patch);
};
// endregion

// region mutation update
const innerUpdateAttribute = async (user, instance, rawInput, wTx, options = {}) => {
  const { id } = instance;
  const { forceUpdate = false, operation = EVENT_TYPE_UPDATE } = options;
  const { key, value } = rawInput; // value can be multi valued
  // Format the data in regards of the operation for multiple attributes
  const isMultiple = R.includes(key, multipleAttributes);
  let finalVal;
  let finalKey = key;
  if (dictAttributes[key]) {
    throw UnsupportedError('Dictionary attribute cant be updated directly', { rawInput });
  }
  if (key.includes('.')) {
    // In case of dict attributes, patching the content is possible through first level path
    const splitKey = key.split('.');
    if (splitKey.length > 2) {
      throw UnsupportedError('Multiple path follow is not supported', { rawInput });
    }
    const [baseKey, targetKey] = splitKey;
    if (!dictAttributes[baseKey]) {
      throw UnsupportedError('Path update only available for dictionary attributes', { rawInput });
    }
    finalKey = baseKey;
    const currentJson = instance[baseKey];
    const valueToTake = R.head(value);
    if (currentJson[targetKey] === valueToTake) {
      return []; // No need to update the attribute
    }
    // If data is empty, remove the key
    if (R.isEmpty(valueToTake) || R.isNil(valueToTake)) {
      finalVal = [R.dissoc(targetKey, currentJson)];
    } else {
      finalVal = [R.assoc(targetKey, valueToTake, currentJson)];
    }
  } else if (isMultiple) {
    const currentValues = instance[key] || [];
    if (operation === EVENT_TYPE_UPDATE_ADD) {
      finalVal = R.pipe(R.append(value), R.flatten, R.uniq)(currentValues);
    } else if (operation === EVENT_TYPE_UPDATE_REMOVE) {
      finalVal = R.filter((n) => !R.includes(n, value), currentValues);
    } else {
      finalVal = value;
    }
    if (!forceUpdate && R.equals(finalVal.sort(), currentValues.sort())) {
      return []; // No need to update the attribute
    }
  } else {
    finalVal = value;
    if (!forceUpdate && R.equals(instance[key], R.head(value))) {
      return []; // No need to update the attribute
    }
  }
  const input = { key: finalKey, value: finalVal };
  const updatedInputs = [input];
  // --- 01 Get the current attribute types
  const escapedKey = escape(input.key);
  const labelTypeQuery = `match $x type ${escapedKey}; get;`;
  const labelIterator = await wTx.query(labelTypeQuery);
  const labelAnswer = await labelIterator.next();
  // eslint-disable-next-line prettier/prettier
  const ansConcept = labelAnswer.map().get('x');
  const attrType = await ansConcept.asRemote(wTx).valueType();
  const typedValues = R.map((v) => {
    if (isDictionaryAttribute(input.key)) return `"${escapeString(JSON.stringify(v))}"`;
    if (attrType === GraknString) return `"${escapeString(v)}"`;
    if (attrType === GraknDate) return prepareDate(v);
    return escape(v);
  }, input.value);
  // --- Delete the old attribute reference of the entity
  const entityId = `${escapeString(id)}`;
  const deleteQuery = `match $x has internal_id "${entityId}", has ${escapedKey} $del; delete $x has ${escapedKey} $del;`;
  logger.debug(`[GRAKN - infer: false] updateAttribute - delete reference`, { query: deleteQuery });
  await wTx.query(deleteQuery);
  // --- Delete the entire attribute if its now an orphan
  // Disable waiting for grakn 2.0 - https://github.com/graknlabs/grakn/issues/5296
  // const orphanQuery = `match $x isa ${escapedKey}; not { $y has ${escapedKey} $x; }; delete $x isa ${escapedKey};`;
  // logger.debug(`[GRAKN - infer: false] updateAttribute - delete orphan`, { query: deleteQuery });
  // await wTx.query(orphanQuery);
  if (typedValues.length > 0) {
    let graknValues;
    if (typedValues.length === 1) {
      graknValues = `has ${escapedKey} ${R.head(typedValues)}`;
    } else {
      graknValues = `${R.join(
        ' ',
        R.map((gVal) => `has ${escapedKey} ${gVal},`, R.tail(typedValues))
      )} has ${escapedKey} ${R.head(typedValues)}`;
    }
    const createQuery = `match $x has internal_id "${entityId}"; insert $x ${graknValues};`;
    logger.debug(`[GRAKN - infer: false] updateAttribute - insert`, { query: createQuery });
    await wTx.query(createQuery);
  }
  // Adding dates elements
  const updateOperations = [];
  if (R.includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(R.head(input.value));
    const monthValue = monthFormat(R.head(input.value));
    const yearValue = yearFormat(R.head(input.value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    updatedInputs.push(dayInput);
    updateOperations.push(innerUpdateAttribute(user, instance, dayInput, wTx));
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    updatedInputs.push(monthInput);
    updateOperations.push(innerUpdateAttribute(user, instance, monthInput, wTx));
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    updatedInputs.push(yearInput);
    updateOperations.push(innerUpdateAttribute(user, instance, yearInput, wTx));
  }
  // Update modified / updated_at
  if (isStixDomainObject(instance.entity_type) && key !== 'modified' && key !== 'updated_at') {
    const today = now();
    const updatedAtInput = { key: 'updated_at', value: [today] };
    updatedInputs.push(updatedAtInput);
    updateOperations.push(innerUpdateAttribute(user, instance, updatedAtInput, wTx));
    const modifiedAtInput = { key: 'modified', value: [today] };
    updatedInputs.push(modifiedAtInput);
    updateOperations.push(innerUpdateAttribute(user, instance, modifiedAtInput, wTx));
  }
  // Update created
  if (instance.entity_type === ENTITY_TYPE_CONTAINER_REPORT && key === 'published') {
    const createdInput = { key: 'created', value: input.value };
    updatedInputs.push(createdInput);
    updateOperations.push(innerUpdateAttribute(user, instance, createdInput, wTx));
  }
  await Promise.all(updateOperations);
  return updatedInputs;
};

const mergeInstanceWithInputs = (instance, inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value } = input;
    const val = R.includes(key, multipleAttributes) ? value : R.head(value);
    return { [key]: val };
  }, inputs);
  const updatedData = R.mergeAll(inputPairs);
  return R.mergeRight(instance, updatedData);
};
export const updateAttribute = async (user, id, type, inputs, options = {}) => {
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const { noLog = false, operation = EVENT_TYPE_UPDATE } = options;
  if (operation !== EVENT_TYPE_UPDATE && elements.length > 1) {
    throw FunctionalError(`Unsupported operation`, { operation, elements });
  }
  // const { noLog = false } = options;
  const instance = await loadById(id, type, options);
  if (!instance) {
    throw FunctionalError(`Cant find element to update`, { id, type });
  }
  // --- take lock, ensure no one currently create or update this element
  let lock;
  const updatedInputs = [];
  try {
    // Try to get the lock in redis
    lock = await lockResource(instance.internal_id);
    await executeWrite(async (wTx) => {
      // Update all needed attributes
      for (let index = 0; index < elements.length; index += 1) {
        const input = elements[index];
        // eslint-disable-next-line no-await-in-loop
        const ins = await innerUpdateAttribute(user, instance, input, wTx, options);
        updatedInputs.push(...ins);
      }
      // If update is part of the key, update the standard_id
      const instanceType = instance.entity_type;
      const isRelation = instance.base_type === BASE_TYPE_RELATION;
      const keys = R.map((t) => t.key, updatedInputs);
      if (!isRelation && isFieldContributingToStandardId(instanceType, keys)) {
        const updatedInstance = mergeInstanceWithInputs(instance, updatedInputs);
        const standardId = generateStandardId(instanceType, updatedInstance);
        const standardInput = { key: 'standard_id', value: [standardId] };
        // eslint-disable-next-line no-await-in-loop
        const ins = await innerUpdateAttribute(user, instance, standardInput, wTx, options);
        // currentInstanceData = R.assoc('standard_id', standardId, currentInstanceData);
        updatedInputs.push(...ins);
      }
    });
    // Update elasticsearch and send logs
    const postOperations = [];
    const index = inferIndexFromConceptType(instance.entity_type);
    const updateAsObject = R.mergeAll(
      R.map(({ key, value }) => ({ [key]: isMultipleAttribute(key) ? value : R.head(value) }), updatedInputs)
    );
    const esData = prepareElementForIndexing(updateAsObject);
    postOperations.push(elUpdate(index, instance.internal_id, { doc: esData }));
    const dataToLogSend = R.filter((input) => input.key !== 'x_opencti_graph_data', elements);
    if (!noLog && !R.isEmpty(dataToLogSend)) {
      const baseData = {
        standard_id: instance.standard_id,
        internal_id: instance.id,
        entity_type: instance.entity_type,
        spec_version: instance.spec_version,
      };
      let from;
      let to;
      if (instance.base_type === BASE_TYPE_RELATION) {
        const fromPromise = internalLoadById(instance.fromId);
        const toPromise = internalLoadById(instance.toId);
        const [fromEntity, toEntity] = await Promise.all([fromPromise, toPromise]);
        from = fromEntity;
        to = toEntity;
      }
      // eslint-disable-next-line no-restricted-syntax
      for (const dataLog of dataToLogSend) {
        postOperations.push(sendLog(operation, user, baseData, { key: dataLog.key, value: dataLog.value, from, to }));
      }
    }
    // Wait for all
    await Promise.all(postOperations);
  } finally {
    if (lock) await lock.unlock();
  }
  // Return fully updated instance
  return mergeInstanceWithInputs(instance, updatedInputs);
};

export const patchAttribute = async (user, id, type, patch, options = {}) => {
  const inputs = R.pipe(
    R.toPairs,
    R.map((t) => {
      const val = R.last(t);
      return { key: R.head(t), value: Array.isArray(val) ? val : [val] };
    })
  )(patch);
  return updateAttribute(user, id, type, inputs, options);
};
// endregion

// region mutation relation
const upsertRelation = async (user, relationship, type, data) => {
  if (!R.isNil(data.stix_id) && relationship.stix_ids.length < 3) {
    const id = relationship.internal_id;
    const patch = { stix_ids: [data.stix_id] };
    return patchAttribute(user, id, type, patch, { operation: EVENT_TYPE_UPDATE_ADD });
  }
  return relationship;
};
const addInnerRelation = async (user, from, to, type, opts) => {
  const targets = Array.isArray(to) ? to : [to];
  if (!to || R.isEmpty(targets)) return undefined;
  const relations = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i];
    const input = { from, to: target, relationship_type: type };
    // eslint-disable-next-line no-await-in-loop,no-use-before-define
    const rel = await createRelationRaw(user, input, opts);
    relations.push(rel);
  }
  return relations;
};
const createRelationRaw = async (user, input, opts = {}) => {
  const { from, to, relationship_type: relationshipType } = input;
  const { noLog = false } = opts;
  // 03. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // 04. Check existing relationship
  const listingArgs = { fromId: from.internal_id, toId: to.internal_id };
  if (isStixCoreRelationship(relationshipType)) {
    if (!R.isNil(input.start_time)) {
      listingArgs.startTimeStart = prepareDate(moment(input.start_time).subtract(1, 'months').utc());
      listingArgs.startTimeStop = prepareDate(moment(input.start_time).add(1, 'months').utc());
    }
    if (!R.isNil(input.stop_time)) {
      listingArgs.stopTimeStart = prepareDate(moment(input.stop_time).subtract(1, 'months'));
      listingArgs.stopTimeStop = prepareDate(moment(input.stop_time).add(1, 'months'));
    }
  } else if (isStixSightingRelationship(relationshipType)) {
    if (!R.isNil(input.first_seen)) {
      listingArgs.firstSeenStart = prepareDate(moment(input.first_seen).subtract(1, 'months').utc());
      listingArgs.firstSeenStop = prepareDate(moment(input.first_seen).add(1, 'months').utc());
    }
    if (!R.isNil(input.last_seen)) {
      listingArgs.lastSeenStart = prepareDate(moment(input.last_seen).subtract(1, 'months'));
      listingArgs.lastSeenStop = prepareDate(moment(input.last_seen).add(1, 'months'));
    }
  }
  const existingRelationships = await listRelations(relationshipType, listingArgs);
  let existingRelationship = null;
  if (existingRelationships.edges.length > 0) {
    existingRelationship = R.head(existingRelationships.edges).node;
  }
  if (existingRelationship) {
    return upsertRelation(user, existingRelationship, relationshipType, input);
  }
  // 05. Prepare the relation to be created
  const today = now();
  let relationAttributes = {};
  // Default attributes
  // basic-relationship
  relationAttributes.internal_id = internalId;
  relationAttributes.standard_id = standardId;
  relationAttributes.entity_type = relationshipType;
  relationAttributes.created_at = today;
  relationAttributes.updated_at = today;
  // stix-relationship
  if (isStixRelationShipExceptMeta(relationshipType)) {
    relationAttributes.stix_ids = R.isNil(input.stix_id) ? [] : [input.stix_id];
    relationAttributes.spec_version = STIX_SPEC_VERSION;
    relationAttributes.revoked = R.isNil(input.revoked) ? false : input.revoked;
    relationAttributes.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
    relationAttributes.lang = R.isNil(input.lang) ? 'en' : input.lang;
    relationAttributes.created = R.isNil(input.created) ? today : input.created;
    relationAttributes.modified = R.isNil(input.modified) ? today : input.modified;
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    relationAttributes.relationship_type = relationshipType;
    relationAttributes.description = input.description ? input.description : '';
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-observable-relationship
  if (isStixCyberObservableRelationship(relationshipType)) {
    relationAttributes.relationship_type = relationshipType;
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-sighting-relationship
  if (isStixSightingRelationship(relationshipType)) {
    relationAttributes.description = R.isNil(input.description) ? '' : input.description;
    relationAttributes.attribute_count = R.isNil(input.attribute_count) ? 1 : input.attribute_count;
    relationAttributes.x_opencti_negative = R.isNil(input.x_opencti_negative) ? false : input.x_opencti_negative;
    relationAttributes.first_seen = R.isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen;
    relationAttributes.last_seen = R.isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen;
    /* istanbul ignore if */
    if (relationAttributes.first_seen > relationAttributes.last_seen) {
      throw DatabaseError('You cant create a relation with a first_seen less than the last_seen', {
        from: input.fromId,
        input,
      });
    }
  }
  // Add the additional fields for dates (day, month, year)
  const dataKeys = Object.keys(relationAttributes);
  for (let index = 0; index < dataKeys.length; index += 1) {
    // Adding dates elements
    if (R.includes(dataKeys[index], statsDateAttributes)) {
      const dayValue = dayFormat(relationAttributes[dataKeys[index]]);
      const monthValue = monthFormat(relationAttributes[dataKeys[index]]);
      const yearValue = yearFormat(relationAttributes[dataKeys[index]]);
      relationAttributes = R.pipe(
        R.assoc(`${dataKeys[index]}_day`, dayValue),
        R.assoc(`${dataKeys[index]}_month`, monthValue),
        R.assoc(`${dataKeys[index]}_year`, yearValue)
      )(relationAttributes);
    }
  }
  // 04. Create the relation
  const fromRole = `${relationshipType}_from`;
  const toRole = `${relationshipType}_to`;
  await executeWrite(async (wTx) => {
    // Build final query
    let query = `match $from isa ${input.fromType ? input.fromType : 'thing'}; 
      $from has internal_id "${from.internal_id}"; $to has internal_id "${to.internal_id}";
      insert $rel(${fromRole}: $from, ${toRole}: $to) isa ${relationshipType},`;
    const queryElements = flatAttributesForObject(relationAttributes);
    const nbElements = queryElements.length;
    for (let index = 0; index < nbElements; index += 1) {
      const { key, value } = queryElements[index];
      const insert = prepareAttribute(key, value);
      const separator = index + 1 === nbElements ? ';' : ',';
      query += `has ${key} ${insert}${separator} `;
    }
    logger.debug(`[GRAKN - infer: false] createRelation`, { query });
    const iterator = await wTx.query(query);
    const txRelation = await iterator.next();
    if (txRelation === null) {
      throw MissingReferenceError({ input });
    }
  });
  // 06. Prepare the final data with Grakn IDs
  const created = R.pipe(
    R.assoc('id', internalId),
    R.assoc('fromId', from.internal_id),
    R.assoc('fromRole', fromRole),
    R.assoc('fromType', from.entity_type),
    R.assoc('toId', to.internal_id),
    R.assoc('toRole', toRole),
    R.assoc('toType', to.entity_type),
    // Relation specific
    R.assoc('inferred', false),
    // Types
    R.assoc('entity_type', relationshipType),
    R.assoc('parent_types', getParentTypes(relationshipType)),
    R.assoc('base_type', BASE_TYPE_RELATION)
  )(relationAttributes);
  const postOperations = [];
  // 07. Index the relation and the modification in the base entity
  postOperations.push(elIndexElements([created]));
  // 08. Send logs
  if (!noLog) {
    if (isStixMetaRelationship(relationshipType)) {
      const eventType = relationshipType === RELATION_CREATED_BY ? EVENT_TYPE_UPDATE : EVENT_TYPE_UPDATE_ADD;
      postOperations.push(sendLog(eventType, user, created, { from, to }));
    } else {
      postOperations.push(sendLog(EVENT_TYPE_CREATE, user, created, { from, to }));
    }
  }
  // Complete with eventual relations (will eventually update the index)
  if (isStixCoreRelationship(relationshipType)) {
    postOperations.push(
      addInnerRelation(user, created, input.createdBy, RELATION_CREATED_BY, opts),
      addInnerRelation(user, created, input.objectMarking, RELATION_OBJECT_MARKING, opts),
      addInnerRelation(user, created, input.killChainPhases, RELATION_KILL_CHAIN_PHASE, opts)
    );
  }
  await Promise.all(postOperations);
  // 09. Return result if no need to reverse the relations from and to
  return created;
};
export const createRelation = async (user, input, opts = {}) => {
  let lock;
  const { fromId, toId, relationship_type: relationshipType } = input;
  if (fromId === toId) {
    /* istanbul ignore next */
    throw UnsupportedError(`You cant create a relation with the same source and target`, {
      from: input.fromId,
      relationshipType,
    });
  }
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(input);
  const { from, to } = resolvedInput;
  // Build lock ids
  const lockFrom = `${from.standard_id}_${relationshipType}_${to.standard_id}`;
  const lockTo = `${to.standard_id}_${relationshipType}_${from.standard_id}`;
  const lockIds = [lockFrom, lockTo];
  if (!R.isNil(resolvedInput.stix_id)) lockIds.push(resolvedInput.stix_id);
  try {
    // Try to get the lock in redis
    lock = await lockResource(lockIds);
    // noinspection UnnecessaryLocalVariableJS
    const creation = await createRelationRaw(user, resolvedInput, opts);
    // Return created element after waiting for it.
    return creation;
  } catch (err) {
    if (err.name === TYPE_DUPLICATE_ENTRY) {
      logger.warn(err.message, { input, ...err.data });
      const existingRelationship = loadById(err.data.id, input.relationship_type);
      return upsertRelation(user, existingRelationship, input.relationship_type, input);
    }
    if (err.name === TYPE_LOCK_ERROR) {
      throw DatabaseError('Operation still in progress (redis lock)', { lockIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
/* istanbul ignore next */
export const createRelations = async (user, inputs, opts = {}) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improve by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const relation = await createRelation(user, inputs[i], opts);
    createdRelations.push(relation);
  }
  return createdRelations;
};
// endregion

// region mutation entity
const upsertEntity = async (user, entity, type, data) => {
  if (!R.isNil(data.stix_id) && entity.stix_ids.length < 5) {
    const id = entity.internal_id;
    const patch = { stix_ids: [data.stix_id] };
    return patchAttribute(user, id, type, patch, { operation: EVENT_TYPE_UPDATE_ADD });
  }
  return entity;
};
const createRawEntity = async (user, standardId, input, type, opts = {}) => {
  const { noLog = false } = opts;
  // Generate the internal id
  const internalId = input.internal_id || generateInternalId();
  // Check if the entity exists
  const participantIds = R.isNil(input.stix_id) ? [standardId] : [input.stix_id, standardId];
  const existingEntity = await internalLoadById(participantIds);
  if (existingEntity) {
    return upsertEntity(user, existingEntity, type, input);
  }
  // Complete with identifiers
  const today = now();
  // Dissoc additional data
  let data = R.pipe(
    R.assoc('internal_id', internalId),
    R.assoc('entity_type', type),
    R.dissoc('update'),
    R.dissoc('createdBy'),
    R.dissoc('objectMarking'),
    R.dissoc('objectLabel'),
    R.dissoc('killChainPhases'),
    R.dissoc('externalReferences'),
    R.dissoc('objects')
  )(input);
  // Default attributes
  // Internal-Object
  if (isInternalObject(type)) {
    data = R.assoc('standard_id', standardId, data);
  }
  // Some internal objects have dates
  if (isDatedInternalObject(type)) {
    data = R.pipe(R.assoc('created_at', today), R.assoc('updated_at', today))(data);
  }
  // Stix-Object
  if (isStixObject(type)) {
    data = R.pipe(
      R.assoc('standard_id', standardId),
      R.assoc('stix_ids', R.isNil(input.stix_id) ? [] : [input.stix_id]),
      R.dissoc('stix_id'),
      R.assoc('spec_version', STIX_SPEC_VERSION),
      R.assoc('created_at', today),
      R.assoc('updated_at', today)
    )(data);
  }
  // Stix-Meta-Object
  if (isStixMetaObject(type)) {
    data = R.pipe(
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // STIX-Core-Object
  // -- STIX-Domain-Object
  if (isStixDomainObject(type)) {
    data = R.pipe(
      R.assoc('revoked', R.isNil(data.revoked) ? false : data.revoked),
      R.assoc('confidence', R.isNil(data.confidence) ? 0 : data.confidence),
      R.assoc('lang', R.isNil(data.lang) ? 'en' : data.lang),
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // Add the additional fields for dates (day, month, year)
  const dataKeys = Object.keys(data);
  for (let index = 0; index < dataKeys.length; index += 1) {
    // Adding dates elements
    if (R.includes(dataKeys[index], statsDateAttributes)) {
      const dayValue = dayFormat(data[dataKeys[index]]);
      const monthValue = monthFormat(data[dataKeys[index]]);
      const yearValue = yearFormat(data[dataKeys[index]]);
      data = R.pipe(
        R.assoc(`${dataKeys[index]}_day`, dayValue),
        R.assoc(`${dataKeys[index]}_month`, monthValue),
        R.assoc(`${dataKeys[index]}_year`, yearValue)
      )(data);
    }
  }
  // Generate fields for query and build the query
  const queryElements = flatAttributesForObject(data);
  const nbElements = queryElements.length;
  let query = `insert $entity isa ${type}, `;
  for (let index = 0; index < nbElements; index += 1) {
    const { key, value } = queryElements[index];
    const insert = prepareAttribute(key, value);
    const separator = index + 1 === nbElements ? ';' : ',';
    if (!R.isNil(insert) && insert.length !== 0) {
      query += `has ${key} ${insert}${separator} `;
    }
  }
  // Create the input
  await executeWrite(async (wTx) => {
    logger.debug(`[GRAKN - infer: false] createEntity`, { query });
    await wTx.query(query);
  });
  // Transaction succeed, complete the result to send it back
  const created = R.pipe(
    R.assoc('id', internalId),
    R.assoc('base_type', BASE_TYPE_ENTITY),
    R.assoc('parent_types', getParentTypes(type))
  )(data);
  // Transaction succeed, index the result
  try {
    await elIndexElements([created]);
  } catch (err) {
    throw DatabaseError('Cannot index input', { error: err, data: created });
  }
  const postOperations = [];
  // Send creation log
  if (!noLog) postOperations.push(sendLog(EVENT_TYPE_CREATE, user, created));
  // Complete with eventual relations (will eventually update the index)
  if (isStixCoreObject(type)) {
    postOperations.push(
      addInnerRelation(user, created, input.createdBy, RELATION_CREATED_BY, opts),
      addInnerRelation(user, created, input.objectMarking, RELATION_OBJECT_MARKING, opts),
      addInnerRelation(user, created, input.objectLabel, RELATION_OBJECT_LABEL, opts),
      addInnerRelation(user, created, input.killChainPhases, RELATION_KILL_CHAIN_PHASE, opts),
      addInnerRelation(user, created, input.externalReferences, RELATION_EXTERNAL_REFERENCE, opts),
      addInnerRelation(user, created, input.objects, RELATION_OBJECT, opts)
    );
  }
  await Promise.all(postOperations);
  // Simply return the data
  return created;
};
export const createEntity = async (user, input, type, opts = {}) => {
  let lock;
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(input);
  // Generate the internal id
  const standardId = generateStandardId(type, resolvedInput);
  const participantIds = R.isNil(resolvedInput.stix_id) ? standardId : [resolvedInput.stix_id, standardId];
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // noinspection UnnecessaryLocalVariableJS
    const creation = await createRawEntity(user, standardId, resolvedInput, type, opts);
    // Return created element after waiting for it.
    return creation;
  } catch (err) {
    if (err.name === TYPE_DUPLICATE_ENTRY) {
      logger.warn(err.message, { input, ...err.data });
      const existingEntityRefreshed = await loadById(err.data.id, type);
      return upsertEntity(user, existingEntityRefreshed, type, resolvedInput);
    }
    if (err.name === TYPE_LOCK_ERROR) {
      throw DatabaseError('Operation still in progress (redis lock)', { participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
// endregion

const getElementsRelated = async (targetId, elements = [], options = {}) => {
  const eid = escapeString(targetId);
  const read = `match $from has internal_id "${eid}"; $rel($from, $to) isa ${ABSTRACT_BASIC_RELATIONSHIP}; get;`;
  const connectedRelations = await find(read, ['rel'], options);
  const connectedRelationsIds = R.map((r) => {
    const { id, entity_type: entityType } = r.rel;
    return { id, type: entityType, relDependency: true };
  }, connectedRelations);
  elements.push(...connectedRelationsIds);
  await Promise.all(connectedRelationsIds.map(({ id }) => getElementsRelated(id, elements, options)));
  return elements;
};

const deleteElementById = async (elementId, elementType, isRelation, options = {}) => {
  // 00. Load everything we need to remove
  const dependencies = [{ id: elementId, type: elementType, relDependency: isRelation }];
  await getElementsRelated(elementId, dependencies, options);
  // 01. Delete dependencies.
  // Remove all dep in reverse order to handle correctly relations
  for (let i = dependencies.length - 1; i >= 0; i -= 1) {
    const { id, type, relDependency } = dependencies[i];
    // eslint-disable-next-line no-await-in-loop
    await executeWrite(async (wTx) => {
      const query = `match $x has internal_id "${id}"; delete $x isa ${type};`;
      logger.debug(`[GRAKN - infer: false] delete element ${id}`, { query });
      await wTx.query(query, { infer: false });
    }).then(async () => {
      // If element is a relation, modify the impacted from and to.
      if (relDependency) {
        await elRemoveRelationConnection(id);
      }
      // Remove the element itself from the index
      await elDeleteInstanceIds([id]);
    });
  }
};

// region mutation deletion
export const deleteEntityById = async (user, entityId, type, options = {}) => {
  const { noLog = false } = options;
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting an entity`);
  }
  // Check consistency
  const entity = await loadById(entityId, type, options);
  if (entity === null) {
    throw DatabaseError(`Cant find entity to delete ${entityId}`);
  }
  // Delete entity and all dependencies
  await deleteElementById(entityId, entity.entity_type, false, options);
  // Send the log if everything fine
  if (!noLog) {
    await sendLog(EVENT_TYPE_DELETE, user, entity);
  }
  return entityId;
};
export const deleteRelationById = async (user, relationId, type, options = {}) => {
  const { noLog = false } = options;
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting a relation`);
  }
  const relation = await loadById(relationId, type, options);
  if (relation === null) throw DatabaseError(`Cant find relation to delete ${relationId}`);
  await deleteElementById(relationId, relation.entity_type, true, options);
  // Send the log if everything fine
  if (!noLog) {
    const from = await elLoadByIds(relation.fromId);
    const to = await elLoadByIds(relation.toId);
    if (isStixMetaRelationship(relation.entity_type)) {
      if (relation.entity_type === RELATION_CREATED_BY) {
        await sendLog(EVENT_TYPE_UPDATE, user, relation, { from, to });
      } else {
        await sendLog(EVENT_TYPE_UPDATE_REMOVE, user, relation, { from, to });
      }
    } else {
      await sendLog(EVENT_TYPE_DELETE, user, relation, { from, to });
    }
  }
  return relationId;
};
export const deleteRelationsByFromAndTo = async (user, fromId, toId, relationshipType, scopeType, opts = {}) => {
  /* istanbul ignore if */
  if (R.isNil(scopeType)) {
    throw FunctionalError(`You need to specify a scope type when deleting a relation with from and to`);
  }
  const fromThing = await internalLoadById(fromId);
  const toThing = await internalLoadById(toId);
  const read = `match $from has internal_id "${fromThing.internal_id}"; 
    $to has internal_id "${toThing.internal_id}"; 
    $rel($from, $to) isa ${relationshipType}; get;`;
  const relationsToDelete = await find(read, ['rel']);
  for (let i = 0; i < relationsToDelete.length; i += 1) {
    const r = relationsToDelete[i];
    // eslint-disable-next-line no-await-in-loop
    await deleteRelationById(user, r.rel.id, r.rel.entity_type, opts);
  }
};
export const deleteAttributeById = async (id) => {
  return executeWrite(async (wTx) => {
    const query = `match $x id ${escape(id)}; delete $x isa thing;`;
    logger.debug(`[GRAKN - infer: false] deleteAttributeById`, { query });
    await wTx.query(query, { infer: false });
    return id;
  });
};
// endregion

// region inferences
/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @returns {Promise}
 */
export const getRelationInferredById = async (id) => {
  return executeRead(async (rTx) => {
    const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
    const query = `match ${decodedQuery} get;`;
    logger.debug(`[GRAKN - infer: true] getRelationInferredById`, { query });
    const answerIterator = await rTx.query(query, { infer: true, explain: true });
    const answerConceptMap = await answerIterator.next();
    const vars = extractQueryVars(query);
    const concepts = await getConcepts(rTx, [answerConceptMap], vars, [INFERRED_RELATION_KEY], { noCache: true });
    const relation = R.head(concepts).rel;
    const explanation = await answerConceptMap.explanation();
    const explanationAnswers = explanation.getAnswers();
    const inferences = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const explanationAnswer of explanationAnswers) {
      const explanationMap = explanationAnswer.map();
      const explanationKeys = Array.from(explanationMap.keys());
      const queryVars = R.map((v) => ({ alias: v }), explanationKeys);
      const explanationRelationKey = R.last(R.filter((n) => n.includes(INFERRED_RELATION_KEY), explanationKeys));
      // eslint-disable-next-line no-await-in-loop
      const explanationConcepts = await getConcepts(rTx, [explanationAnswer], queryVars, [explanationRelationKey]);
      inferences.push({ node: R.head(explanationConcepts)[explanationRelationKey] });
    }
    return R.pipe(R.assoc('inferences', { edges: inferences }))(relation);
  });
};
// endregion
