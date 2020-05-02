import { v4 as uuid, v5 as uuid5 } from 'uuid';
import {
  __,
  append,
  ascend,
  assoc,
  chain,
  concat,
  descend,
  dissoc,
  equals,
  filter,
  find as Rfind,
  flatten,
  fromPairs,
  groupBy,
  head,
  includes,
  isEmpty,
  isNil,
  join,
  last,
  map,
  mapObjIndexed,
  mergeAll,
  mergeRight,
  pipe,
  pluck,
  prop,
  sortWith,
  split,
  tail,
  take,
  toPairs,
  uniq,
  uniqBy,
} from 'ramda';
import moment from 'moment';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn-client';
import { DatabaseError } from '../config/errors';
import conf, { logger } from '../config/conf';
import {
  buildPagination,
  fillTimeSeries,
  INDEX_STIX_ENTITIES,
  INDEX_STIX_RELATIONS,
  inferIndexFromConceptTypes,
  TYPE_RELATION_EMBEDDED,
  TYPE_STIX_DOMAIN_ENTITY,
  TYPE_STIX_OBSERVABLE,
  TYPE_STIX_OBSERVABLE_RELATION,
  TYPE_STIX_RELATION,
  utcDate,
} from './utils';
import { isInversed, resolveNaturalRoles, ROLE_FROM } from './graknRoles';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elBulk,
  elDeleteInstanceIds,
  elHistogramCount,
  elIndexElements,
  elLoadByGraknId,
  elLoadById,
  elLoadByStixId,
  elPaginate,
  elRemoveRelationConnection,
  elUpdate,
  forceNoCache,
  REL_INDEX_PREFIX,
} from './elasticSearch';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_UPDATE,
  EVENT_TYPE_UPDATE_ADD,
  EVENT_TYPE_UPDATE_REMOVE,
  EVENT_TYPE_DELETE,
  sendLog,
} from './rabbitmq';

// region global variables
const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';
const GraknString = 'String';
const GraknDate = 'Date';

export const REL_CONNECTED_SUFFIX = 'CONNECTED';
export const TYPE_STIX_DOMAIN = 'Stix-Domain';
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

// Attributes key that can contains multiple values.
export const multipleAttributes = ['stix_label', 'alias', 'grant', 'platform', 'required_permission'];
export const statsDateAttributes = ['created_at', 'first_seen', 'last_seen', 'published', 'valid_from', 'valid_until'];
export const readOnlyAttributes = ['observable_value'];
// endregion

// region client
const client = new Grakn(`${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`);
let session = null;
// endregion

// region basic commands
const closeTx = async (gTx) => {
  if (gTx.tx.isOpen()) {
    return gTx.tx.close().catch(
      /* istanbul ignore next */ (err) => {
        logger.error('[GRAKN] CloseReadTx error', { error: err });
      }
    );
  }
  return true;
};
const takeReadTx = async (retry = false) => {
  if (session === null) session = await client.session('grakn');
  return session
    .transaction()
    .read()
    .then((tx) => ({ session, tx }))
    .catch(
      /* istanbul ignore next */ (err) => {
        logger.error('[GRAKN] TakeReadTx error', { error: err });
        if (retry === true) {
          logger.error('[GRAKN] TakeReadTx, retry failed, Grakn seems down, stopping...');
          process.exit(1);
        }
        return takeReadTx(true);
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
    logger.error('[GRAKN] executeRead error', { error: err });
    /* istanbul ignore next */
    throw err;
  }
};

const takeWriteTx = async (retry = false) => {
  if (session === null) session = await client.session('grakn');
  return session
    .transaction()
    .write()
    .then((tx) => ({ session, tx }))
    .catch(
      /* istanbul ignore next */ (err) => {
        logger.error('[GRAKN] TakeWriteTx error', { error: err });
        if (retry === true) {
          logger.error('[GRAKN] TakeWriteTx, retry failed, Grakn seems down, stopping...');
          process.exit(1);
        }
        return takeWriteTx(true);
      }
    );
};
const commitWriteTx = async (wTx) => {
  return wTx.tx.commit().catch(
    /* istanbul ignore next */ (err) => {
      logger.error('[GRAKN] CommitWriteTx error', { error: err });
      if (err.code === 3) {
        throw new DatabaseError({
          data: { details: split('\n', err.details)[1] },
        });
      }
      throw new DatabaseError({ data: { details: err.details } });
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
    logger.error('[GRAKN] executeWrite error', { error: err });
    /* istanbul ignore next */
    throw err;
  }
};
export const internalDirectWrite = async (query) => {
  const wTx = await takeWriteTx();
  return wTx.tx
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
      /* istanbul ignore next */ (err) => {
        logger.error(`[GRAKN] Seems down`, { error: err });
        throw new Error('Grakn seems down');
      }
    );
};
export const getGraknVersion = () => {
  // It seems that Grakn server does not expose its version yet:
  // https://github.com/graknlabs/client-nodejs/issues/47
  return '1.6.2';
};

/**
 * Recursive fetch of every types of a concept
 * @param concept the element
 * @param currentType the current type
 * @param acc the recursive accuStixDomainEntitiesExportComponentmulator
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
  if (conceptLabel === 'entity' || conceptLabel === 'relation') return acc;
  acc.push(conceptLabel);
  return conceptTypes(concept, parentType, acc);
};

const getAliasInternalIdFilter = (query, alias) => {
  const reg = new RegExp(`\\$${alias}[\\s]*has[\\s]*internal_id_key[\\s]*"([0-9a-z-_]+)"`, 'gi');
  const keyVars = Array.from(query.matchAll(reg));
  return keyVars.length > 0 ? last(head(keyVars)) : undefined;
};
const extractRelationAlias = (alias, role, oppositeAlias, relationType) => {
  const variables = [];
  const naturalRoles = resolveNaturalRoles(relationType);
  const oppositeRole = head(Rfind((n) => head(n) !== role, Object.entries(naturalRoles)));
  // Control the role specified in the query.
  variables.push({ role, alias, forceNatural: false });
  variables.push({ role: oppositeRole, alias: oppositeAlias, forceNatural: false });
  return variables;
};
/**
 * Extract all vars from a grakn query
 * @param query
 */
export const extractQueryVars = (query) => {
  const vars = uniq(map((m) => ({ alias: m.replace('$', '') }), query.match(/\$[a-z_]+/gi)));
  const relationsVars = Array.from(query.matchAll(/\(([a-z_\-\s:$]+),([a-z_\-\s:$]+)\)[\s]*isa[\s]*([a-z_-]+)/g));
  const roles = flatten(
    map((r) => {
      const [, left, right, relationType] = r;
      const [leftRole, leftAlias] = includes(':', left) ? left.trim().split(':') : [null, left];
      const [rightRole, rightAlias] = includes(':', right) ? right.trim().split(':') : [null, right];
      const lAlias = leftAlias.trim().replace('$', '');
      const lKeyFilter = getAliasInternalIdFilter(query, lAlias);
      const rAlias = rightAlias.trim().replace('$', '');
      const rKeyFilter = getAliasInternalIdFilter(query, rAlias);
      // If one filtering key is specified, just return the duo with no roles
      if (lKeyFilter || rKeyFilter) {
        return [
          { alias: lAlias, internalIdKey: lKeyFilter, forceNatural: false },
          { alias: rAlias, internalIdKey: rKeyFilter, forceNatural: false },
        ];
      }
      // If no filtering, roles must be fully specified or not specified.
      // If missing left role
      if (leftRole === null && rightRole !== null) {
        return extractRelationAlias(rAlias, rightRole, lAlias, relationType);
      }
      // If missing right role
      if (leftRole !== null && rightRole === null) {
        return extractRelationAlias(lAlias, leftRole, rAlias, relationType);
      }
      // Else, we have both or nothing
      const roleForRight = rightRole ? rightRole.trim() : undefined;
      const roleForLeft = leftRole ? leftRole.trim() : undefined;
      return [
        { role: roleForRight, alias: rAlias, forceNatural: roleForRight === undefined },
        { role: roleForLeft, alias: lAlias, forceNatural: roleForLeft === undefined },
      ];
    }, relationsVars)
  );
  return map((v) => {
    const associatedRole = Rfind((r) => r.alias === v.alias, roles);
    return pipe(
      assoc('role', associatedRole ? associatedRole.role : undefined),
      assoc('internalIdKey', associatedRole ? associatedRole.internalIdKey : undefined)
    )(v);
  }, vars);
};
// endregion

// region Loader common
export const queryAttributeValues = async (type) => {
  return executeRead(async (rTx) => {
    const query = `match $x isa ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValues`, { query });
    const iterator = await rTx.tx.query(query);
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
    await rTx.tx.query(checkQuery);
    return true;
  }).catch(() => false);
};
export const queryAttributeValueByGraknId = async (id) => {
  return executeRead(async (rTx) => {
    const query = `match $x id ${escape(id)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValueById`, { query });
    const iterator = await rTx.tx.query(query);
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
/**
 * Load any grakn instance with internal grakn ID.
 * @param concept the concept to get attributes from
 * @param args
 * @returns {Promise}
 */
const loadConcept = async (concept, args = {}) => {
  const { id } = concept;
  const { relationsMap = new Map(), noCache = false, infer = false, explanationAlias = new Map() } = args;
  const conceptType = concept.baseType;
  const types = await conceptTypes(concept);
  const index = inferIndexFromConceptTypes(types);
  // 01. Return the data in elastic if not explicitly asked in grakn
  // Very useful for getting every entities through relation query.
  if (infer === false && noCache === false && !forceNoCache()) {
    const conceptFromCache = await elLoadByGraknId(id, null, relationsMap, [index]);
    if (!conceptFromCache) {
      /* istanbul ignore next */
      logger.error(`[ELASTIC] ${id} missing, cant load the element, you need to reindex`);
    } else {
      return conceptFromCache;
    }
  }
  // 02. If not found continue the process.
  logger.debug(`[GRAKN - infer: false] getAttributes ${head(types)} ${id}`);
  const attributesIterator = await concept.attributes();
  const attributes = await attributesIterator.collect();
  const attributesPromises = attributes.map(async (attribute) => {
    const attributeType = await attribute.type();
    const attributeLabel = await attributeType.label();
    return {
      dataType: await attributeType.dataType(),
      label: attributeLabel,
      value: await attribute.value(),
    };
  });
  return Promise.all(attributesPromises)
    .then((attributesData) => {
      const transform = pipe(
        map((attribute) => {
          let transformedVal = attribute.value;
          const { dataType, label } = attribute;
          if (dataType === GraknDate) {
            transformedVal = moment(attribute.value).utc().toISOString();
          } else if (dataType === GraknString) {
            transformedVal = attribute.value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
          }
          return { [label]: transformedVal };
        }), // Extract values
        chain(toPairs), // Convert to pairs for grouping
        groupBy(head), // Group by key
        map(pluck(1)), // Remove grouping boilerplate
        mapObjIndexed((num, key, obj) =>
          // eslint-disable-next-line no-nested-ternary
          Array.isArray(obj[key]) && !includes(key, multipleAttributes)
            ? head(obj[key])
            : head(obj[key]) && head(obj[key]) !== ''
            ? obj[key]
            : []
        ) // Remove extra list then contains only 1 element
      )(attributesData);
      return pipe(
        assoc('_index', index),
        assoc('index_version', '1.0'),
        assoc('id', transform.internal_id_key),
        assoc('grakn_id', concept.id),
        assoc('parent_types', types),
        assoc('base_type', conceptType.toLowerCase())
      )(transform);
    })
    .then(async (entityData) => {
      if (entityData.base_type !== 'relation') return entityData;
      const isInferredPromise = concept.isInferred();
      const rolePlayers = await concept.rolePlayersMap();
      const roleEntries = Array.from(rolePlayers.entries());
      const rolesPromises = Promise.all(
        map(async (roleItem) => {
          // eslint-disable-next-line prettier/prettier
          const roleTargetId = last(roleItem).values().next().value.id;
          const conceptFromMap = relationsMap.get(roleTargetId);
          if (conceptFromMap && conceptFromMap.forceNatural !== true) {
            const { alias } = conceptFromMap;
            // eslint-disable-next-line prettier/prettier
            return head(roleItem)
              .label()
              .then(async (roleLabel) => {
                // For inference rules we cant use the from/to convention
                // So we need to specify it differently through the relation name.
                const useAlias = explanationAlias.get(roleLabel) || alias;
                return {
                  [useAlias]: null, // With be use lazily
                  [`${useAlias}Id`]: roleTargetId,
                  [`${useAlias}Role`]: roleLabel,
                };
              });
          }
          // Target was not resolved but we can just infer from natural
          // eslint-disable-next-line prettier/prettier
          return head(roleItem)
            .label()
            .then(async (roleLabel) => {
              const useAlias = resolveNaturalRoles(head(types))[roleLabel];
              return {
                [useAlias]: null, // With be use lazily
                [`${useAlias}Id`]: roleTargetId,
                [`${useAlias}Role`]: roleLabel,
              };
            });
        }, roleEntries)
      );
      // Wait for all promises before building the result
      return Promise.all([isInferredPromise, rolesPromises]).then(([isInferred, roles]) => {
        return pipe(
          assoc('id', isInferred ? uuid() : entityData.id),
          assoc('inferred', isInferred),
          assoc('entity_type', entityData.entity_type || TYPE_RELATION_EMBEDDED),
          assoc('relationship_type', head(types)),
          mergeRight(mergeAll(roles))
        )(entityData);
      });
    })
    .then((relationData) => {
      // Then change the id if relation is inferred
      if (relationData.inferred) {
        const { fromId, fromRole, toId, toRole } = relationData;
        const type = relationData.relationship_type;
        const pattern = `{ $${INFERRED_RELATION_KEY}(${fromRole}: $from, ${toRole}: $to) isa ${type}; $from id ${fromId}; $to id ${toId}; };`;
        return pipe(
          assoc('id', Buffer.from(pattern).toString('base64')),
          assoc('internal_id_key', Buffer.from(pattern).toString('base64')),
          assoc('stix_id_key', `relationship--${uuid()}`),
          assoc('created', now()),
          assoc('modified', now()),
          assoc('created_at', now()),
          assoc('updated_at', now())
        )(relationData);
      }
      return relationData;
    });
};
// endregion

// region Loader list
const getSingleValue = (query, infer = false) => {
  return executeRead(async (rTx) => {
    logger.debug(`[GRAKN - infer: ${infer}] getSingleValue`, { query });
    const iterator = await rTx.tx.query(query, { infer });
    return iterator.next();
  });
};
export const getSingleValueNumber = (query, infer = false) => {
  return getSingleValue(query, infer).then((data) => data.number());
};

const getConcepts = async (answers, conceptQueryVars, entities, conceptOpts = {}) => {
  const { infer = false, noCache = false, explanationAlias = new Map() } = conceptOpts;
  const plainEntities = filter((e) => !isEmpty(e) && !isNil(e), entities);
  if (answers.length === 0) return [];
  // 02. Query concepts and rebind the data
  const queryConcepts = await Promise.all(
    map(async (answer) => {
      // Create a map useful for relation roles binding
      const queryVarsToConcepts = await Promise.all(
        conceptQueryVars.map(async ({ alias, role, internalIdKey }) => {
          const concept = answer.map().get(alias);
          if (!concept || concept.baseType === 'ATTRIBUTE') return undefined; // If specific attributes are used for filtering, ordering, ...
          const types = await conceptTypes(concept);
          return { id: concept.id, data: { concept, alias, role, internalIdKey, types } };
        })
      );
      const conceptsIndex = filter((e) => e, queryVarsToConcepts);
      const fetchingConceptsPairs = map((x) => [x.id, x.data], conceptsIndex);
      const relationsMap = new Map(fetchingConceptsPairs);
      // Fetch every concepts of the answer
      const requestedConcepts = filter((r) => includes(r.data.alias, entities), conceptsIndex);
      return map((t) => {
        const { concept } = t.data;
        return { id: concept.id, concept, relationsMap };
      }, requestedConcepts);
    }, answers)
  );
  // 03. Fetch every unique concepts
  const uniqConceptsLoading = pipe(
    flatten,
    uniqBy((e) => e.id),
    map((l) => loadConcept(l.concept, { relationsMap: l.relationsMap, noCache, infer, explanationAlias }))
  )(queryConcepts);
  const resolvedConcepts = await Promise.all(uniqConceptsLoading);
  // 04. Create map from concepts
  const conceptCache = new Map(map((c) => [c.grakn_id, c], resolvedConcepts));
  // 05. Bind all row to data entities
  return answers.map((answer) => {
    const dataPerEntities = plainEntities.map((entity) => {
      const concept = answer.map().get(entity);
      const conceptData = concept && conceptCache.get(concept.id);
      return [entity, conceptData];
    });
    return fromPairs(dataPerEntities);
  });
};
export const find = async (query, entities, findOpts = {}) => {
  // Remove empty values from entities
  const { infer = false } = findOpts;
  return executeRead(async (rTx) => {
    const conceptQueryVars = extractQueryVars(query);
    logger.debug(`[GRAKN - infer: ${infer}] Find`, { query });
    const iterator = await rTx.tx.query(query, { infer });
    // 01. Get every concepts to fetch (unique)
    const answers = await iterator.collect();
    return getConcepts(answers, conceptQueryVars, entities, findOpts);
  });
};

// TODO Start - Refactor UI to be able to remove these 2 API
export const findWithConnectedRelations = async (query, key, options = {}) => {
  const { extraRelKey = null, forceNatural = false } = options;
  let dataFind = await find(query, [key, extraRelKey], options);
  if (forceNatural) {
    dataFind = map((relation) => {
      const data = relation[key];
      const naturalRoles = resolveNaturalRoles(data.relationship_type);
      if (naturalRoles[data.fromRole] !== ROLE_FROM) {
        return assoc(
          key,
          pipe(
            assoc('fromId', data.toId),
            assoc('fromInternalId', data.toInternalId),
            assoc('fromStixId', data.toStixId),
            assoc('fromRole', data.toRole),
            assoc('fromTypes', data.toTypes),
            assoc('toId', data.fromId),
            assoc('toInternalId', data.fromInternalId),
            assoc('toStixId', data.fromStixId),
            assoc('toRole', data.fromRole),
            assoc('toTypes', data.fromTypes)
          )(data),
          relation
        );
      }
      return relation;
    }, dataFind);
  }
  return map((t) => ({ node: t[key], relation: t[extraRelKey] }), dataFind);
};
export const loadWithConnectedRelations = (query, key, options = {}) => {
  return findWithConnectedRelations(query, key, options).then((result) => head(result));
};

const listElements = async (
  baseQuery,
  first,
  offset,
  orderBy,
  orderMode,
  queryKey,
  connectedReference,
  inferred,
  forceNatural,
  noCache
) => {
  const countQuery = `${baseQuery} count;`;
  const paginateQuery = `offset ${offset}; limit ${first};`;
  const orderQuery = orderBy ? `sort $order ${orderMode};` : '';
  const query = `${baseQuery} ${orderQuery} ${paginateQuery}`;
  const countPromise = getSingleValueNumber(countQuery, inferred);
  const instancesPromise = await findWithConnectedRelations(query, queryKey, {
    extraRelKey: connectedReference,
    infer: inferred,
    forceNatural,
    noCache,
  });
  return Promise.all([instancesPromise, countPromise]).then(([instances, globalCount]) => {
    return buildPagination(first, offset, instances, globalCount);
  });
};
export const listEntities = async (entityTypes, searchFields, args = {}) => {
  // filters contains potential relations like, mitigates, tagged ...
  const { first = 1000, after, orderBy, orderMode = 'asc', noCache = false } = args;
  const { parentType = null, search, filters } = args;
  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && includes('.', orderBy);

  // Define if Elastic can support this query.
  // 01-2 Check the filters
  const validFilters = filter((f) => f && f.values.filter((n) => n).length > 0, filters || []);
  const unSupportedRelations =
    filter((k) => {
      // If the relation must be forced in a specific direction, ES cant support it.
      if (k.fromRole || k.toRole) return true;
      const isRelationFilter = includes('.', k.key);
      if (isRelationFilter) {
        // ES only support internal_id reference
        const [, field] = k.key.split('.');
        if (field !== 'internal_id_key') return true;
      }
      return false;
    }, validFilters).length > 0;
  // 01-3 Check the ordering
  const unsupportedOrdering = isRelationOrderBy && last(orderBy.split('.')) !== 'internal_id_key';
  const supportedByCache = !unsupportedOrdering && !unSupportedRelations;
  if (!forceNoCache() && !noCache && supportedByCache) {
    const index = inferIndexFromConceptTypes(entityTypes, parentType);
    return elPaginate(index, assoc('types', entityTypes, args));
  }
  logger.debug(`[GRAKN] ListEntities on Grakn, supportedByCache: ${supportedByCache} - noCache: ${noCache}`);

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
      const isRelationFilter = includes('.', filterKey);
      if (isRelationFilter) {
        const [relation, field] = filterKey.split('.');
        const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
        const sourceRole = validFilters[index].fromRole ? `${validFilters[index].fromRole}:` : '';
        const toRole = validFilters[index].toRole ? `${validFilters[index].toRole}:` : '';
        const relId = `rel_${curatedRelation}`;
        relationsFields.push(`$${relId} (${sourceRole}$elem, ${toRole}$${curatedRelation}) isa ${curatedRelation};`);
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          const val = filterValues[valueIndex];
          // Apply filter on target.
          // TODO @Julien Support more than only string filters
          attributesFields.push(`$${curatedRelation} has ${field} "${val}";`);
        }
      } else {
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          const val = filterValues[valueIndex];
          attributesFields.push(`$elem has ${filterKey} "${escapeString(val)}";`);
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
    const searchFilter = pipe(
      map((e) => `{ $${e} contains "${escapeString(search)}"; }`),
      join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  // build the final query
  const queryAttributesFields = join(' ', attributesFields);
  const queryAttributesFilters = join(' ', attributesFilters);
  const queryRelationsFields = join(' ', relationsFields);
  const headType = entityTypes.length === 1 ? head(entityTypes) : 'entity';
  const extraTypes =
    entityTypes.length > 1
      ? pipe(
          map((e) => `{ $elem isa ${e}; }`),
          join(' or '),
          concat(__, ';')
        )(entityTypes)
      : '';
  const baseQuery = `match $elem isa ${headType}; ${extraTypes} ${queryRelationsFields} 
                      ${queryAttributesFields} ${queryAttributesFilters} get;`;
  return listElements(baseQuery, first, offset, orderBy, orderMode, 'elem', null, false, false, noCache);
};

export const listRelations = async (relationType, args) => {
  const searchFields = ['name', 'description'];
  const {
    first = 1000,
    after,
    orderBy,
    orderMode = 'asc',
    relationFilter,
    inferred = false,
    forceNatural = false,
    noCache = false,
  } = args;
  let useInference = inferred;
  const { filters = [], search, fromId, fromRole, toId, toRole, fromTypes = [], toTypes = [] } = args;
  const { firstSeenStart, firstSeenStop, lastSeenStart, lastSeenStop, weights = [] } = args;

  // Use $from, $to only if fromId or toId specified.
  // Else, just ask for the relation only.
  // fromType or toType only allow if fromId or toId available
  const definedRoles = !isNil(fromRole) || !isNil(toRole);
  const askForConnections = !isNil(fromId) || !isNil(toId) || definedRoles;
  const haveTargetFilters = filters && filters.length > 0; // For now filters only contains target to filtering
  const fromTypesFilter = fromTypes && fromTypes.length > 0;
  const toTypesFilter = toTypes && toTypes.length > 0;
  if (askForConnections === false && (haveTargetFilters || fromTypesFilter || toTypesFilter || search)) {
    throw new Error('Cant list relation with types filtering or search if from or to id are not specified');
  }

  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && includes('.', orderBy);
  // Handle relation type(s)
  const relationToGet = relationType || 'stix_relation';
  // 0 - Check if we can support the query by Elastic
  const unsupportedOrdering = isRelationOrderBy && last(orderBy.split('.')) !== 'internal_id_key';
  // Search is not supported because its only search on the relation to.
  const supportedByCache = !search && !unsupportedOrdering && !haveTargetFilters && !inferred && !definedRoles;
  const useCache = !forceNoCache() && !noCache && supportedByCache;
  if (useCache) {
    const finalFilters = [];
    if (relationFilter) {
      const { relation, id, relationId } = relationFilter;
      finalFilters.push({ key: `${REL_INDEX_PREFIX}${relation}.internal_id_key`, values: [id] });
      if (relationId) {
        finalFilters.push({ key: `internal_id_key`, values: [relationId] });
      }
    }
    const relationsMap = new Map();
    if (fromId) {
      finalFilters.push({ key: 'connections.internal_id_key', values: [fromId] });
      relationsMap.set(fromId, { alias: 'from', internalIdKey: fromId });
    }
    if (toId) {
      finalFilters.push({ key: 'connections.internal_id_key', values: [toId] });
      relationsMap.set(toId, { alias: 'to', internalIdKey: toId });
    }
    if (fromTypes && fromTypes.length > 0) finalFilters.push({ key: 'connections.types', values: fromTypes });
    if (toTypes && toTypes.length > 0) finalFilters.push({ key: 'connections.types', values: toTypes });
    if (firstSeenStart) finalFilters.push({ key: 'first_seen', values: [firstSeenStart], operator: 'gt' });
    if (firstSeenStop) finalFilters.push({ key: 'first_seen', values: [firstSeenStop], operator: 'lt' });
    if (lastSeenStart) finalFilters.push({ key: 'last_seen', values: [lastSeenStart], operator: 'gt' });
    if (lastSeenStop) finalFilters.push({ key: 'last_seen', values: [lastSeenStop], operator: 'lt' });
    if (lastSeenStop) finalFilters.push({ key: 'last_seen', values: [lastSeenStop], operator: 'lt' });
    if (weights && weights.length > 0) finalFilters.push({ key: 'weight', values: [weights] });
    const paginateArgs = pipe(
      assoc('types', [relationToGet]),
      assoc('filters', finalFilters),
      assoc('relationsMap', relationsMap)
    )(args);
    return elPaginate(INDEX_STIX_RELATIONS, paginateArgs);
  }
  // 1- If not, use Grakn
  const queryFromTypes = fromTypesFilter
    ? pipe(
        map((e) => `{ $from isa ${e}; }`),
        join(' or '),
        concat(__, ';')
      )(fromTypes)
    : '';
  const queryToTypes = toTypesFilter
    ? pipe(
        map((e) => `{ $to isa ${e}; }`),
        join(' or '),
        concat(__, ';')
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
    const searchFilter = pipe(
      map((e) => `{ $${e} contains "${escapeString(search)}"; }`),
      join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  if (fromId) attributesFilters.push(`$from has internal_id_key "${escapeString(fromId)}";`);
  if (toId) attributesFilters.push(`$to has internal_id_key "${escapeString(toId)}";`);
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
  if (weights && weights.length > 0) {
    attributesFields.push(`$rel has weight $weight;`);
    // eslint-disable-next-line prettier/prettier
    attributesFilters.push(
      pipe(
        map((e) => `{ $weight == ${e}; }`),
        join(' or '),
        concat(__, ';')
      )(weights)
    );
  }
  const relationRef = relationFilter ? 'relationRef' : null;
  if (relationFilter) {
    // eslint-disable-next-line no-shadow
    const { relation, fromRole: fromRoleFilter, toRole: toRoleFilter, id, relationId } = relationFilter;
    const pEid = escapeString(id);
    const relationQueryPart = `$${relationRef}(${fromRoleFilter}:$rel, ${toRoleFilter}:$pointer) isa ${relation}; $pointer has internal_id_key "${pEid}";`;
    relationsFields.push(relationQueryPart);
    if (relationId) {
      attributesFilters.push(`$rel has internal_id_key "${escapeString(relationId)}";`);
    }
  }
  if (filters.length > 0) {
    // eslint-disable-next-line
    for (const f of filters) {
      if (!includes(REL_CONNECTED_SUFFIX, f.key)) throw new Error('Filters only support connected target filtering');
      // eslint-disable-next-line prettier/prettier
      const filterKey = f.key.replace(REL_INDEX_PREFIX, '').replace(REL_CONNECTED_SUFFIX, '').split('.');
      const [key, val] = filterKey;
      const queryFilters = pipe(
        map((e) => `{ $${key} has ${val} ${f.operator === 'match' ? 'contains' : ''} "${escapeString(e)}"; }`),
        join(' or '),
        concat(__, ';')
      )(f.values);
      attributesFilters.push(queryFilters);
    }
  }
  // Build the query
  const queryAttributesFields = join(' ', attributesFields);
  const queryAttributesFilters = join(' ', attributesFilters);
  const queryRelationsFields = join(' ', relationsFields);
  const querySource = askForConnections
    ? `$rel(${fromRole ? `${fromRole}:` : ''}$from, ${toRole ? `${toRole}:` : ''}$to)`
    : '$rel';
  const baseQuery = `match ${querySource} isa ${relationToGet};
                      ${queryFromTypes} ${queryToTypes} 
                      ${queryRelationsFields} ${queryAttributesFields} ${queryAttributesFilters} get;`;
  return listElements(
    baseQuery,
    first,
    offset,
    orderBy,
    orderMode,
    'rel',
    relationRef,
    useInference,
    forceNatural,
    noCache
  );
};
// endregion

// region Loader element
export const load = async (query, entities, options) => {
  const data = await find(query, entities, options);
  return head(data);
};
export const internalLoadEntityById = async (id, type = null, args = {}) => {
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    // [ELASTIC] From cache
    return elLoadById(id, type);
  }
  const query = `match $x ${type ? `isa ${type},` : ''} has internal_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x'], { noCache });
  return element ? element.x : null;
};
export const loadEntityById = async (id, type, args = {}) => {
  if (isNil(type)) {
    throw new Error(`[GRAKN] loadEntityById > Missing type`);
  }
  return internalLoadEntityById(id, type, args);
};
export const internalLoadEntityByStixId = async (id, type = null, args = {}) => {
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    return elLoadByStixId(id, type);
  }
  const query = `match $x ${type ? `isa ${type},` : ''} has stix_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x']);
  return element ? element.x : null;
};
export const loadEntityByStixId = async (id, type, args = {}) => {
  if (isNil(type)) {
    throw new Error(`[GRAKN] loadEntityByStixId > Missing type`);
  }
  return internalLoadEntityByStixId(id, type, args);
};
export const loadEntityByGraknId = async (graknId, args = {}) => {
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadByGraknId(graknId);
    if (fromCache) return fromCache;
  }
  const query = `match $x id ${escapeString(graknId)}; get;`;
  const element = await load(query, ['x']);
  return element.x;
};
export const loadRelationById = async (id, type, args = {}) => {
  if (isNil(type)) {
    throw new Error(`[GRAKN] loadRelationById > Missing type`);
  }
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadById(id, type);
    if (fromCache) return fromCache;
  }
  const eid = escapeString(id);
  const query = `match $rel($from, $to) isa ${type}, has internal_id_key "${eid}"; get;`;
  const element = await load(query, ['rel']);
  return element ? element.rel : null;
};
export const loadRelationByStixId = async (id, type, args = {}) => {
  if (isNil(type)) {
    throw new Error(`[GRAKN] loadRelationByStixId > Missing type`);
  }
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadByStixId(id, type);
    if (fromCache) return fromCache;
  }
  const eid = escapeString(id);
  const query = `match $rel($from, $to) isa ${type}, has stix_id_key "${eid}"; get;`;
  const element = await load(query, ['rel']);
  return element ? element.rel : null;
};
export const loadRelationByGraknId = async (graknId, args = {}) => {
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadByGraknId(graknId);
    if (fromCache) return fromCache;
  }
  const eid = escapeString(graknId);
  const query = `match $rel($from, $to) isa relation; $rel id ${eid}; get;`;
  const element = await load(query, ['rel']);
  return element ? element.rel : null;
};
export const loadByGraknId = async (graknId, args = {}) => {
  // Could be entity or relation.
  const { noCache = false } = args;
  if (!noCache && !forceNoCache()) {
    // [ELASTIC] From cache - Already support the diff between entity and relation.
    const fromCache = await elLoadByGraknId(graknId);
    if (fromCache) return fromCache;
  }
  const entity = await loadEntityByGraknId(graknId, { noCache: true });
  if (entity.base_type === 'relation') {
    return loadRelationByGraknId(graknId, { noCache: true });
  }
  return entity;
};
// endregion

// region Indexer
const reindexAttributeValue = async (queryType, type, value) => {
  const index = queryType === 'relation' ? INDEX_STIX_RELATIONS : INDEX_STIX_ENTITIES;
  const readQuery = `match $x isa ${queryType}, has ${escape(type)} $a; $a "${escapeString(value)}"; get;`;
  logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: readQuery });
  const elementIds = await executeRead(async (rTx) => {
    const iterator = await rTx.tx.query(readQuery, { infer: false });
    const answer = await iterator.collect();
    return answer.map((n) => n.get('x').id);
  });
  const body = elementIds.flatMap((id) => [{ update: { _index: index, _id: id } }, { doc: { [type]: value } }]);
  if (body.length > 0) {
    await elBulk({ refresh: true, body });
  }
};
export const reindexEntityAttribute = (type, value) => reindexAttributeValue('entity', type, value);
export const reindexRelationAttribute = (type, value) => reindexAttributeValue('relation', type, value);
// endregion

// region Graphics
const buildAggregationQuery = (entityType, filters, options) => {
  const { operation, field, interval, startDate, endDate } = options;
  let baseQuery = `match $from isa ${entityType}; ${startDate || endDate ? `$from has ${field} $created;` : ''}`;
  if (startDate) baseQuery = `${baseQuery} $created > ${prepareDate(startDate)};`;
  if (endDate) baseQuery = `${baseQuery} $created < ${prepareDate(endDate)};`;
  const filterQuery = pipe(
    map((filterElement) => {
      const { isRelation, value, from, to, start, end, type } = filterElement;
      const eValue = `${escapeString(value)}`;
      if (isRelation) {
        const fromRole = from ? `${from}:` : '';
        const toRole = to ? `${to}:` : '';
        const dateRange =
          start && end
            ? `$rel_${type} has first_seen $fs; $fs > ${prepareDate(start)}; $fs < ${prepareDate(end)};`
            : '';
        const relation = `$rel_${type}(${fromRole}$from, ${toRole}$${type}_to) isa ${type};`;
        return `${relation} ${dateRange} $${type}_to has internal_id_key "${eValue}";`;
      }
      return `$from has ${type} "${eValue}";`;
    }),
    join('')
  )(filters);
  const groupField = interval ? `${field}_${interval}` : field;
  const groupingQuery = `$from has ${groupField} $g; get; group $g; ${operation};`;
  return `${baseQuery} ${filterQuery} ${groupingQuery}`;
};
const graknTimeSeries = (query, keyRef, valueRef, inferred) => {
  return executeRead(async (rTx) => {
    logger.debug(`[GRAKN - infer: ${inferred}] timeSeries`, { query });
    const iterator = await rTx.tx.query(query, { infer: inferred });
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
  // filters: [ { isRelation: true, type: stix_relation, from: 'role', to: 'role', value: uuid } ]
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
  // filters: [ { isRelation: true, type: stix_relation, from: 'role', to: 'role', value: uuid } ]
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, operation, relationType, field, interval } = options;
  const { fromId, noCache = false, inferred = false } = options;
  // Check if can be supported by ES
  let histogramData;
  const entityType = relationType ? escape(relationType) : 'stix_relation';
  if (!noCache && operation === 'count' && inferred === false) {
    const filters = [];
    if (fromId) filters.push({ isRelation: false, type: 'connections.internal_id_key', value: fromId });
    histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);
  } else {
    const query = `match $x ${fromId ? '($from)' : ''} isa ${entityType}; ${
      fromId ? `$from has internal_id_key "${escapeString(fromId)}";` : ''
    }`;
    const finalQuery = `${query} $x has ${field}_${interval} $g; get; group $g; ${operation};`;
    histogramData = await graknTimeSeries(finalQuery, 'date', 'value', inferred);
  }
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionEntities = async (entityType, filters = [], options) => {
  // filters: { isRelation: true, type: stix_relation, start: date, end: date, from: 'role', to: 'role', value: uuid }
  const { noCache = false, inferred = false, limit = 10, order = 'asc' } = options;
  const { startDate, endDate, field, operation } = options;
  let distributionData;
  // Unsupported in cache: const { isRelation, value, from, to, start, end, type };
  if (field.includes('.')) throw new Error('Distribution entities doesnt support relation aggregation field');
  const supportedFilters = filter((f) => f.start || f.end || f.from || f.to, filters).length === 0;
  if (!noCache && operation === 'count' && supportedFilters && inferred === false) {
    distributionData = await elAggregationCount(entityType, field, startDate, endDate, filters);
  } else {
    const finalQuery = buildAggregationQuery(entityType, filters, options);
    distributionData = await graknTimeSeries(finalQuery, 'label', 'value', inferred);
  }
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? ascend : descend;
  return take(limit, sortWith([orderingFunction(prop('value'))])(distributionData));
};
export const distributionRelations = async (options) => {
  const { fromId, field, operation } = options; // Mandatory fields
  const { limit = 50, order, noCache = false, inferred = false } = options;
  const { startDate, endDate, relationType, toTypes = [] } = options;
  let distributionData;
  const entityType = relationType ? escape(relationType) : 'stix_relation';
  // Using elastic can only be done if the distribution is a count on types
  if (!noCache && field === 'entity_type' && operation === 'count' && inferred === false) {
    distributionData = await elAggregationRelationsCount(entityType, startDate, endDate, toTypes, fromId);
  } else {
    const query = `match $rel($from, $to) isa ${entityType}; ${
      toTypes && toTypes.length > 0
        ? `${join(
            ' ',
            map((toType) => `{ $to isa ${escape(toType)}; } or`, toTypes)
          )} { $to isa ${escape(head(toTypes))}; };`
        : ''
    } $from has internal_id_key "${escapeString(fromId)}";
    ${
      startDate && endDate
        ? `$rel has first_seen $fs; $fs > ${prepareDate(startDate)}; $fs < ${prepareDate(endDate)};`
        : ''
    }
      $to has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
    distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  }
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? ascend : descend;
  return take(limit, sortWith([orderingFunction(prop('value'))])(distributionData));
};
export const distributionEntitiesThroughRelations = async (options) => {
  const { limit = 10, order, inferred = false } = options;
  const { relationType, remoteRelationType, toType, fromId, field, operation } = options;
  let query = `match $rel($from, $to) isa ${relationType}; $to isa ${toType};`;
  query += `$from has internal_id_key "${escapeString(fromId)}";`;
  query += `$rel2($to, $to2) isa ${remoteRelationType};`;
  query += `$to2 has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
  const distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? ascend : descend;
  return take(limit, sortWith([orderingFunction(prop('value'))])(distributionData));
};
// endregion

// region mutation common
const prepareAttribute = (value) => {
  if (value instanceof Date) return prepareDate(value);
  if (Date.parse(value) > 0 && new Date(value).toISOString() === value) return prepareDate(value);
  if (/\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z)/.test(value)) return prepareDate(value);
  if (typeof value === 'string') return `"${escapeString(value)}"`;
  return escape(value);
};
const flatAttributesForObject = (data) => {
  const elements = Object.entries(data);
  return pipe(
    map((elem) => {
      const key = head(elem);
      const value = last(elem);
      if (Array.isArray(value)) {
        return map((iter) => ({ key, value: iter }), value);
      }
      // Some dates needs to detailed for search
      if (value && includes(key, statsDateAttributes)) {
        return [
          { key, value },
          { key: `${key}_day`, value: dayFormat(value) },
          { key: `${key}_month`, value: monthFormat(value) },
          { key: `${key}_year`, value: yearFormat(value) },
        ];
      }
      return { key, value };
    }),
    flatten,
    filter((f) => f.value !== undefined)
  )(elements);
};
// endregion

// region mutation relation
const createRelationRaw = async (user, fromInternalId, input, opts = {}) => {
  const { indexable = true, reversedReturn = false, isStixObservableRelation = false, noLog = false } = opts;
  // 01. First fix the direction of the relation
  const isStixRelation = includes('stix_id_key', Object.keys(input)) || input.relationship_type;
  const relationshipType = input.relationship_type || input.through;
  if (fromInternalId === input.toId) {
    /* istanbul ignore next */
    throw new Error(
      `[GRAKN] You cant create a relation with the same source and target (${fromInternalId} - ${relationshipType})`
    );
  }
  // eslint-disable-next-line no-nested-ternary
  const entityType = isStixRelation
    ? isStixObservableRelation
      ? TYPE_STIX_OBSERVABLE_RELATION
      : TYPE_STIX_RELATION
    : TYPE_RELATION_EMBEDDED;
  const isInv = isInversed(relationshipType, input.fromRole);
  /* istanbul ignore if */
  if (isInv) {
    const message = `{ from '${input.fromRole}' to '${input.toRole}' through ${relationshipType} }`;
    throw new Error(`[GRAKN] You cant create a relation in incorrect order ${message}`);
  }
  // 02. Prepare the data to create or index
  const today = now();
  let relationId;
  if (input.internal_id_key) {
    relationId = input.internal_id_key;
  } else {
    const relationEmbeddedId = uuid5(`${fromInternalId}${input.toId}`, uuid5.DNS);
    relationId = entityType === TYPE_RELATION_EMBEDDED ? relationEmbeddedId : uuid();
  }
  let relationAttributes = { internal_id_key: relationId };
  if (isStixRelation) {
    const currentDate = now();
    const toCreate = isNil(input.stix_id_key) || input.stix_id_key === 'create';
    relationAttributes.stix_id_key = toCreate ? `relationship--${uuid()}` : input.stix_id_key;
    relationAttributes.revoked = false;
    relationAttributes.name = input.name ? input.name : ''; // Force name of the relation
    relationAttributes.description = input.description ? input.description : '';
    relationAttributes.role_played = input.role_played ? input.role_played : 'Unknown';
    relationAttributes.weight = input.weight ? input.weight : 1;
    relationAttributes.entity_type = entityType;
    relationAttributes.relationship_type = relationshipType;
    relationAttributes.updated_at = currentDate;
    relationAttributes.created = input.created ? input.created : today;
    relationAttributes.modified = input.modified ? input.modified : today;
    relationAttributes.created_at = currentDate;
    relationAttributes.first_seen = input.first_seen ? input.first_seen : today;
    relationAttributes.last_seen = input.last_seen ? input.last_seen : today;
    /* istanbul ignore if */
    if (relationAttributes.first_seen > relationAttributes.last_seen) {
      throw new DatabaseError({
        data: { details: `You cant create a relation with a first seen less than the last_seen` },
      });
    }
  }
  // Add the additional fields for dates (day, month, year)
  const dataKeys = Object.keys(relationAttributes);
  for (let index = 0; index < dataKeys.length; index += 1) {
    // Adding dates elements
    if (includes(dataKeys[index], statsDateAttributes)) {
      const dayValue = dayFormat(relationAttributes[dataKeys[index]]);
      const monthValue = monthFormat(relationAttributes[dataKeys[index]]);
      const yearValue = yearFormat(relationAttributes[dataKeys[index]]);
      relationAttributes = pipe(
        assoc(`${dataKeys[index]}_day`, dayValue),
        assoc(`${dataKeys[index]}_month`, monthValue),
        assoc(`${dataKeys[index]}_year`, yearValue)
      )(relationAttributes);
    }
  }
  // 02. Create the relation
  const graknRelation = await executeWrite(async (wTx) => {
    let query = `match $from ${input.fromType ? `isa ${input.fromType},` : ''} has internal_id_key "${fromInternalId}";
      $to ${input.toType ? `isa ${input.toType},` : ''} has internal_id_key "${input.toId}";
      insert $rel(${input.fromRole}: $from, ${input.toRole}: $to) isa ${relationshipType},`;
    const queryElements = flatAttributesForObject(relationAttributes);
    const nbElements = queryElements.length;
    for (let index = 0; index < nbElements; index += 1) {
      const { key, value } = queryElements[index];
      const insert = prepareAttribute(value);
      const separator = index + 1 === nbElements ? ';' : ',';
      query += `has ${key} ${insert}${separator} `;
    }
    logger.debug(`[GRAKN - infer: false] createRelation`, { query });
    const iterator = await wTx.tx.query(query);
    const txRelation = await iterator.next();
    const conceptRelation = txRelation.map().get('rel');
    const relationTypes = await conceptTypes(conceptRelation);
    const graknRelationId = conceptRelation.id;
    const conceptFrom = txRelation.map().get('from');
    const graknFromId = conceptFrom.id;
    const fromTypes = await conceptTypes(conceptFrom);
    const conceptTo = txRelation.map().get('to');
    const graknToId = conceptTo.id;
    const toTypes = await conceptTypes(conceptTo);
    return { graknRelationId, graknFromId, graknToId, relationTypes, fromTypes, toTypes };
  });
  // 03. Prepare the final data with grakn IDS
  const createdRel = pipe(
    assoc('id', relationId),
    // Grakn identifiers
    assoc('grakn_id', graknRelation.graknRelationId),
    assoc('fromId', graknRelation.graknFromId),
    assoc('fromRole', input.fromRole),
    assoc('fromTypes', graknRelation.fromTypes),
    assoc('toId', graknRelation.graknToId),
    assoc('toRole', input.toRole),
    assoc('toTypes', graknRelation.toTypes),
    // Relation specific
    assoc('inferred', false),
    // Types
    assoc('entity_type', entityType),
    assoc('base_type', 'relation'),
    assoc('relationship_type', relationshipType),
    assoc('parent_types', graknRelation.relationTypes)
  )(relationAttributes);
  if (indexable) {
    // 04. Index the relation and the modification in the base entity
    await elIndexElements([createdRel]);
  }
  // 06. Send logs
  if (!noLog) {
    const from = await elLoadByGraknId(createdRel.fromId);
    const to = await elLoadByGraknId(createdRel.toId);
    if (entityType === TYPE_RELATION_EMBEDDED) {
      await sendLog(
        relationshipType === 'created_by_ref' ? EVENT_TYPE_UPDATE : EVENT_TYPE_UPDATE_ADD,
        user,
        createdRel,
        { from, to }
      );
    } else {
      await sendLog(EVENT_TYPE_CREATE, user, createdRel, { from, to });
    }
  }
  // 07. Return result
  if (reversedReturn !== true) {
    return createdRel;
  }
  // 08. Return result inversed if asked
  /* istanbul ignore next */
  return pipe(
    assoc('fromId', createdRel.toId),
    assoc('fromRole', createdRel.toRole),
    assoc('fromTypes', createdRel.toTypes),
    assoc('toId', createdRel.fromId),
    assoc('toRole', createdRel.fromRole),
    assoc('toTypes', createdRel.fromTypes)
  )(createdRel);
};
const addOwner = async (user, fromInternalId, createdByOwnerId, opts = {}) => {
  if (!createdByOwnerId) return undefined;
  const input = { fromRole: 'so', toId: createdByOwnerId, toType: 'Identity', toRole: 'owner', through: 'owned_by' };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addCreatedByRef = async (user, fromInternalId, createdByRefId, opts = {}) => {
  if (!createdByRefId) return undefined;
  const input = {
    fromRole: 'so',
    toId: createdByRefId,
    toType: 'Identity',
    toRole: 'creator',
    through: 'created_by_ref',
  };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addMarkingDef = async (user, fromInternalId, markingDefId, opts = {}) => {
  if (!markingDefId) return undefined;
  const input = {
    fromRole: 'so',
    toId: markingDefId,
    toType: 'Marking-Definition',
    toRole: 'marking',
    through: 'object_marking_refs',
  };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addMarkingDefs = async (user, internalId, markingDefIds, opts = {}) => {
  if (!markingDefIds || isEmpty(markingDefIds)) return undefined;
  const markings = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < markingDefIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const marking = await addMarkingDef(user, internalId, markingDefIds[i], opts);
    markings.push(marking);
  }
  return markings;
};
const addTag = async (user, fromInternalId, tagId, opts = {}) => {
  if (!tagId) return undefined;
  const input = { fromRole: 'so', toId: tagId, toType: 'Tag', toRole: 'tagging', through: 'tagged' };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addTags = async (user, internalId, tagsIds, opts = {}) => {
  if (!tagsIds || isEmpty(tagsIds)) return undefined;
  const tags = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < tagsIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const tag = await addTag(user, internalId, tagsIds[i], opts);
    tags.push(tag);
  }
  return tags;
};
const addKillChain = async (user, fromInternalId, killChainId, opts = {}) => {
  if (!killChainId) return undefined;
  const input = {
    fromRole: 'phase_belonging',
    toId: killChainId,
    toType: 'Kill-Chain-Phase',
    toRole: 'kill_chain_phase',
    through: 'kill_chain_phases',
  };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addKillChains = async (user, internalId, killChainIds, opts = {}) => {
  if (!killChainIds || isEmpty(killChainIds)) return undefined;
  const killChains = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < killChainIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const killChain = await addKillChain(user, internalId, killChainIds[i], opts);
    killChains.push(killChain);
  }
  return killChains;
};
const addObjectRef = async (user, fromInternalId, stixObjectId, opts = {}) => {
  if (!stixObjectId) return undefined;
  const input = {
    fromRole: 'knowledge_aggregation',
    toId: stixObjectId,
    toType: 'Stix-Domain-Entity',
    toRole: 'so',
    through: 'object_refs',
  };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addObjectRefs = async (user, internalId, stixObjectIds, opts = {}) => {
  if (!stixObjectIds || isEmpty(stixObjectIds)) return undefined;
  const objectRefs = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixObjectIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const objectRef = await addObjectRef(user, internalId, stixObjectIds[i], opts);
    objectRefs.push(objectRef);
  }
  return objectRefs;
};
const addObservableRef = async (user, fromInternalId, observableId, opts = {}) => {
  if (!observableId) return undefined;
  const input = {
    fromRole: 'observables_aggregation',
    toId: observableId,
    toType: 'Stix-Observable',
    toRole: 'soo',
    through: 'observable_refs',
  };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addObservableRefs = async (user, internalId, observableIds, opts = {}) => {
  if (!observableIds || isEmpty(observableIds)) return undefined;
  const observableRefs = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < observableIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const observableRef = await addObservableRef(user, internalId, observableIds[i], opts);
    observableRefs.push(observableRef);
  }
  return observableRefs;
};
const addRelationRef = async (user, fromInternalId, stixRelationId, opts = {}) => {
  if (!stixRelationId) return undefined;
  const input = {
    fromRole: 'knowledge_aggregation',
    toId: stixRelationId,
    toType: 'stix_relation',
    toRole: 'so',
    through: 'object_refs',
  };
  return createRelationRaw(user, fromInternalId, input, opts);
};
const addRelationRefs = async (user, internalId, stixRelationIds, opts = {}) => {
  if (!stixRelationIds || isEmpty(stixRelationIds)) return undefined;
  const relationRefs = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixRelationIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const relationRef = await addRelationRef(user, internalId, stixRelationIds[i], opts);
    relationRefs.push(relationRef);
  }
  return relationRefs;
};
export const createRelation = async (user, fromInternalId, input, opts = {}) => {
  const created = await createRelationRaw(user, fromInternalId, input, opts);
  if (created) {
    // 05. Complete with eventual relations (will eventually update the index)
    await addOwner(user, created.id, input.createdByOwner, opts);
    await addCreatedByRef(user, created.id, input.createdByRef, opts);
    await addMarkingDefs(user, created.id, input.markingDefinitions, opts);
    await addKillChains(user, created.id, input.killChainPhases, opts);
  }
  return created;
};
/* istanbul ignore next */
export const createRelations = async (user, fromInternalId, inputs, opts = {}) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improve by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const relation = await createRelation(user, fromInternalId, inputs[i], opts);
    createdRelations.push(relation);
  }
  return createdRelations;
};
// endregion

// region mutation entity
export const createEntity = async (user, entity, type, opts = {}) => {
  const { modelType = TYPE_STIX_DOMAIN_ENTITY, stixIdType, indexable = true, noLog = false } = opts;
  const internalId = entity.internal_id_key ? entity.internal_id_key : uuid();
  const stixType = stixIdType || type.toLowerCase();
  const stixId = entity.stix_id_key ? entity.stix_id_key : `${stixType}--${uuid()}`;
  // Complete with identifiers
  const today = now();
  let data = pipe(
    assoc('internal_id_key', internalId),
    assoc('entity_type', type.toLowerCase()),
    assoc('created_at', today),
    assoc('updated_at', today),
    dissoc('createdByOwner'),
    dissoc('createdByRef'),
    dissoc('markingDefinitions'),
    dissoc('tags'),
    dissoc('killChainPhases'),
    dissoc('objectRefs'),
    dissoc('relationRefs'),
    dissoc('observableRefs')
  )(entity);
  if (type === 'User' && !entity.user_email) {
    data = assoc('user_email', `${uuid()}@mail.com`, data);
  }
  // For stix domain entity, force the initialization of the alias list.
  if (modelType === TYPE_STIX_DOMAIN_ENTITY) {
    const alias = data.alias ? data.alias : [''];
    data = assoc('alias', alias, data);
  }
  if (modelType === TYPE_STIX_OBSERVABLE) {
    data = pipe(
      assoc('stix_id_key', stixId), //
      assoc('name', data.name ? data.name : '')
    )(data);
  }
  if (modelType === TYPE_STIX_DOMAIN || modelType === TYPE_STIX_DOMAIN_ENTITY) {
    data = pipe(
      assoc('stix_id_key', stixId),
      assoc('created', entity.created ? entity.created : today),
      assoc('modified', entity.modified ? entity.modified : today),
      assoc('revoked', false)
    )(data);
  }
  // Add the additional fields for dates (day, month, year)
  const dataKeys = Object.keys(data);
  for (let index = 0; index < dataKeys.length; index += 1) {
    // Adding dates elements
    if (includes(dataKeys[index], statsDateAttributes)) {
      const dayValue = dayFormat(data[dataKeys[index]]);
      const monthValue = monthFormat(data[dataKeys[index]]);
      const yearValue = yearFormat(data[dataKeys[index]]);
      data = pipe(
        assoc(`${dataKeys[index]}_day`, dayValue),
        assoc(`${dataKeys[index]}_month`, monthValue),
        assoc(`${dataKeys[index]}_year`, yearValue)
      )(data);
    }
  }
  // Generate fields for query and build the query
  const queryElements = flatAttributesForObject(data);
  const nbElements = queryElements.length;
  let query = `insert $entity isa ${type}, `;
  for (let index = 0; index < nbElements; index += 1) {
    const { key, value } = queryElements[index];
    const insert = prepareAttribute(value);
    const separator = index + 1 === nbElements ? ';' : ',';
    if (!isNil(insert) && insert.length !== 0) {
      query += `has ${key} ${insert}${separator} `;
    }
  }
  const entityCreated = await executeWrite(async (wTx) => {
    logger.debug(`[GRAKN - infer: false] createEntity`, { query });
    const iterator = await wTx.tx.query(query);
    const txEntity = await iterator.next();
    const concept = txEntity.map().get('entity');
    const types = await conceptTypes(concept);
    return { id: concept.id, types };
  });
  // Transaction succeed, complete the result to send it back
  const completedData = pipe(
    assoc('id', internalId),
    assoc('base_type', 'entity'),
    // Grakn identifiers
    assoc('grakn_id', entityCreated.id),
    // Types (entity type directly saved)
    assoc('parent_types', entityCreated.types)
  )(data);
  // Transaction succeed, index the result
  if (indexable) {
    await elIndexElements([completedData]);
  }
  // Send creation log
  if (!noLog) {
    await sendLog(EVENT_TYPE_CREATE, user, completedData);
  }
  // Complete with eventual relations (will eventually update the index)
  await addOwner(user, internalId, entity.createdByOwner, opts);
  if (modelType === TYPE_STIX_DOMAIN || modelType === TYPE_STIX_DOMAIN_ENTITY || modelType === TYPE_STIX_OBSERVABLE) {
    await addCreatedByRef(user, internalId, entity.createdByRef || user.id, opts);
    await addMarkingDefs(user, internalId, entity.markingDefinitions, opts);
    await addTags(user, internalId, entity.tags, opts);
    await addKillChains(user, internalId, entity.killChainPhases, opts);
    await addObjectRefs(user, internalId, entity.objectRefs, opts);
    await addObservableRefs(user, internalId, entity.observableRefs, opts);
    await addRelationRefs(user, internalId, entity.relationRefs, opts);
  }
  // Simply return the data
  return completedData;
};
// endregion

// region mutation update
export const updateAttribute = async (user, id, type, input, wTx, options = {}) => {
  const { forceUpdate = false, noLog = false } = options;
  const { key, value } = input; // value can be multi valued
  if (includes(key, readOnlyAttributes)) {
    throw new DatabaseError({ data: { details: `The field ${key} cannot be modified` } });
  }
  const currentInstanceData = await loadEntityById(id, type);
  const val = includes(key, multipleAttributes) ? value : head(value);
  // --- 00 Need update?
  if (!forceUpdate && equals(currentInstanceData[key], val)) {
    return id;
  }
  // --- 01 Get the current attribute types
  const escapedKey = escape(key);
  const labelTypeQuery = `match $x type ${escapedKey}; get;`;
  const labelIterator = await wTx.tx.query(labelTypeQuery);
  const labelAnswer = await labelIterator.next();
  // eslint-disable-next-line prettier/prettier
  const attrType = await labelAnswer.map().get('x').dataType();
  const typedValues = map((v) => {
    if (attrType === GraknString) return `"${escapeString(v)}"`;
    if (attrType === GraknDate) return prepareDate(v);
    return escape(v);
  }, value);
  // --- Delete the old attribute
  const entityId = `${escapeString(id)}`;
  const deleteQuery = `match $x isa ${type}, has internal_id_key "${entityId}", has ${escapedKey} $del via $d; delete $d;`;
  // eslint-disable-next-line prettier/prettier
  logger.debug(`[GRAKN - infer: false] updateAttribute - delete`, { query: deleteQuery });
  await wTx.tx.query(deleteQuery);
  if (typedValues.length > 0) {
    let graknValues;
    if (typedValues.length === 1) {
      graknValues = `has ${escapedKey} ${head(typedValues)}`;
    } else {
      graknValues = `${join(
        ' ',
        map((gVal) => `has ${escapedKey} ${gVal},`, tail(typedValues))
      )} has ${escapedKey} ${head(typedValues)}`;
    }
    const createQuery = `match $x isa ${type}, has internal_id_key "${entityId}"; insert $x ${graknValues};`;
    logger.debug(`[GRAKN - infer: false] updateAttribute - insert`, { query: createQuery });
    await wTx.tx.query(createQuery);
  }
  // Adding dates elements
  if (includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(head(value));
    const monthValue = monthFormat(head(value));
    const yearValue = yearFormat(head(value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    await updateAttribute(user, id, type, dayInput, wTx, options);
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    await updateAttribute(user, id, type, monthInput, wTx, options);
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    await updateAttribute(user, id, type, yearInput, wTx, options);
  }
  // Update modified / updated_at
  if (currentInstanceData.parent_types.includes(TYPE_STIX_DOMAIN) && key !== 'modified' && key !== 'updated_at') {
    const today = now();
    await updateAttribute(user, id, type, { key: 'updated_at', value: [today] }, wTx, assoc('noLog', true, options));
    await updateAttribute(user, id, type, { key: 'modified', value: [today] }, wTx, assoc('noLog', true, options));
  }

  // Update elasticsearch
  const currentIndex = inferIndexFromConceptTypes(currentInstanceData.parent_types);
  // eslint-disable-next-line no-nested-ternary
  const typedVal = val === 'true' ? true : val === 'false' ? false : val;
  const updateValueField = { [key]: typedVal };
  try {
    await elUpdate(currentIndex, currentInstanceData.grakn_id, { doc: updateValueField });
  } catch (e) {
    /* istanbul ignore next */
    logger.error(`[ELASTIC] ${id} missing, cant update the element, you need to reindex`);
  }
  if (!noLog && escapedKey !== 'graph_data') {
    await sendLog(
      EVENT_TYPE_UPDATE,
      user,
      {
        id: currentInstanceData.id,
        stix_id_key: currentInstanceData.stix_id_key,
        entity_type: currentInstanceData.entity_type,
        [escapedKey]: includes(input.key, multipleAttributes) ? input.value : head(input.value),
      },
      { key: escapedKey, value: input.value }
    );
  }
  return id;
};
// endregion

// region mutation deletion
export const deleteEntityById = async (user, id, type, options = {}) => {
  const { noLog = false } = options;
  if (isNil(type)) {
    /* istanbul ignore next */
    throw new Error(`[GRAKN] deleteEntityById > Missing type`);
  }
  const eid = escapeString(id);
  const currentEntity = await loadEntityById(eid, type);
  // 00. Load everything we need to remove in elastic
  const read = `match $from isa ${type}, has internal_id_key "${eid}"; $rel($from, $to);
   { $rel isa stix_relation; } or { $rel isa stix_observable_relation; } or { $rel isa stix_relation_embedded; } or { $rel isa relation_embedded; }; get;`;
  const relationsToDeIndex = await find(read, ['rel'], options);
  const relationsIds = map((r) => r.rel.id, relationsToDeIndex);
  // 01. Execute the delete in grakn and elastic
  return executeWrite(async (wTx) => {
    const query = `match $x isa ${type}, has internal_id_key "${eid}"; $z($x, $y); delete $z, $x;`;
    logger.debug(`[GRAKN - infer: false] deleteTypedEntityById`, { query });
    await wTx.tx.query(query, { infer: false });
  }).then(async () => {
    if (!noLog && currentEntity) {
      await sendLog(EVENT_TYPE_DELETE, user, currentEntity);
    }
    // [ELASTIC] Delete entity and relations connected to
    await elDeleteInstanceIds(append(eid, relationsIds));
    return id;
  });
};
export const deleteRelationById = async (user, relationId, type, options = {}) => {
  const { noLog = false } = options;
  if (isNil(type)) {
    /* istanbul ignore next */
    throw new Error(`[GRAKN] deleteRelationById > Missing type`);
  }
  const eid = escapeString(relationId);
  const currentRelation = await loadRelationById(eid, type);
  // 00. Load everything we need to remove in elastic
  const read = `match $from isa ${type}, has internal_id_key "${eid}"; $to isa entity; $rel($from, $to) isa relation; get;`;
  const relationsToDeIndex = await find(read, ['rel']);
  const answers = map((r) => r.rel.id, relationsToDeIndex);
  const relationsIds = filter((r) => r, answers); // Because of relation to attributes
  // 01. Execute the delete in grakn and elastic
  return executeWrite(async (wTx) => {
    const query = `match $x isa ${type}, has internal_id_key "${eid}"; $z($x, $y); delete $z, $x;`;
    logger.debug(`[GRAKN - infer: false] deleteRelationById`, { query });
    await wTx.tx.query(query, { infer: false });
  }).then(async () => {
    // [ELASTIC] Update - Delete the inner indexed relations in entities;
    if (!noLog && currentRelation) {
      const from = await elLoadByGraknId(currentRelation.fromId);
      const to = await elLoadByGraknId(currentRelation.toId);
      if (currentRelation.entity_type === TYPE_RELATION_EMBEDDED) {
        if (currentRelation.relationship_type !== 'created_by_ref') {
          await sendLog(EVENT_TYPE_UPDATE_REMOVE, user, currentRelation, { from, to });
        }
      } else {
        await sendLog(EVENT_TYPE_DELETE, user, currentRelation, { from, to });
      }
    }
    await elRemoveRelationConnection(eid);
    await elDeleteInstanceIds(append(eid, relationsIds));
    return relationId;
  });
};
export const deleteRelationsByFromAndTo = async (user, fromId, toId, relationType, scopeType) => {
  /* istanbul ignore if */
  if (isNil(scopeType)) {
    throw new Error(`[GRAKN] deleteRelationsByFromAndTo > Missing scopeType`);
  }
  const efromId = escapeString(fromId);
  const etoId = escapeString(toId);
  const read = `match $from has internal_id_key "${efromId}"; 
    $to has internal_id_key "${etoId}"; 
    $rel($from, $to) isa ${relationType}; get;`;
  const relationsToDelete = await find(read, ['rel']);
  const relationsIds = map((r) => r.rel.id, relationsToDelete);
  for (let i = 0; i < relationsIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await deleteRelationById(user, relationsIds[i], scopeType);
  }
};

export const deleteAttributeById = async (id) => {
  return executeWrite(async (wTx) => {
    const query = `match $x id ${escape(id)}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteAttributeById`, { query });
    await wTx.tx.query(query, { infer: false });
    return id;
  });
};
// endregion

// region inferences
/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @param options
 * @returns {Promise}
 */
export const getRelationInferredById = async (id, options = { noCache: true }) => {
  return executeRead(async (rTx) => {
    const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
    const query = `match ${decodedQuery} get;`;
    logger.debug(`[GRAKN - infer: true] getRelationInferredById`, { query });
    const answerIterator = await rTx.tx.query(query);
    const answerConceptMap = await answerIterator.next();
    const concepts = await getConcepts(
      [answerConceptMap],
      extractQueryVars(query), //
      [INFERRED_RELATION_KEY],
      { noCache: true }
    );
    const relation = head(concepts).rel;
    const explanation = await answerConceptMap.explanation();
    const explanationAnswers = explanation.getAnswers();
    const inferences = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const explanationAnswer of explanationAnswers) {
      const explanationMap = explanationAnswer.map();
      const explanationKeys = Array.from(explanationMap.keys());
      const queryVars = map((v) => ({ alias: v }), explanationKeys);
      const explanationRelationKey = last(filter((n) => n.includes(INFERRED_RELATION_KEY), explanationKeys));
      // Because of multiple relations, we cannot use the from/to alias
      // So we use the relation name to specify the rel_from_to
      const [, from, to] = explanationRelationKey.split('_');
      const fromEntry = [from.replace('-', '_'), 'from'];
      const toEntry = [to.replace('-', '_'), 'to'];
      const explanationAlias = new Map([fromEntry, toEntry]);
      const testOpts = assoc('explanationAlias', explanationAlias, options);
      // eslint-disable-next-line no-await-in-loop
      const explanationConcepts = await getConcepts([explanationAnswer], queryVars, [explanationRelationKey], testOpts);
      inferences.push({ node: head(explanationConcepts)[explanationRelationKey] });
    }
    return pipe(assoc('inferences', { edges: inferences }))(relation);
  });
};
// endregion
