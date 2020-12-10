import moment from 'moment';
import * as R from 'ramda';
import DataLoader from 'dataloader';
import {
  DatabaseError,
  FunctionalError,
  MissingReferenceError,
  TYPE_LOCK_ERROR,
  UnsupportedError,
} from '../config/errors';
import { logger } from '../config/conf';
import {
  buildPagination,
  fillTimeSeries,
  isNotEmptyField,
  relationTypeToInputName,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE,
  utcDate,
} from './utils';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elDeleteInstanceIds,
  elFindByIds,
  elHistogramCount,
  elIndexElements,
  elLoadByIds,
  elPaginate,
  elRemoveRelationConnection,
  elUpdateElement,
  ENTITIES_INDICES,
  RELATIONSHIPS_INDICES,
} from './elasticSearch';
import {
  generateAliasesId,
  generateInternalId,
  generateStandardId,
  isFieldContributingToStandardId,
  NAME_FIELD,
  normalizeName,
  X_MITRE_ID_FIELD,
} from '../schema/identifier';
import { lockResource, storeCreateEvent, storeUpdateEvent } from './redis';
import { buildStixData, cleanStixIds, STIX_SPEC_VERSION } from './stix';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INTERNAL_IDS_ALIASES,
  REL_INDEX_PREFIX,
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
import { isDatedInternalObject } from '../schema/internalObject';
import { isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isStixRelationShipExceptMeta } from '../schema/stixRelationship';
import {
  dictAttributes,
  isDictionaryAttribute,
  multipleAttributes,
  statsDateAttributes,
} from '../schema/fieldDataAdapter';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import {
  ATTRIBUTE_ALIASES,
  ATTRIBUTE_ALIASES_OPENCTI,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_REPORT,
  isStixDomainObject,
  isStixObjectAliased,
  resolveAliasesField,
  stixDomainObjectFieldsToBeUpdated,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_LABEL, isStixMetaObject } from '../schema/stixMetaObject';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservable } from '../schema/stixCyberObservableObject';

// region global variables
export const MAX_BATCH_SIZE = 25;
export const FROM_START = 0;
export const FROM_START_STR = '1970-01-01T00:00:00.000Z';
export const UNTIL_END = 100000000000000;
export const UNTIL_END_STR = '5138-11-16T09:46:40.000Z';
const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';

export const REL_CONNECTED_SUFFIX = 'CONNECTED';

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
export const escapeString = (s) => (s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '').trim();
// endregion

// region basic commands
export const initBatchLoader = (loader) => {
  const opts = { cache: false, maxBatchSize: MAX_BATCH_SIZE };
  return new DataLoader((ids) => loader(ids), opts);
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
// endregion

// region Loader common
export const querySubTypes = async () => {
  /*
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
  */
  // TODO JRI MIGRATION
};
export const queryAttributes = async () => {
  /*
return executeRead(async (rTx) => {
  const query = `match $x type ${escape(type)}; get;`;
  logger.debug(`[GRAKN - infer: false] querySubTypes`, { query });
  const iterator = await rTx.query(query);
  const answer = await iterator.next();
  const typeResult = await answer.map().get('x');
  const attributesIterator = await typeResult.asRemote(rTx).attributes();
  const attributes = await attributesIterator.collect();
  const result = await Promise.all(
    attributes.map(async (attribute) => {
      const attributeLabel = await attribute.label();
      return { id: attribute.id, value: attributeLabel, type: 'attribute' };
    })
  );
  const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('value')));
  const finalResult = R.pipe(
    sortByLabel,
    R.filter((f) => !f.value.startsWith('i_')), // Filter all internal fields
    R.uniqBy((n) => n.value),
    R.map((n) => ({ node: n }))
  )(result);
  return buildPagination(5000, 0, finalResult, 5000);
});
*/
  // TODO JRI MIGRATION
};
export const queryAttributeValues = async () => {
  /*
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
*/
  // TODO JRI MIGRATION
};
export const attributeExists = async () => {
  /*
return executeRead(async (rTx) => {
  const checkQuery = `match $x sub ${attributeLabel}; get;`;
  logger.debug(`[GRAKN - infer: false] attributeExists`, { query: checkQuery });
  await rTx.query(checkQuery);
  return true;
}).catch(() => false);
*/
  // TODO JRI MIGRATION
};
export const queryAttributeValueByGraknId = async () => {
  /*
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
*/
  // TODO JRI MIGRATION
};

export const find = async () => {
  // TODO JRI MIGRATION
  return [];
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
const getSingleValue = () => {
  // TODO JRI MIGRATION
  // return executeRead(async (rTx) => {
  //   logger.debug(`[GRAKN - infer: ${infer}] getSingleValue`, { query });
  //   const iterator = await rTx.query(query, { infer });
  //   return iterator.next();
  // });
  return 0;
};
export const getSingleValueNumber = (query, infer = false) => {
  return getSingleValue(query, infer).then((data) => data.number());
};
// Bulk loading method
export const batchFromEntitiesThrough = async (toIds, relationType, fromEntityType, opts = {}) => {
  const { paginate = true } = opts;
  // USING ELASTIC
  const ids = Array.isArray(toIds) ? toIds : [toIds];
  // Filter on connection to get only relation coming from ids.
  const toInternalIdFilter = {
    key: 'connections',
    nested: [
      { key: 'internal_id', values: ids },
      { key: 'role', values: ['*_to'], operator: 'wildcard' },
    ],
  };
  // Filter the other side of the relation to have expected toEntityType
  const fromTypeFilter = {
    key: 'connections',
    nested: [
      { key: 'types', values: [fromEntityType] },
      { key: 'role', values: ['*_from'], operator: 'wildcard' },
    ],
  };
  const filters = [toInternalIdFilter, fromTypeFilter];
  // Resolve all relations
  const relations = await elPaginate(RELATIONSHIPS_INDICES, {
    connectionFormat: false,
    filters,
    types: [relationType],
  });
  // For each relation resolved the target entity
  const targets = await elFindByIds(R.uniq(relations.map((s) => s.fromId)));
  // Group and rebuild the result
  const elGrouped = R.groupBy((e) => e.toId, relations);
  if (paginate) {
    return ids.map((id) => {
      const values = elGrouped[id];
      let edges = [];
      if (values) edges = values.map((i) => ({ node: R.find((s) => s.internal_id === i.fromId, targets) }));
      return buildPagination(0, 0, edges, edges.length);
    });
  }
  return R.flatten(
    ids.map((id) => {
      const values = elGrouped[id];
      return values?.map((i) => R.find((s) => s.internal_id === i.fromId, targets)) || [];
    })
  );
};
export const batchToEntitiesThrough = async (fromIds, fromType, relationType, toEntityType, opts = {}) => {
  const { paginate = true } = opts;
  // USING ELASTIC
  const ids = Array.isArray(fromIds) ? fromIds : [fromIds];
  // Filter on connection to get only relation coming from ids.
  const fromInternalIdFilter = {
    key: 'connections',
    nested: [
      { key: 'internal_id', values: ids },
      { key: 'role', values: ['*_from'], operator: 'wildcard' },
    ],
  };
  // Filter the other side of the relation to have expected toEntityType
  const toTypeFilter = {
    key: 'connections',
    nested: [
      { key: 'types', values: [toEntityType] },
      { key: 'role', values: ['*_to'], operator: 'wildcard' },
    ],
  };
  const filters = [fromInternalIdFilter, toTypeFilter];
  // Resolve all relations
  const relations = await elPaginate(RELATIONSHIPS_INDICES, {
    connectionFormat: false,
    filters,
    types: [relationType],
  });
  // For each relation resolved the target entity
  const targets = await elFindByIds(R.uniq(relations.map((s) => s.toId)));
  // Group and rebuild the result
  const elGrouped = R.groupBy((e) => e.fromId, relations);
  if (paginate) {
    return ids.map((id) => {
      const values = elGrouped[id];
      let edges = [];
      if (values) edges = values.map((i) => ({ node: R.find((s) => s.internal_id === i.toId, targets) }));
      return buildPagination(0, 0, edges, edges.length);
    });
  }
  return R.flatten(
    ids.map((id) => {
      const values = elGrouped[id];
      return values?.map((i) => R.find((s) => s.internal_id === i.toId, targets)) || [];
    })
  );
};
// Standard loading
export const listToEntitiesThroughRelation = (fromId, fromType, relationType, toEntityType) => {
  return batchToEntitiesThrough(fromId, fromType, relationType, toEntityType);
};
export const listFromEntitiesThroughRelation = (toId, toType, relationType, fromEntityType, infer = false) => {
  // TODO JRI MIGRATION
  return find(
    `match $from isa ${fromEntityType}; 
    $rel(${relationType}_from:$from, ${relationType}_to:$to) isa ${relationType};
    ${toType ? `$to isa ${toType};` : ''}
    $to has internal_id "${escapeString(toId)}"; get;`,
    ['from'],
    { paginationKey: 'from', infer }
  );
};

export const listEntities = async (entityTypes, searchFields, args = {}) => {
  // filters contains potential relations like, mitigates, tagged ...
  return elPaginate(ENTITIES_INDICES, R.assoc('types', entityTypes, args));
};
export const listRelations = async (relationshipType, args) => {
  const { relationFilter = false } = args;
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
  // Handle relation type(s)
  const relationToGet = relationshipType || 'stix-core-relationship';
  // 0 - Check if we can support the query by Elastic
  const finalFilters = [];
  if (relationFilter) {
    const { relation, id, relationId } = relationFilter;
    finalFilters.push({ key: `${REL_INDEX_PREFIX}${relation}.internal_id`, values: [id] });
    if (relationId) {
      finalFilters.push({ key: `internal_id`, values: [relationId] });
    }
  }
  if (elementId) {
    finalFilters.push({ key: 'connections', nested: [{ key: 'internal_id', values: [elementId] }] });
  }
  // region from filtering
  const nestedFrom = [];
  if (fromId) {
    nestedFrom.push(
      { key: 'internal_id', values: [fromId] }
      // { key: 'role', values: ['*_from'], operator: 'wildcard' }
    );
  }
  if (fromTypes && fromTypes.length > 0) {
    nestedFrom.push({ key: 'types', values: fromTypes });
  }
  if (nestedFrom.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedFrom });
  }
  // endregion
  // region to filtering
  const nestedTo = [];
  if (toId) {
    nestedTo.push(
      { key: 'internal_id', values: [toId] }
      // { key: 'role', values: ['*_to'], operator: 'wildcard' }
    );
  }
  if (toTypes && toTypes.length > 0) {
    nestedTo.push({ key: 'types', values: toTypes });
  }
  if (nestedTo.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedTo });
  }
  // endregion
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
};
// endregion

// region Loader element
const internalFindByIds = (ids, args = {}) => {
  const { type } = args;
  return elFindByIds(ids, type);
};
export const internalLoadById = (id, args = {}) => {
  const { type } = args;
  return elLoadByIds(id, type);
};
export const loadById = async (id, type, args = {}) => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError(`You need to specify a type when loading a element`);
  }
  const loadArgs = R.assoc('type', type, args);
  return internalLoadById(id, loadArgs);
};
const transformRawRelationsToAttributes = (data, orientation) => {
  return R.mergeAll(
    Object.entries(
      R.groupBy(
        (a) => a.rel.entity_type,
        R.filter((f) => f.direction === orientation, data)
      )
    ).map(([k, v]) => ({
      [k]: R.map((i) => {
        return Object.assign(i.target, { i_connected_rel: i.rel });
      }, v),
    }))
  );
};

export const loadByIdFullyResolved = async (id, type, args = {}) => {
  const typeOpts = type ? args : R.assoc('type', type, args);
  const element = await internalLoadById(id, typeOpts);
  if (!element) return null;
  // eslint-disable-next-line no-use-before-define
  const deps = await findElementDependencies(element, typeOpts);
  return R.mergeRight(element, deps);
};
const findElementDependencies = async (instance, args = {}) => {
  const { onlyMarking = false, orientation = 'from', noCache = false } = args;
  const isRelation = instance.base_type === BASE_TYPE_RELATION;
  const relType = onlyMarking ? 'object-marking' : 'stix-relationship';
  const relations = await listRelations(relType, { elementId: instance.id, noCache });
  const targetsToResolve = R.map((e) => {
    return e.node.fromId === instance.id ? e.node.toId : e.node.fromId;
  }, relations.edges);
  let rawDataPromise;
  if (targetsToResolve.length === 0) {
    rawDataPromise = Promise.resolve([]);
  } else {
    rawDataPromise = internalFindByIds(targetsToResolve, args).then((ids) => {
      return R.map((e) => {
        const matchId = e.node.fromId === instance.id ? e.node.toId : e.node.fromId;
        const to = R.find((s) => s.id === matchId, ids);
        return { rel: e.node, to: { id: to.id, standard_id: to.standard_id } };
      }, relations.edges);
    });
  }
  let rawData;
  const data = {};
  if (isRelation && !onlyMarking) {
    const [rFrom, rTo, rData] = await Promise.all([
      loadByIdFullyResolved(instance.fromId, null, { onlyMarking: true, noCache }),
      loadByIdFullyResolved(instance.toId, null, { onlyMarking: true, noCache }),
      rawDataPromise,
    ]);
    data.from = rFrom;
    data.to = rTo;
    rawData = rData;
  } else {
    rawData = await rawDataPromise;
  }
  const withDirection = R.map((r) => {
    const direction = r.rel.fromId === instance.id ? 'from' : 'to';
    return { rel: r.rel, target: r.to, direction };
  }, rawData);
  data.i_relations_from = transformRawRelationsToAttributes(withDirection, 'from');
  data.i_relations_to = transformRawRelationsToAttributes(withDirection, 'to');
  // Filter if needed
  let filtered = withDirection;
  if (orientation !== 'all') {
    filtered = R.filter((s) => s.direction === orientation, withDirection);
  }
  const grouped = R.groupBy((a) => relationTypeToInputName(a.rel.entity_type), filtered);
  const entries = Object.entries(grouped);
  for (let index = 0; index < entries.length; index += 1) {
    const [key, values] = entries[index];
    data[key] = R.map((v) => v.target, values);
  }
  return data;
};
export const stixElementLoader = async (id, type) => {
  const element = await loadByIdFullyResolved(id, type);
  return element && buildStixData(element);
};
// endregion

// region Indexer
export const reindexAttributeValue = async () => {
  /*
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
  */
  // TODO JRI MIGRATION
};
// endregion

// region Graphics
export const timeSeriesEntities = async (entityType, filters, options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid } ]
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, field, interval } = options;
  // Check if can be supported by ES
  const histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesRelations = async (options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid }
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, relationship_type: relationshipType, field, interval } = options;
  const { fromId } = options;
  // Check if can be supported by ES
  const entityType = relationshipType ? escape(relationshipType) : 'stix-relationship';
  const filters = fromId ? [{ isRelation: false, isNested: true, type: 'connections.internal_id', value: fromId }] : [];
  const histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);

  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionEntities = async (entityType, filters = [], options) => {
  // filters: { isRelation: true, type: stix_relation, start: date, end: date, value: uuid }
  const { limit = 10, order = 'desc' } = options;
  const { startDate, endDate, field } = options;
  // Unsupported in cache: const { isRelation, value, from, to, start, end, type };
  if (field.includes('.')) {
    throw FunctionalError('Distribution entities does not support relation aggregation field');
  }
  const distributionData = await elAggregationCount(entityType, field, startDate, endDate, filters);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field === ID_INTERNAL) {
    const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
    return R.map((n) => R.assoc('entity', internalLoadById(n.label), n), data);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionRelations = async (options) => {
  const { field } = options; // Mandatory fields
  const { fromId = null, limit = 50, order } = options;
  const {
    startDate,
    endDate,
    relationship_type: relationshipType,
    dateAttribute = 'start_time',
    toTypes = [],
    isTo = false,
    noDirection = false,
  } = options;

  const entityType = relationshipType ? escape(relationshipType) : ABSTRACT_STIX_CORE_RELATIONSHIP;
  const finalDateAttribute = isStixMetaRelationship(entityType) ? 'created_at' : dateAttribute;
  // Using elastic can only be done if the distribution is a count on types
  const distributionData = await elAggregationRelationsCount(
    entityType,
    startDate,
    endDate,
    toTypes,
    fromId,
    field,
    finalDateAttribute,
    isTo,
    noDirection
  );
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field === ID_INTERNAL) {
    const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
    return R.map((n) => R.assoc('entity', internalLoadById(n.label), n), data);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionEntitiesThroughRelations = async () => {
  // TODO JRI MIGRATION
  return [];
  // const { limit = 10, order, inferred = false } = options;
  // const { relationshipType, remoteRelationshipType, toTypes, fromId, field, operation } = options;
  // const queryToTypes = toTypes
  //   ? R.pipe(
  //       R.map((e) => `{ $to isa ${e}; }`),
  //       R.join(' or '),
  //       R.concat(__, ';')
  //     )(toTypes)
  //   : '';
  // let query = `match $rel($from, $to) isa ${relationshipType}; ${queryToTypes}`;
  // query += `$from has internal_id "${escapeString(fromId)}";`;
  // query += `$rel2($to, $to2) isa ${remoteRelationshipType};`;
  // query += `$to2 has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
  // const distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  // // Take a maximum amount of distribution depending on the ordering.
  // const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  // if (field === ID_INTERNAL) {
  //   const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
  //   return R.map((n) => R.assoc('entity', internalLoadById(n.label), n), data);
  // }
  // return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
// endregion

// region mutation common
const TRX_CREATION = 'creation';
const TRX_UPDATE = 'update';
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
          { key: `i_${key}_day`, value: dayFormat(value) },
          { key: `i_${key}_month`, value: monthFormat(value) },
          { key: `i_${key}_year`, value: yearFormat(value) },
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
  const expectedIds = [];
  for (let index = 0; index < depsKeys.length; index += 1) {
    const { src, dst } = depsKeys[index];
    const destKey = dst || src;
    let id = input[src];
    if (!R.isNil(id) && !R.isEmpty(id)) {
      const isListing = Array.isArray(id);
      // Handle specific case of object label that can be directly the value instead of the key.
      let keyPromise;
      if (src === 'objectLabel') {
        const idLabel = (label) => {
          return isAnId(label) ? label : generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(label) });
        };
        id = R.map((label) => idLabel(label), id);
        expectedIds.push(...id);
        keyPromise = internalFindByIds(id);
      } else if (src === 'fromId' || src === 'toId') {
        keyPromise = loadByIdFullyResolved(id, null, { onlyMarking: true });
        expectedIds.push(id);
      } else if (isListing) {
        keyPromise = internalFindByIds(id);
        expectedIds.push(...id);
      } else {
        keyPromise = internalLoadById(id);
        expectedIds.push(id);
      }
      const dataPromise = keyPromise.then((data) => ({ [destKey]: data }));
      deps.push(dataPromise);
    }
  }
  const resolved = await Promise.all(deps);
  const resolvedIds = R.flatten(
    R.map((r) => {
      const [, val] = R.head(Object.entries(r));
      if (isNotEmptyField(val)) {
        const values = Array.isArray(val) ? val : [val];
        return R.map((v) => [v.internal_id, v.standard_id, ...(v.x_opencti_stix_ids || [])], values);
      }
      return [];
    }, resolved)
  );
  const unresolvedIds = R.filter((n) => !R.includes(n, resolvedIds), expectedIds);
  if (unresolvedIds.length > 0) {
    throw MissingReferenceError({ input, unresolvedIds });
  }
  const patch = R.mergeAll(resolved);
  return R.mergeRight(input, patch);
};
const indexCreatedElement = async ({ type, element, relations, indexInput }) => {
  if (type === TRX_CREATION) {
    await elIndexElements([element]);
  } else if (indexInput) {
    // Can be null in case of unneeded update on upsert
    await elUpdateElement(indexInput);
  }
  if (relations.length > 0) {
    await elIndexElements(relations);
  }
};
// endregion

// region mutation update
const updatedInputsToData = (inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value } = input;
    const val = R.includes(key, multipleAttributes) ? value : R.head(value);
    return { [key]: val };
  }, inputs);
  return R.mergeAll(inputPairs);
};
const mergeInstanceWithInputs = (instance, inputs) => {
  const data = updatedInputsToData(inputs);
  return R.mergeRight(instance, data);
};
const partialInstanceWithInputs = (instance, inputs) => {
  const inputData = updatedInputsToData(inputs);
  return { internal_id: instance.internal_id, entity_type: instance.entity_type, ...inputData };
};
const rebuildAndMergeInputFromExistingData = (rawInput, instance, options = {}) => {
  const { forceUpdate = false, operation = UPDATE_OPERATION_REPLACE } = options;
  const { key, value } = rawInput; // value can be multi valued
  const isMultiple = R.includes(key, multipleAttributes);
  let finalVal;
  let finalKey = key;
  if (dictAttributes[key]) {
    throw UnsupportedError('Dictionary attribute cant be updated directly', { rawInput });
  }
  // region rebuild input values consistency
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
    const compareValue = R.isEmpty(valueToTake) || R.isNil(valueToTake) ? undefined : valueToTake;
    if (currentJson[targetKey] === compareValue) {
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
    if (operation === UPDATE_OPERATION_ADD) {
      finalVal = R.pipe(R.append(value), R.flatten, R.uniq)(currentValues);
    } else if (operation === UPDATE_OPERATION_REMOVE) {
      finalVal = R.filter((n) => !R.includes(n, value), currentValues);
    } else {
      finalVal = value;
    }
    if (!forceUpdate && R.equals(finalVal.sort(), currentValues.sort())) {
      return {}; // No need to update the attribute
    }
  } else {
    finalVal = value;
    if (!forceUpdate && R.equals(instance[key], R.head(value))) {
      return {}; // No need to update the attribute
    }
  }
  // endregion
  // region cleanup cases
  if (finalKey === IDS_STIX) {
    // Special stixIds uuid v1 cleanup.
    finalVal = cleanStixIds(finalVal);
  }
  // endregion
  return { key: finalKey, value: finalVal };
};

const innerUpdateAttribute = async (user, instance, rawInput, options = {}) => {
  const { key } = rawInput;
  const input = rebuildAndMergeInputFromExistingData(rawInput, instance, options);
  if (R.isEmpty(input)) return [];
  const updatedInputs = [input];
  // --- 01 Get the current attribute types
  // Adding dates elements
  const updateOperations = [];
  if (R.includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(R.head(input.value));
    const monthValue = monthFormat(R.head(input.value));
    const yearValue = yearFormat(R.head(input.value));
    const dayInput = { key: `i_${key}_day`, value: [dayValue] };
    updatedInputs.push(dayInput);
    updateOperations.push(innerUpdateAttribute(user, instance, dayInput));
    const monthInput = { key: `i_${key}_month`, value: [monthValue] };
    updatedInputs.push(monthInput);
    updateOperations.push(innerUpdateAttribute(user, instance, monthInput));
    const yearInput = { key: `i_${key}_year`, value: [yearValue] };
    updatedInputs.push(yearInput);
    updateOperations.push(innerUpdateAttribute(user, instance, yearInput));
  }
  // Update modified / updated_at
  if (isStixDomainObject(instance.entity_type) && key !== 'modified' && key !== 'updated_at') {
    const today = now();
    const updatedAtInput = { key: 'updated_at', value: [today] };
    updatedInputs.push(updatedAtInput);
    updateOperations.push(innerUpdateAttribute(user, instance, updatedAtInput));
    const modifiedAtInput = { key: 'modified', value: [today] };
    updatedInputs.push(modifiedAtInput);
    updateOperations.push(innerUpdateAttribute(user, instance, modifiedAtInput));
  }
  // Update created
  if (instance.entity_type === ENTITY_TYPE_CONTAINER_REPORT && key === 'published') {
    const createdInput = { key: 'created', value: input.value };
    updatedInputs.push(createdInput);
    updateOperations.push(innerUpdateAttribute(user, instance, createdInput));
  }
  await Promise.all(updateOperations);
  return updatedInputs;
};
export const updateAttributeRaw = async (user, instance, inputs, options = {}) => {
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const updatedInputs = [];
  const impactedInputs = [];
  const instanceType = instance.entity_type;
  // Update all needed attributes
  for (let index = 0; index < elements.length; index += 1) {
    const input = elements[index];
    // eslint-disable-next-line no-await-in-loop
    const ins = await innerUpdateAttribute(user, instance, input, options);
    if (ins.length > 0) {
      updatedInputs.push(input);
      impactedInputs.push(...ins);
    }
    // If named entity name updated, modify the aliases ids
    if (isStixObjectAliased(instanceType) && (input.key === NAME_FIELD || input.key === X_MITRE_ID_FIELD)) {
      const name = R.head(input.value);
      const aliases = [name, ...(instance[ATTRIBUTE_ALIASES] || []), ...(instance[ATTRIBUTE_ALIASES_OPENCTI] || [])];
      const aliasesId = generateAliasesId(aliases);
      const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
      // eslint-disable-next-line no-await-in-loop
      const aliasIns = await innerUpdateAttribute(user, instance, aliasInput, options);
      impactedInputs.push(...aliasIns);
    }
    // If input impact aliases (aliases or x_opencti_aliases), regenerate internal ids
    const aliasesAttrs = [ATTRIBUTE_ALIASES, ATTRIBUTE_ALIASES_OPENCTI];
    const isAliasesImpacted = aliasesAttrs.includes(input.key) && !R.isEmpty(ins.length);
    if (isAliasesImpacted) {
      const aliasesId = generateAliasesId([instance.name, ...input.value]);
      const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
      // eslint-disable-next-line no-await-in-loop
      const aliasIns = await innerUpdateAttribute(user, instance, aliasInput, options);
      if (aliasIns.length > 0) {
        impactedInputs.push(...aliasIns);
      }
    }
  }
  // If update is part of the key, update the standard_id
  const keys = R.map((t) => t.key, impactedInputs);
  if (isFieldContributingToStandardId(instance, keys)) {
    const updatedInstance = mergeInstanceWithInputs(instance, impactedInputs);
    const standardId = generateStandardId(instanceType, updatedInstance);
    const standardInput = { key: ID_STANDARD, value: [standardId] };
    const ins = await innerUpdateAttribute(user, instance, standardInput, options);
    if (ins.length > 0) {
      impactedInputs.push(...ins);
    }
  }
  // Return fully updated instance
  return {
    updatedInputs, // Sourced inputs for event stream
    impactedInputs, // All inputs with dependencies
    updatedInstance: mergeInstanceWithInputs(instance, impactedInputs),
  };
};

/*
const targetedRelations = (entities, direction) => {
  return R.flatten(
    R.map((s) => {
      const relations = [];
      const directedRelations = s[`i_relations_${direction}`];
      const info = directedRelations ? Object.entries(directedRelations) : [];
      for (let index = 0; index < info.length; index += 1) {
        const [key, values] = info[index];
        if (key !== RELATION_CREATED_BY) {
          // Except created by ref (mono valued)
          relations.push(
            ...R.map((val) => {
              return {
                internal_id: val.i_connected_rel.internal_id,
                standard_id: val.i_connected_rel.standard_id,
                entity_type: key,
                connect: val.standard_id,
                relation: val.i_connected_rel,
              };
            }, values)
          );
        }
      }
      return relations;
    }, entities)
  );
};
const filterTargetByExisting = (sources, targets) => {
  const ed = (date) => isEmptyField(date) || date === FROM_START_STR || date === UNTIL_END_STR;
  const noDate = (e) => ed(e.first_seen) && ed(e.last_seen) && ed(e.start_time) && ed(e.stop_time);
  return R.filter((f) => {
    const finder = (t) => {
      // Find the same if type + target + no date specified
      return t.entity_type === f.entity_type && t.connect === f.connect && noDate(t.relation);
    };
    return !R.find(finder, targets);
  }, sources);
};

const mergeEntitiesRaw = async () => {
  // chosenFields = { 'description': 'source1EntityStandardId', 'hashes': 'source2EntityStandardId' } ]
  const { chosenFields = {} } = opts;
  // Pre-checks
  const sourceIds = R.map((e) => e.internal_id, sourceEntities);
  if (R.includes(targetEntity.internal_id, sourceIds)) {
    throw FunctionalError(`Cannot merge an entity on itself`, {
      dest: targetEntity.internal_id,
      source: sourceIds,
    });
  }
  const targetType = targetEntity.entity_type;
  const sourceTypes = R.map((s) => s.entity_type, sourceEntities);
  const isWorkingOnSameType = sourceTypes.every((v) => v === targetType);
  if (!isWorkingOnSameType) {
    throw FunctionalError(`Cannot merge entities of different types`, {
      dest: targetType,
      source: sourceTypes,
    });
  }
  const updateAttributes = [];
  // 1. Update all possible attributes
  const attributes = await queryAttributes(targetType);
  const sourceFields = R.map((a) => a.node.value, attributes.edges);
  for (let fieldIndex = 0; fieldIndex < sourceFields.length; fieldIndex += 1) {
    const sourceFieldKey = sourceFields[fieldIndex];
    const mergedEntityCurrentFieldValue = targetEntity[sourceFieldKey];
    const chosenSourceEntityId = chosenFields[sourceFieldKey];
    const takenFrom = chosenSourceEntityId
      ? R.find((i) => i.standard_id === chosenSourceEntityId, sourceEntities)
      : R.head(sourceEntities); // If not specified, take the first one.
    const sourceFieldValue = takenFrom[sourceFieldKey];
    // Check if we need to do something
    if (isDictionaryAttribute(sourceFieldKey)) {
      // Special case of dictionary
      const dictInputs = Object.entries(sourceFieldValue).map(([k, v]) => ({
        key: `${sourceFieldKey}.${k}`,
        value: [v],
      }));
      updateAttributes.push(...dictInputs);
    } else if (isMultipleAttribute(sourceFieldKey)) {
      const sourceValues = sourceFieldValue || [];
      // For aliased entities, get name of the source to add it as alias of the target
      if (sourceFieldKey === ATTRIBUTE_ALIASES || sourceFieldKey === ATTRIBUTE_ALIASES_OPENCTI) {
        sourceValues.push(takenFrom.name);
      }
      // If multiple attributes, concat all values
      if (sourceValues.length > 0) {
        const multipleValues = R.uniq(R.concat(mergedEntityCurrentFieldValue || [], sourceValues));
        updateAttributes.push({ key: sourceFieldKey, value: multipleValues });
      }
    } else if (isEmptyField(mergedEntityCurrentFieldValue) && isNotEmptyField(sourceFieldValue)) {
      // Single value. Put the data in the merged field only if empty.
      updateAttributes.push({ key: sourceFieldKey, value: [sourceFieldValue] });
    }
  }
  // 2. standard_id must also be kept.
  await updateAttributeRaw(wTx, user, targetEntity, updateAttributes);
  // 2. EACH SOURCE (Ignore createdBy)
  // - EVERYTHING I TARGET (->to) ==> We change to relationship FROM -> TARGET ENTITY + REINDEX RELATION
  // - EVERYTHING TARGETING ME (-> from) ==> We change to relationship TO -> TARGET ENTITY + REINDEX RELATION
  // region CHANGING FROM
  const allTargetToRelations = targetedRelations([targetEntity], 'from');
  const allSourcesToRelations = targetedRelations(sourceEntities, 'from');
  const relationsToRedirectFrom = filterTargetByExisting(allSourcesToRelations, allTargetToRelations);
  // region CHANGING TO
  const allTargetFromRelations = targetedRelations([targetEntity], 'to');
  const allSourcesFromRelations = targetedRelations(sourceEntities, 'to');
  const relationsFromRedirectTo = filterTargetByExisting(allSourcesFromRelations, allTargetFromRelations);
  const queries = [];
  for (let indexFrom = 0; indexFrom < relationsToRedirectFrom.length; indexFrom += 1) {
    const r = relationsToRedirectFrom[indexFrom];
    const type = r.entity_type;
    const removeOldFrom = `match $rel(${type}_from:$from, ${type}_to:$to) isa ${type};
      $rel has internal_id "${r.internal_id}"; delete $rel (${type}_from:$from);`;
    const insertNewFrom = `match $rel(${type}_to:$to) isa ${type};
      $new-from isa entity, has standard_id "${targetEntity.standard_id}";
      $rel has internal_id "${r.internal_id}"; insert $rel (${type}_from:$new-from);`;
    queries.push(wTx.query(removeOldFrom).then(() => wTx.query(insertNewFrom)));
  }
  for (let indexTo = 0; indexTo < relationsFromRedirectTo.length; indexTo += 1) {
    const r = relationsFromRedirectTo[indexTo];
    const type = r.entity_type;
    const removeOldTo = `match $rel(${type}_from:$from, ${type}_to:$to) isa ${type};
      $rel has internal_id "${r.internal_id}"; delete $rel (${type}_to:$to);`;
    const insertNewTo = `match $rel(${type}_from:$from) isa ${type};
      $new-to isa entity, has standard_id "${targetEntity.standard_id}";
      $rel has internal_id "${r.internal_id}"; insert $rel (${type}_to:$new-to);`;
    queries.push(wTx.query(removeOldTo).then(() => wTx.query(insertNewTo)));
  }
  await Promise.all(queries);
  // Build updated ids list
  const updated = R.map((d) => d.internal_id, [targetEntity, ...relationsToRedirectFrom, ...relationsFromRedirectTo]);
  // Delete sourcing entities
  const deletedDependencies = [];
  for (let delIndex = 0; delIndex < sourceEntities.length; delIndex += 1) {
    const element = sourceEntities[delIndex];
    const dependencies = [{ internal_id: element.internal_id, type: element.entity_type, relDependency: false }];
    // eslint-disable-next-line no-use-before-define,no-await-in-loop
    await getElementsRelated(element.internal_id, dependencies);
    // 01. Delete dependencies.
    // Remove all not re-routed relations
    const depsToRemove = R.filter((d) => !updated.includes(d.internal_id), dependencies);
    deletedDependencies.push(...depsToRemove);
    for (let i = depsToRemove.length - 1; i >= 0; i -= 1) {
      const { internal_id: id, type } = depsToRemove[i];
      const query = `match $x has internal_id "${id}"; delete $x isa ${type};`;
      logger.debug(`[GRAKN - infer: false] delete element ${id}`, { query });
      // eslint-disable-next-line no-await-in-loop
      await wTx.query(query, { infer: false });
    }
  }
  // Return results
  return { updated, deleted: deletedDependencies };
};
*/

export const mergeEntities = async () => {
  // // 01. Execute merge
  // const { updated, deleted } = await executeWrite(async (wTx) => {
  //   const merged = await mergeEntitiesRaw(wTx, user, targetEntity, sourceEntities, opts);
  //   await storeMergeEvent(user, targetEntity, sourceEntities);
  //   return merged;
  // });
  // // Update elastic index.
  // // 02. Remove elements in index
  // for (let index = 0; index < deleted.length; index += 1) {
  //   const { internal_id: id, relDependency } = deleted[index];
  //   // 01. If element is a relation, modify the impacted from and to.
  //   if (relDependency) {
  //     // eslint-disable-next-line no-await-in-loop
  //     await elRemoveRelationConnection(id);
  //   }
  //   // 02. Remove the element itself from the index
  //   // eslint-disable-next-line no-await-in-loop
  //   await elDeleteInstanceIds([id]);
  // }
  // // 03. Update elements in index
  // const reindexRelations = [];
  // for (let upIndex = 0; upIndex < updated.length; upIndex += 1) {
  //   const id = updated[upIndex];
  //   // eslint-disable-next-line no-await-in-loop
  //   const element = await internalLoadById(id, { noCache: true });
  //   const indexPromise = elIndexElements([element]);
  //   reindexRelations.push(indexPromise);
  // }
  // await Promise.all(reindexRelations);
  // // 04. Return entity
  // return loadById(targetEntity.id, ABSTRACT_STIX_CORE_OBJECT).then((finalStixCoreObject) =>
  //   notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalStixCoreObject, user)
  // );
  // TODO JRI MIGRATION
  return null;
};

export const updateAttribute = async (user, id, type, inputs, options = {}) => {
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const { operation = UPDATE_OPERATION_REPLACE } = options;
  if (operation !== UPDATE_OPERATION_REPLACE && elements.length > 1) {
    throw FunctionalError(`Unsupported operation`, { operation, elements });
  }
  const instance = await loadByIdFullyResolved(id, type, options);
  if (!instance) {
    throw FunctionalError(`Cant find element to update`, { id, type });
  }
  const participantIds = [instance.standard_id];
  // 01. Check if updating alias lead to entity conflict
  const keys = R.map((t) => t.key, elements);
  if (isStixObjectAliased(instance.entity_type)) {
    // If user ask for aliases modification, we need to check if it not already belong to another entity.
    const isInputAliases = (input) => input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI;
    const aliasedInputs = R.filter((input) => isInputAliases(input), elements);
    if (aliasedInputs.length > 0) {
      const aliases = R.uniq(R.flatten(R.map((a) => a.value, aliasedInputs)));
      const aliasesIds = generateAliasesId(aliases);
      const existingEntities = await internalFindByIds(aliasesIds, { type: instance.entity_type });
      const differentEntities = R.filter((e) => e.internal_id !== id, existingEntities);
      if (differentEntities.length > 0) {
        throw FunctionalError(`This update will produce a duplicate`, { id: instance.id, type });
      }
    }
  }
  // 02. Check if this update is not resulting to an entity merging
  let stixObservableTargetMerge = null;
  if (isFieldContributingToStandardId(instance, keys)) {
    // In this case we need to reconstruct the data like if an update already appears
    // Based on that we will be able to generate the correct standard id
    const mergeInput = (input) => rebuildAndMergeInputFromExistingData(input, instance, options);
    const remappedInputs = R.map((i) => mergeInput(i), elements);
    const resolvedInputs = R.filter((f) => !R.isEmpty(f), remappedInputs);
    const updatedInstance = mergeInstanceWithInputs(instance, resolvedInputs);
    const targetStandardId = generateStandardId(instance.entity_type, updatedInstance);
    if (targetStandardId !== instance.standard_id) {
      const existingEntity = await loadByIdFullyResolved(targetStandardId);
      if (existingEntity) {
        // If stix observable, we can merge. If not throw an error.
        if (isStixCyberObservable(existingEntity.entity_type)) {
          stixObservableTargetMerge = existingEntity;
          participantIds.push(targetStandardId);
        } else {
          throw FunctionalError(`This update will produce a duplicate`, { id: instance.id, type });
        }
      }
    }
  }
  // --- take lock, ensure no one currently create or update this element
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // Only for StixCyberObservable
    if (stixObservableTargetMerge) {
      // noinspection UnnecessaryLocalVariableJS
      const merged = await mergeEntities(user, stixObservableTargetMerge, [instance]);
      // Return merged element after waiting for it.
      return merged;
    }
    // noinspection UnnecessaryLocalVariableJS
    const data = await updateAttributeRaw(user, instance, inputs, options);
    // Only push event in stream if modifications really happens
    if (data.updatedInputs.length > 0) {
      const updatedData = updatedInputsToData(data.updatedInputs);
      await storeUpdateEvent(user, instance, [{ [operation]: updatedData }]);
    }
    const { updatedInstance, impactedInputs } = data;
    // region Update elasticsearch
    // Elastic update with partial instance to prevent data override
    if (impactedInputs.length > 0) {
      const updateAsInstance = partialInstanceWithInputs(instance, impactedInputs);
      await elUpdateElement(updateAsInstance);
    }
    // Return updated element after waiting for it.
    return updatedInstance;
  } finally {
    if (lock) await lock.unlock();
  }
};
const transformPathToInput = (patch) => {
  return R.pipe(
    R.toPairs,
    R.map((t) => {
      const val = R.last(t);
      return { key: R.head(t), value: Array.isArray(val) ? val : [val] };
    })
  )(patch);
};
export const patchAttributeRaw = async (user, instance, patch, options = {}) => {
  const inputs = transformPathToInput(patch);
  return updateAttributeRaw(user, instance, inputs, options);
};
export const patchAttribute = async (user, id, type, patch, options = {}) => {
  const inputs = transformPathToInput(patch);
  return updateAttribute(user, id, type, inputs, options);
};
// endregion

// region mutation relation
const buildRelationInsertQuery = (input) => {
  const { from, to, relationship_type: relationshipType } = input;
  // 03. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
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
    relationAttributes.x_opencti_stix_ids = isNotEmptyField(input.stix_id) ? [input.stix_id] : [];
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
        R.assoc(`i_${dataKeys[index]}_day`, dayValue),
        R.assoc(`i_${dataKeys[index]}_month`, monthValue),
        R.assoc(`i_${dataKeys[index]}_year`, yearValue)
      )(relationAttributes);
    }
  }
  // 04. Create the relation
  const fromRole = `${relationshipType}_from`;
  const toRole = `${relationshipType}_to`;
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
  return { relation: relationAttributes, query };
};
const buildInnerRelation = (from, to, type) => {
  const targets = Array.isArray(to) ? to : [to];
  if (!to || R.isEmpty(targets)) return [];
  const relations = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i];
    const input = { from, to: target, relationship_type: type };
    const { relation, query } = buildRelationInsertQuery(input);
    const basicRelation = {
      id: relation.internal_id,
      fromId: from.internal_id,
      fromRole: `${type}_from`,
      fromType: from.entity_type,
      toId: target.internal_id,
      toRole: `${type}_to`,
      toType: target.entity_type,
      base_type: BASE_TYPE_RELATION,
      parent_types: getParentTypes(relation.entity_type),
      ...relation,
    };
    relations.push({ relation: basicRelation, query });
  }
  return relations;
};
const upsertElementRaw = async (user, id, type, data) => {
  let element = await loadByIdFullyResolved(id, type, { onlyMarking: true });
  const updatedAddInputs = []; // Direct modified inputs (add)
  const updatedReplaceInputs = []; // Direct modified inputs (replace)
  const impactedInputs = []; // Inputs impacted by updated inputs + updated inputs
  // Handle attributes updates
  if (isNotEmptyField(data.stix_id)) {
    const patch = { x_opencti_stix_ids: [data.stix_id] };
    const patched = await patchAttributeRaw(user, element, patch, {
      operation: UPDATE_OPERATION_ADD,
    });
    impactedInputs.push(...patched.impactedInputs);
    updatedAddInputs.push(...patched.updatedInputs);
  }
  // Upsert the aliases
  if (isStixObjectAliased(type)) {
    const { name } = data;
    const key = resolveAliasesField(type);
    const aliases = [...(data[ATTRIBUTE_ALIASES] || []), ...(data[ATTRIBUTE_ALIASES_OPENCTI] || [])];
    if (normalizeName(element.name) !== normalizeName(name)) aliases.push(name);
    const patch = { [key]: aliases };
    const patched = await patchAttributeRaw(user, element, patch, { operation: UPDATE_OPERATION_ADD });
    impactedInputs.push(...patched.impactedInputs);
    updatedAddInputs.push(...patched.updatedInputs);
  }
  if (isStixSightingRelationship(type) && data.attribute_count) {
    const patch = { attribute_count: element.attribute_count + data.attribute_count };
    const patched = await patchAttributeRaw(user, element, patch);
    impactedInputs.push(...patched.impactedInputs);
    updatedReplaceInputs.push(...patched.updatedInputs);
  }
  if (isStixDomainObject(type) && data.update === true) {
    const fields = stixDomainObjectFieldsToBeUpdated[type];
    if (fields) {
      const patch = {};
      for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
        const fieldKey = fields[fieldIndex];
        const inputData = data[fieldKey];
        if (isNotEmptyField(inputData)) {
          patch[fieldKey] = Array.isArray(inputData) ? inputData : [inputData];
        }
      }
      if (!R.isEmpty(patch)) {
        const patched = await patchAttributeRaw(user, element, patch);
        impactedInputs.push(...patched.impactedInputs);
        updatedReplaceInputs.push(...patched.updatedInputs);
      }
    }
  }
  // Upsert markings
  const rawRelations = [];
  const targetsPerType = [];
  if (data.objectMarking && data.objectMarking.length > 0) {
    const markings = [];
    const markingsIds = R.map((m) => m.standard_id, element.objectMarking || []);
    const markingToCreate = R.filter((m) => !markingsIds.includes(m.standard_id), data.objectMarking);
    for (let index = 0; index < markingToCreate.length; index += 1) {
      const markingTo = markingToCreate[index];
      const dataRels = buildInnerRelation(element, markingTo, RELATION_OBJECT_MARKING);
      const builtQuery = R.head(dataRels);
      rawRelations.push(builtQuery.relation);
      markings.push(markingTo);
    }
    targetsPerType.push({ objectMarking: markings });
  }
  // Build the stream input
  const streamInputs = [];
  if (updatedReplaceInputs.length > 0) {
    streamInputs.push({ [UPDATE_OPERATION_REPLACE]: updatedInputsToData(updatedReplaceInputs) });
  }
  if (updatedAddInputs.length > 0 || rawRelations.length > 0) {
    let streamInput = updatedInputsToData(updatedAddInputs);
    if (rawRelations.length > 0) {
      streamInput = Object.assign(streamInput, R.mergeAll(targetsPerType));
    }
    streamInputs.push({ [UPDATE_OPERATION_ADD]: streamInput });
  }
  let indexInput;
  if (impactedInputs.length > 0) {
    element = mergeInstanceWithInputs(element, impactedInputs);
    // Build the input to reindex in elastic
    indexInput = partialInstanceWithInputs(element, impactedInputs);
  }
  // Return all elements requirement for stream and indexation
  return { type: TRX_UPDATE, element, relations: rawRelations, streamInputs, indexInput };
};

const createRelationRaw = async (user, input) => {
  const { from, to, relationship_type: relationshipType } = input;
  // 03. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // region 04. Check existing relationship
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
  // endregion
  let existingRelationship = null;
  if (existingRelationships.edges.length > 0) {
    existingRelationship = R.head(existingRelationships.edges).node;
  }
  if (existingRelationship) {
    return upsertElementRaw(user, existingRelationship.id, relationshipType, input);
  }
  // 05. Prepare the relation to be created
  const today = now();
  let data = {};
  // Default attributes
  // basic-relationship
  data.internal_id = internalId;
  data.standard_id = standardId;
  data.entity_type = relationshipType;
  data.created_at = today;
  data.updated_at = today;
  // stix-relationship
  if (isStixRelationShipExceptMeta(relationshipType)) {
    data.x_opencti_stix_ids = isNotEmptyField(input.stix_id) ? [input.stix_id] : [];
    data.spec_version = STIX_SPEC_VERSION;
    data.revoked = R.isNil(input.revoked) ? false : input.revoked;
    data.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
    data.lang = R.isNil(input.lang) ? 'en' : input.lang;
    data.created = R.isNil(input.created) ? today : input.created;
    data.modified = R.isNil(input.modified) ? today : input.modified;
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    data.relationship_type = relationshipType;
    data.description = input.description ? input.description : '';
    data.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (data.start_time > data.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-observable-relationship
  if (isStixCyberObservableRelationship(relationshipType)) {
    data.relationship_type = relationshipType;
    data.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (data.start_time > data.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-sighting-relationship
  if (isStixSightingRelationship(relationshipType)) {
    data.description = R.isNil(input.description) ? '' : input.description;
    data.attribute_count = R.isNil(input.attribute_count) ? 1 : input.attribute_count;
    data.x_opencti_negative = R.isNil(input.x_opencti_negative) ? false : input.x_opencti_negative;
    data.first_seen = R.isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen;
    data.last_seen = R.isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen;
    /* istanbul ignore if */
    if (data.first_seen > data.last_seen) {
      throw DatabaseError('You cant create a relation with a first_seen less than the last_seen', {
        from: input.fromId,
        input,
      });
    }
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
        R.assoc(`i_${dataKeys[index]}_day`, dayValue),
        R.assoc(`i_${dataKeys[index]}_month`, monthValue),
        R.assoc(`i_${dataKeys[index]}_year`, yearValue)
      )(data);
    }
  }
  // 04. Create the relation
  const fromRole = `${relationshipType}_from`;
  const toRole = `${relationshipType}_to`;
  // Build final query
  const relToCreate = [];
  if (isStixCoreRelationship(relationshipType)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
    relToCreate.push(...buildInnerRelation(data, input.objectMarking, RELATION_OBJECT_MARKING));
    relToCreate.push(...buildInnerRelation(data, input.killChainPhases, RELATION_KILL_CHAIN_PHASE));
  }
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
  )(data);
  // 09. Return result if no need to reverse the relations from and to
  const relations = relToCreate.map((r) => r.relation);
  return { type: TRX_CREATION, element: created, relations };
};
export const createRelation = async (user, input) => {
  let lock;
  const { fromId, toId, relationship_type: relationshipType } = input;
  if (fromId === toId) {
    /* istanbul ignore next */
    const errorData = { from: input.fromId, relationshipType };
    throw UnsupportedError(`Relation cant be created with the same source and target`, errorData);
  }
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(input);
  const { from, to } = resolvedInput;
  // Build lock ids
  const lockFrom = `${from.standard_id}_${relationshipType}_${to.standard_id}`;
  const lockTo = `${to.standard_id}_${relationshipType}_${from.standard_id}`;
  const lockIds = [lockFrom, lockTo];
  if (isNotEmptyField(resolvedInput.stix_id)) {
    lockIds.push(resolvedInput.stix_id);
  }
  try {
    // Try to get the lock in redis
    lock = await lockResource(lockIds);
    // noinspection UnnecessaryLocalVariableJS
    const dataRel = await createRelationRaw(user, resolvedInput);
    // Push the input in the stream
    if (dataRel.type === TRX_CREATION) {
      // If new marking, redispatch an entity creation
      if (input.relationship_type === RELATION_OBJECT_MARKING) {
        const markings = [...(from.objectMarking || []), resolvedInput.to];
        const inputEvent = R.assoc('objectMarking', markings, from);
        // In case of relation we need to full reload the from entity to redispatch it.
        // From and to of the source are required for stream message generation
        let fromCreation = from;
        if (from.base_type === BASE_TYPE_RELATION) {
          fromCreation = await loadByIdFullyResolved(from.id, from.entity_type);
        }
        await storeCreateEvent(user, fromCreation, inputEvent);
      } else {
        // Else just dispatch the relation creation
        const relWithConnections = Object.assign(dataRel.element, { from, to });
        await storeCreateEvent(user, relWithConnections, resolvedInput);
      }
    } else if (dataRel.streamInputs.length > 0) {
      // If upsert with new data
      await storeUpdateEvent(user, dataRel.element, dataRel.streamInputs);
    }
    // Index the created element
    await indexCreatedElement(dataRel);
    return dataRel.element;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw DatabaseError('Transaction fail, execution timeout. (Check your grakn sizing)', { lockIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
/* istanbul ignore next */
export const createRelations = async (user, inputs) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improve by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const relation = await createRelation(user, inputs[i]);
    createdRelations.push(relation);
  }
  return createdRelations;
};
// endregion

// region mutation entity
const createEntityRaw = async (user, standardId, participantIds, input, type) => {
  // Generate the internal id if needed
  const internalId = input.internal_id || generateInternalId();
  // Check if the entity exists
  const existingEntities = await internalFindByIds(participantIds, { type });
  if (existingEntities.length > 0) {
    if (existingEntities.length === 1) {
      return upsertElementRaw(user, R.head(existingEntities).id, type, input);
    }
    // Sometimes multiple entities can match
    // Looking for aliasA, aliasB, find in different entities for example
    // In this case, we try to find if one match the standard id
    const existingByStandard = R.find((e) => e.standard_id === standardId, existingEntities);
    if (existingByStandard) {
      // In this mode we can safely consider this entity like the existing one.
      // We can upsert element except the aliases that are part of other entities
      const concurrentEntities = R.filter((e) => e.standard_id !== standardId, existingEntities);
      const key = resolveAliasesField(type);
      const concurrentAliases = R.uniq(R.flatten(R.map((c) => c[key], concurrentEntities)));
      const filteredAliases = input[key] ? R.filter((i) => !concurrentAliases.includes(i), input[key]) : [];
      const inputAliases = Object.assign(input, { [key]: filteredAliases });
      return upsertElementRaw(user, existingByStandard.id, type, inputAliases);
    }
    // If not we dont know what to do, just throw an exception.
    const entityIds = R.map((i) => i.standard_id, existingEntities);
    throw DatabaseError('Too many entities resolved', { input, entityIds });
  }
  // Complete with identifiers
  const today = now();
  // Default attributes
  let data = R.pipe(
    R.assoc(ID_INTERNAL, internalId),
    R.assoc(ID_STANDARD, standardId),
    R.assoc('entity_type', type),
    R.dissoc('update'),
    R.dissoc('createdBy'),
    R.dissoc('objectMarking'),
    R.dissoc('objectLabel'),
    R.dissoc('killChainPhases'),
    R.dissoc('externalReferences'),
    R.dissoc('objects')
  )(input);
  // Some internal objects have dates
  if (isDatedInternalObject(type)) {
    data = R.pipe(R.assoc('created_at', today), R.assoc('updated_at', today))(data);
  }
  // Stix-Object
  if (isStixObject(type)) {
    data = R.pipe(
      R.assoc(IDS_STIX, isNotEmptyField(input.stix_id) ? [input.stix_id.toLowerCase()] : []),
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
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    const aliases = [input.name, ...(data[ATTRIBUTE_ALIASES] || []), ...(data[ATTRIBUTE_ALIASES_OPENCTI] || [])];
    if (type === ENTITY_TYPE_ATTACK_PATTERN && input.x_mitre_id) {
      aliases.push(input.x_mitre_id);
    }
    data = R.assoc(INTERNAL_IDS_ALIASES, generateAliasesId(aliases), data);
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
        R.assoc(`i_${dataKeys[index]}_day`, dayValue),
        R.assoc(`i_${dataKeys[index]}_month`, monthValue),
        R.assoc(`i_${dataKeys[index]}_year`, yearValue)
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
  const relToCreate = [];
  if (isStixCoreObject(type)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
    relToCreate.push(...buildInnerRelation(data, input.objectMarking, RELATION_OBJECT_MARKING));
    relToCreate.push(...buildInnerRelation(data, input.objectLabel, RELATION_OBJECT_LABEL));
    relToCreate.push(...buildInnerRelation(data, input.killChainPhases, RELATION_KILL_CHAIN_PHASE));
    relToCreate.push(...buildInnerRelation(data, input.externalReferences, RELATION_EXTERNAL_REFERENCE));
    relToCreate.push(...buildInnerRelation(data, input.objects, RELATION_OBJECT));
  }
  logger.debug(`[GRAKN - infer: false] createEntity`, { query });
  // Transaction succeed, complete the result to send it back
  const created = R.pipe(
    R.assoc('id', internalId),
    R.assoc('base_type', BASE_TYPE_ENTITY),
    R.assoc('parent_types', getParentTypes(type))
  )(data);
  // Simply return the data
  const relations = relToCreate.map((r) => r.relation);
  return { type: TRX_CREATION, element: created, relations };
};
export const createEntity = async (user, input, type) => {
  let lock;
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(input);
  // Generate all the possibles ids
  // For marking def, we need to force the standard_id
  const standardId = input.standard_id || generateStandardId(type, resolvedInput);
  const participantIds = [standardId];
  if (isStixObjectAliased(type)) {
    const aliases = [resolvedInput.name, ...(resolvedInput.aliases || []), ...(resolvedInput.x_opencti_aliases || [])];
    participantIds.push(...generateAliasesId(aliases));
  }
  if (isNotEmptyField(resolvedInput.stix_id)) {
    participantIds.push(resolvedInput.stix_id);
  }
  // Create the element
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    const dataEntity = await createEntityRaw(user, standardId, participantIds, resolvedInput, type);
    // Push the input in the stream
    if (dataEntity.type === TRX_CREATION) {
      await storeCreateEvent(user, dataEntity.element, resolvedInput);
    } else if (dataEntity.streamInputs.length > 0) {
      // If upsert with new data
      await storeUpdateEvent(user, dataEntity.element, dataEntity.streamInputs);
    }
    // Index the created element
    await indexCreatedElement(dataEntity);
    // Return created element after waiting for it.
    return dataEntity.element;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw DatabaseError('Transaction fail, execution timeout. (Check your grakn sizing)', { participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
// endregion

// region mutation deletion
/*
const getElementsRelated = async (targetId, elements = [], options = {}) => {
  const eid = escapeString(targetId);
  const read = `match $from has internal_id "${eid}"; $rel($from, $to) isa ${ABSTRACT_BASIC_RELATIONSHIP}; get;`;
  const connectedRelations = await find(read, ['rel'], options);
  const connectedRelationsIds = R.map((r) => {
    const { internal_id: internalId, entity_type: entityType } = r.rel;
    return { internal_id: internalId, type: entityType, relDependency: true };
  }, connectedRelations);
  elements.push(...connectedRelationsIds);
  await Promise.all(connectedRelationsIds.map(({ id }) => getElementsRelated(id, elements, options)));
  return elements;
};

const deleteElementRaw = async (wTx, element, isRelation, options = {}) => {
  // 00. Load everything we need to remove
  const dependencies = [{ internal_id: element.internal_id, type: element.entity_type, relDependency: isRelation }];
  await getElementsRelated(element.internal_id, dependencies, options);
  // 01. Delete dependencies.
  // Remove all dep in reverse order to handle correctly relations
  for (let i = dependencies.length - 1; i >= 0; i -= 1) {
    const { internal_id: id, type } = dependencies[i];
    const query = `match $x has internal_id "${id}"; delete $x isa ${type};`;
    logger.debug(`[GRAKN - infer: false] delete element ${id}`, { query });
    // eslint-disable-next-line no-await-in-loop
    await wTx.query(query, { infer: false });
  }
  // Return list of deleted ids
  return dependencies;
}; */
export const deleteElementById = async (user, elementId, type, options = {}) => {
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting an entity`);
  }
  // Check consistency
  const element = await loadByIdFullyResolved(elementId, type, options);
  if (element === null) {
    throw DatabaseError(`Cant find entity to delete ${elementId}`);
  }
  // Delete entity and all dependencies
  // const deps = await executeWrite(async (wTx) => {
  //   const delDependencies = await deleteElementRaw(wTx, element, false, options);
  //   await storeDeleteEvent(user, element);
  //   return delDependencies;
  // });
  // TODO JRI MIGRATION
  const deps = [];
  // Update elastic index.
  for (let index = 0; index < deps.length; index += 1) {
    const { internal_id: id, relDependency } = deps[index];
    if (relDependency) {
      // eslint-disable-next-line
      await elRemoveRelationConnection(id);
    }
    // 02. Remove the element itself from the index
    // eslint-disable-next-line
    await elDeleteInstanceIds([id]);
  }
  return elementId;
};
export const deleteRelationsByFromAndTo = async () => {
  // /* istanbul ignore if */
  // if (R.isNil(scopeType)) {
  //   throw FunctionalError(`You need to specify a scope type when deleting a relation with from and to`);
  // }
  // const fromThing = await internalLoadById(fromId, opts);
  // const toThing = await internalLoadById(toId, opts);
  // const read = `match $from has internal_id "${fromThing.internal_id}";
  //   $to has internal_id "${toThing.internal_id}";
  //   $rel($from, $to) isa ${relationshipType}; get;`;
  // const relationsToDelete = await find(read, ['rel'], opts);
  // for (let i = 0; i < relationsToDelete.length; i += 1) {
  //   const r = relationsToDelete[i];
  //   // eslint-disable-next-line no-await-in-loop
  //   await deleteElementById(user, r.rel.internal_id, r.rel.entity_type, opts);
  // }
  // TODO JRI MIGRATION
  return true;
};
export const deleteAttributeById = async (id) => {
  // TODO JRI MIGRATION
  return id;
  // return executeWrite(async (wTx) => {
  //   const query = `match $x id ${escape(id)}; delete $x isa thing;`;
  //   logger.debug(`[GRAKN - infer: false] deleteAttributeById`, { query });
  //   await wTx.query(query, { infer: false });
  //   return id;
  // });
};
// endregion
