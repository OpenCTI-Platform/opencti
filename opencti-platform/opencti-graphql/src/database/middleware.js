import moment from 'moment';
import * as R from 'ramda';
import DataLoader from 'dataloader';
import { Promise } from 'bluebird';
import {
  DatabaseError,
  FunctionalError,
  LockTimeoutError,
  MissingReferenceError,
  TYPE_LOCK_ERROR,
  UnsupportedError,
} from '../config/errors';
import {
  buildPagination,
  fillTimeSeries,
  inferIndexFromConceptType,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  READ_DATA_INDICES,
  READ_ENTITIES_INDICES,
  READ_RELATIONSHIPS_INDICES,
  relationTypeToInputName,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE,
} from './utils';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elDeleteElements,
  elFindByFromAndTo,
  elFindByIds,
  elHistogramCount,
  elIndexElements,
  elList,
  elLoadById,
  elPaginate,
  elUpdateElement,
  elUpdateEntityConnections,
  elUpdateRelationConnections,
  ES_MAX_CONCURRENCY,
  isImpactedTypeAndSide,
  MAX_SPLIT,
  ROLE_FROM,
  ROLE_TO,
} from './elasticSearch';
import {
  generateAliasesIdsForInstance,
  generateAliasesId,
  generateInternalId,
  generateStandardId,
  INTERNAL_FROM_FIELD,
  INTERNAL_TO_FIELD,
  isFieldContributingToStandardId,
  isTypeHasAliasIDs,
  NAME_FIELD,
  normalizeName,
  REVOKED,
  VALID_UNTIL,
  getInputIds,
  getInstanceIds,
} from '../schema/identifier';
import {
  buildDeleteEvent,
  lockResource,
  notify,
  redisAddDeletions,
  storeCreateEvent,
  storeDeleteEvent,
  storeMergeEvent,
  storeUpdateEvent,
} from './redis';
import {
  buildStixData,
  checkStixCoreRelationshipMapping,
  checkStixCyberObservableRelationshipMapping,
  cleanStixIds,
  STIX_SPEC_VERSION,
} from './stix';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  INTERNAL_IDS_ALIASES,
  INTERNAL_PREFIX,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
  schemaTypes,
} from '../schema/general';
import { getParentTypes, isAnId } from '../schema/schemaUtils';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import {
  isStixSingleMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { internalObjectsFieldsToBeUpdated, isDatedInternalObject, isInternalObject } from '../schema/internalObject';
import { isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isStixRelationShipExceptMeta } from '../schema/stixRelationship';
import {
  booleanAttributes,
  dateAttributes,
  dictAttributes,
  isDictionaryAttribute,
  isModifiedObject,
  isMultipleAttribute,
  isUpdatedAtObject,
  multipleAttributes,
  numericAttributes,
  statsDateAttributes,
} from '../schema/fieldDataAdapter';
import { isStixCoreRelationship, RELATION_REVOKED_BY } from '../schema/stixCoreRelationship';
import {
  ATTRIBUTE_ALIASES,
  ATTRIBUTE_ALIASES_OPENCTI,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INDICATOR,
  isStixDomainObject,
  isStixObjectAliased,
  resolveAliasesField,
  stixDomainObjectFieldsToBeUpdated,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_LABEL, isStixMetaObject } from '../schema/stixMetaObject';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCyberObservable, stixCyberObservableFieldsToBeUpdated } from '../schema/stixCyberObservable';
import { BUS_TOPICS, logApp } from '../config/conf';
import {
  dayFormat,
  escape,
  FROM_START,
  FROM_START_STR,
  monthFormat,
  now,
  prepareDate,
  UNTIL_END,
  UNTIL_END_STR,
  utcDate,
  yearFormat,
} from '../utils/format';
import { checkObservableSyntax } from '../utils/syntax';
import { deleteAllFiles } from './minio';
import { filterElementsAccordingToUser, SYSTEM_USER } from '../utils/access';
import { createClearRulePatch, isRuleUser, RULE_MANAGER_USER } from '../rules/RuleUtils';

// region global variables
export const MAX_BATCH_SIZE = 300;
// endregion

// region Loader common
export const batchLoader = (loader) => {
  const dataLoader = new DataLoader(
    (objects) => {
      const { user, args } = R.head(objects);
      const ids = objects.map((i) => i.id);
      return loader(user, ids, args);
    },
    { maxBatchSize: MAX_BATCH_SIZE }
  );
  return {
    load: (id, user, args = {}) => {
      return dataLoader.load({ id, user, args });
    },
  };
};
export const querySubTypes = async ({ type }) => {
  const sortByLabel = R.sortBy(R.toLower);
  const types = schemaTypes.get(type);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } }))
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};
export const queryAttributes = async (type) => {
  const attributes = schemaTypes.getAttributes(type);
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: n, value: n } }))
  )(attributes);
  return buildPagination(0, null, finalResult, finalResult.length);
};
const checkInferenceRight = (user, element) => {
  const isRuleManaged = isRuleUser(user);
  const isPurelyInferred = isInferredIndex(element._index);
  if (isPurelyInferred && !isRuleManaged) {
    throw UnsupportedError('Manual inference update/deletion is not allowed', { id: element.id });
  }
};
// endregion

// region bulk loading method
// Listing handle
const batchListThrough = async (user, sources, sourceSide, relationType, targetEntityType, opts = {}) => {
  const { paginate = true, batched = true, first = null } = opts;
  const opposite = sourceSide === 'from' ? 'to' : 'from';
  // USING ELASTIC
  const ids = Array.isArray(sources) ? sources : [sources];
  // Filter on connection to get only relation coming from ids.
  const directionInternalIdFilter = {
    key: 'connections',
    nested: [
      { key: 'internal_id', values: ids },
      { key: 'role', values: [`*_${sourceSide}`], operator: 'wildcard' },
    ],
  };
  // Filter the other side of the relation to have expected toEntityType
  const oppositeTypeFilter = {
    key: 'connections',
    nested: [
      { key: 'types', values: [targetEntityType] },
      { key: 'role', values: [`*_${opposite}`], operator: 'wildcard' },
    ],
  };
  const filters = [directionInternalIdFilter, oppositeTypeFilter];
  // Resolve all relations
  const relations = await elList(user, READ_RELATIONSHIPS_INDICES, {
    filters,
    types: [relationType],
    connectionFormat: false,
  });
  // For each relation resolved the target entity
  const targets = await elFindByIds(user, R.uniq(relations.map((s) => s[`${opposite}Id`])));
  // Group and rebuild the result
  const elGrouped = R.groupBy((e) => e[`${sourceSide}Id`], relations);
  if (paginate) {
    return ids.map((id) => {
      let values = elGrouped[id];
      let edges = [];
      if (values) {
        if (first) {
          values = R.take(first, values);
        }
        edges = values.map((i) => ({ node: R.find((s) => s.internal_id === i[`${opposite}Id`], targets) }));
      }
      return buildPagination(0, null, edges, edges.length);
    });
  }
  const elements = ids.map((id) => {
    let values = elGrouped[id];
    if (first) {
      values = R.take(first, values);
    }
    return values?.map((i) => R.find((s) => s.internal_id === i[`${opposite}Id`], targets)) || [];
  });
  if (batched) {
    return elements;
  }
  return R.flatten(elements);
};
export const batchListThroughGetFrom = async (user, sources, relationType, targetEntityType, opts = {}) => {
  return batchListThrough(user, sources, 'to', relationType, targetEntityType, opts);
};
export const listThroughGetFrom = async (user, sources, relationType, targetEntityType, opts = { paginate: false }) => {
  const options = { ...opts, batched: false };
  return batchListThrough(user, sources, 'to', relationType, targetEntityType, options);
};
export const batchListThroughGetTo = async (user, sources, relationType, targetEntityType, opts = {}) => {
  return batchListThrough(user, sources, 'from', relationType, targetEntityType, opts);
};
export const listThroughGetTo = async (user, sources, relationType, targetEntityType, opts = { paginate: false }) => {
  const options = { ...opts, batched: false };
  return batchListThrough(user, sources, 'from', relationType, targetEntityType, options);
};
// Unary handle
const loadThrough = async (user, sources, sourceSide, relationType, targetEntityType) => {
  const elements = await batchListThrough(user, sources, sourceSide, relationType, targetEntityType, {
    paginate: false,
    batched: false,
  });
  if (elements.length > 1) {
    throw DatabaseError('Expected one element only through relation', { sources, relationType, targetEntityType });
  }
  return R.head(elements);
};
export const batchLoadThroughGetFrom = async (user, sources, relationType, targetEntityType) => {
  const data = await batchListThroughGetFrom(user, sources, relationType, targetEntityType, { paginate: false });
  return data.map((b) => b && R.head(b));
};
export const loadThroughGetFrom = async (user, sources, relationType, targetEntityType) => {
  return loadThrough(user, sources, 'to', relationType, targetEntityType);
};
export const batchLoadThroughGetTo = async (user, sources, relationType, targetEntityType) => {
  const data = await batchListThroughGetTo(user, sources, relationType, targetEntityType, { paginate: false });
  return data.map((b) => b && R.head(b));
};
export const loadThroughGetTo = async (user, sources, relationType, targetEntityType) => {
  return loadThrough(user, sources, 'from', relationType, targetEntityType);
};
// Standard listing
const buildRelationsFilter = (relationshipType, args) => {
  const { relationFilter = false } = args;
  const {
    filters = [],
    search,
    elementId,
    fromId,
    fromRole,
    toId,
    toRole,
    fromTypes = [],
    toTypes = [],
    elementWithTargetTypes = [],
    relationshipTypes = [],
  } = args;
  const {
    startTimeStart,
    startTimeStop,
    stopTimeStart,
    stopTimeStop,
    firstSeenStart,
    firstSeenStop,
    lastSeenStart,
    lastSeenStop,
    startDate,
    endDate,
    confidences = [],
  } = args;
  // Use $from, $to only if fromId or toId specified.
  // Else, just ask for the relation only.
  // fromType or toType only allow if fromId or toId available
  const definedRoles = !R.isNil(fromRole) || !R.isNil(toRole);
  const askForConnections = !R.isNil(elementId) || !R.isNil(fromId) || !R.isNil(toId) || definedRoles;
  const haveTargetFilters = filters && filters.length > 0; // For now filters only contains target to filtering
  const elementWithTargetTypesFilter = elementWithTargetTypes && elementWithTargetTypes.length > 0;
  const fromTypesFilter = fromTypes && fromTypes.length > 0;
  const toTypesFilter = toTypes && toTypes.length > 0;
  if (
    askForConnections === false &&
    (haveTargetFilters || fromTypesFilter || toTypesFilter || elementWithTargetTypesFilter || search)
  ) {
    throw DatabaseError('Cant list relation with types filtering or search if from or to id are not specified');
  }
  // Handle relation type(s)
  const relationToGet = relationshipType || 'stix-core-relationship';
  // 0 - Check if we can support the query by Elastic
  const finalFilters = filters;
  if (relationFilter) {
    const { relation, id, relationId } = relationFilter;
    finalFilters.push({ key: buildRefRelationKey(relation), values: [id] });
    if (relationId) {
      finalFilters.push({ key: `internal_id`, values: [relationId] });
    }
  }
  const nestedElement = [];
  if (elementId) {
    nestedElement.push({ key: 'internal_id', values: [elementId] });
  }
  if (nestedElement.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedElement });
  }
  const nestedElementTypes = [];
  if (elementWithTargetTypes && elementWithTargetTypes.length > 0) {
    nestedElementTypes.push({ key: 'types', values: elementWithTargetTypes });
  }
  if (nestedElementTypes.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedElementTypes });
  }
  // region from filtering
  const nestedFrom = [];
  if (fromId) {
    nestedFrom.push({ key: 'internal_id', values: [fromId] });
  }
  if (fromTypes && fromTypes.length > 0) {
    nestedFrom.push({ key: 'types', values: fromTypes });
  }
  if (fromRole) {
    nestedFrom.push({ key: 'role', values: [fromRole] });
  } else if (fromId || (fromTypes && fromTypes.length > 0)) {
    nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
  }
  if (nestedFrom.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedFrom });
  }
  // endregion
  // region to filtering
  const nestedTo = [];
  if (toId) {
    nestedTo.push({ key: 'internal_id', values: [toId] });
  }
  if (toTypes && toTypes.length > 0) {
    nestedTo.push({ key: 'types', values: toTypes });
  }
  if (toRole) {
    nestedTo.push({ key: 'role', values: [toRole] });
  } else if (toId || (toTypes && toTypes.length > 0)) {
    nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
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
  if (startDate) finalFilters.push({ key: 'created_at', values: [startDate], operator: 'gt' });
  if (endDate) finalFilters.push({ key: 'created_at', values: [endDate], operator: 'lt' });
  if (confidences && confidences.length > 0) finalFilters.push({ key: 'confidence', values: confidences });
  return R.pipe(
    R.assoc('types', relationshipTypes && relationshipTypes.length > 0 ? relationshipTypes : [relationToGet]),
    R.assoc('filters', finalFilters)
  )(args);
};
const buildThingsFilter = (thingsTypes, args) => {
  return R.assoc('types', thingsTypes, args);
};
export const listThings = async (user, thingsTypes, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildThingsFilter(thingsTypes, args);
  return elPaginate(user, indices, paginateArgs);
};
export const listAllThings = async (user, thingsTypes, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildThingsFilter(thingsTypes, args);
  return elList(user, indices, paginateArgs);
};
export const paginateAllThings = async (user, thingsTypes, args = {}) => {
  const result = await listAllThings(user, thingsTypes, args);
  const nodeResult = result.map((n) => ({ node: n }));
  return buildPagination(0, null, nodeResult, nodeResult.length);
};
const buildEntitiesFilter = (entityTypes, args) => {
  return R.assoc('types', entityTypes, args);
};
export const listEntities = async (user, entityTypes, args = {}) => {
  const { indices = READ_ENTITIES_INDICES } = args;
  const paginateArgs = buildEntitiesFilter(entityTypes, args);
  return elPaginate(user, indices, paginateArgs);
};
export const listRelations = async (user, relationshipType, args) => {
  const { indices = READ_RELATIONSHIPS_INDICES } = args;
  const paginateArgs = buildRelationsFilter(relationshipType, args);
  return elPaginate(user, indices, paginateArgs);
};
export const listAllRelations = async (user, relationshipType, args) => {
  const { indices = READ_RELATIONSHIPS_INDICES } = args;
  const paginateArgs = buildRelationsFilter(relationshipType, args);
  return elList(user, indices, paginateArgs);
};
export const loadEntity = async (user, entityTypes, args = {}) => {
  const opts = { ...args, connectionFormat: false };
  const entities = await listEntities(user, entityTypes, opts);
  if (entities.length > 1) {
    throw DatabaseError('Expect only one response', { entityTypes, args });
  }
  return entities && R.head(entities);
};
// endregion

// region Loader element
export const internalFindByIds = (user, ids, args = {}) => {
  return elFindByIds(user, ids, args);
};
export const internalLoadById = (user, id, args = {}) => {
  const { type } = args;
  return elLoadById(user, id, type);
};
export const loadById = async (user, id, type, args = {}) => {
  if (R.isNil(type) || R.isEmpty(type)) {
    throw FunctionalError(`You need to specify a type when loading a element`);
  }
  const loadArgs = R.assoc('type', type, args);
  return internalLoadById(user, id, loadArgs);
};
const transformRawRelationsToAttributes = (data) => {
  return R.mergeAll(Object.entries(R.groupBy((a) => a.i_relation.entity_type, data)).map(([k, v]) => ({ [k]: v })));
};
const loadElementDependencies = async (user, element, args = {}) => {
  const { dependencyType = ABSTRACT_STIX_RELATIONSHIP } = args;
  const { onlyMarking = true, fullResolve = false } = args;
  const elementId = element.internal_id;
  const relType = onlyMarking ? RELATION_OBJECT_MARKING : dependencyType;
  // Resolve all relations
  // noinspection ES6MissingAwait
  const toRelationsPromise = fullResolve ? listAllRelations(user, relType, { toId: elementId }) : [];
  const fromRelationsPromise = listAllRelations(user, relType, { fromId: elementId });
  const [fromRelations, toRelations] = await Promise.all([fromRelationsPromise, toRelationsPromise]);
  const data = {};
  // Parallel resolutions
  const toResolvedIds = R.uniq(fromRelations.map((rel) => rel.toId));
  const fromResolvedIds = R.uniq(toRelations.map((rel) => rel.fromId));
  const toResolvedPromise = elFindByIds(user, toResolvedIds, { toMap: true });
  const fromResolvedPromise = elFindByIds(user, fromResolvedIds, { toMap: true });
  const [toResolved, fromResolved] = await Promise.all([toResolvedPromise, fromResolvedPromise]);
  if (fromRelations.length > 0) {
    // Build the flatten view inside the data
    const grouped = R.groupBy((a) => relationTypeToInputName(a.entity_type), fromRelations);
    const entries = Object.entries(grouped);
    for (let index = 0; index < entries.length; index += 1) {
      const [key, values] = entries[index];
      data[key] = R.map((v) => ({ ...toResolved[v.toId], i_relation: v }), values);
    }
    if (fullResolve) {
      const flatRelations = fromRelations.map((rel) => ({ ...toResolved[rel.toId], i_relation: rel }));
      data[INTERNAL_FROM_FIELD] = transformRawRelationsToAttributes(flatRelations);
    }
  }
  if (toRelations.length > 0) {
    const flatRelations = toRelations.map((rel) => ({ ...fromResolved[rel.fromId], i_relation: rel }));
    data[INTERNAL_TO_FIELD] = transformRawRelationsToAttributes(flatRelations);
  }
  return data;
};
export const loadAnyWithDependencies = async (user, element, args = {}) => {
  const depsPromise = loadElementDependencies(user, element, args);
  const isRelation = element.base_type === BASE_TYPE_RELATION;
  if (isRelation) {
    const relOpts = { onlyMarking: true, fullResolve: false };
    // eslint-disable-next-line no-use-before-define
    const fromPromise = loadByIdWithDependencies(user, element.fromId, element.fromType, relOpts);
    // eslint-disable-next-line no-use-before-define
    const toPromise = loadByIdWithDependencies(user, element.toId, element.toType, relOpts);
    const [from, to, deps] = await Promise.all([fromPromise, toPromise, depsPromise]);
    return R.mergeRight(element, { from, to, ...deps });
  }
  const deps = await depsPromise;
  return R.mergeRight(element, { ...deps });
};
export const loadByIdWithDependencies = async (user, id, type, args = {}) => {
  const element = await internalLoadById(user, id, { type });
  if (!element) return null;
  return loadAnyWithDependencies(user, element, args);
};
export const loadByQueryWithDependencies = async (user, query, args) => {
  const elements = await elPaginate(user, query.index, query.opts);
  const element = elements.length === 1 ? R.head(elements) : undefined;
  if (!element) return null;
  return loadAnyWithDependencies(user, element, args);
};
// Dangerous call because get everything related. (Limited to merging)
export const fullLoadById = async (user, id, type = null) => {
  const element = await loadByIdWithDependencies(user, id, type, { onlyMarking: false, fullResolve: true });
  return { ...element, i_fully_resolved: true };
};
// Get element with every elements connected element -> rel -> to
export const stixLoadById = async (user, id, type = null) => {
  return loadByIdWithDependencies(user, id, type, {
    dependencyType: ABSTRACT_STIX_META_RELATIONSHIP,
    onlyMarking: false,
    fullResolve: false,
  });
};
export const stixLoadByQuery = async (user, query) => {
  return loadByQueryWithDependencies(user, query, {
    dependencyType: ABSTRACT_STIX_META_RELATIONSHIP,
    onlyMarking: false,
    fullResolve: false,
  });
};
export const stixElementLoader = async (user, id, type) => {
  const element = await stixLoadById(user, id, type);
  return element && buildStixData(element);
};
// endregion

// region Graphics
const restrictedAggElement = { name: 'Restricted', entity_type: 'Malware', parent_types: [] };
const convertAggregateDistributions = async (user, limit, orderingFunction, distribution) => {
  const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distribution));
  // eslint-disable-next-line prettier/prettier
  const resolveLabels = await elFindByIds(user, data.map((d) => d.label), { toMap: true });
  return R.map((n) => {
    const resolved = resolveLabels[n.label];
    const resolvedData = resolved || restrictedAggElement;
    return R.assoc('entity', resolvedData, n);
  }, data);
};
export const timeSeriesEntities = async (user, entityType, filters, options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid } ]
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, field, interval, toTypes = [] } = options;
  // Check if can be supported by ES
  const histogramData = await elHistogramCount(user, entityType, field, interval, startDate, endDate, toTypes, filters);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesRelations = async (user, options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid }
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, relationship_type: relationshipType, field, interval, toTypes = [] } = options;
  const { fromId } = options;
  // Check if can be supported by ES
  const entityType = relationshipType ? escape(relationshipType) : 'stix-relationship';
  const filters = fromId ? [{ isRelation: false, isNested: true, type: 'connections.internal_id', value: fromId }] : [];
  const histogramData = await elHistogramCount(user, entityType, field, interval, startDate, endDate, toTypes, filters);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionEntities = async (user, entityType, filters = [], options) => {
  // filters: { isRelation: true, type: stix_relation, start: date, end: date, value: uuid }
  const { limit = 10, order = 'desc' } = options;
  const { startDate, endDate, field } = options;
  // Unsupported in cache: const { isRelation, value, from, to, start, end, type };
  if (field.includes('.') && !field.endsWith('internal_id')) {
    throw FunctionalError('Distribution entities does not support relation aggregation field');
  }
  let finalField = field;
  if (field.includes('.')) {
    finalField = REL_INDEX_PREFIX + field;
  }
  const distributionData = await elAggregationCount(user, entityType, finalField, startDate, endDate, filters);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL)) {
    return convertAggregateDistributions(user, limit, orderingFunction, distributionData);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionRelations = async (user, options) => {
  const { field } = options; // Mandatory fields
  const { limit = 50, order } = options;
  const { relationship_type: relationshipType, dateAttribute = 'created_at' } = options;
  const entityType = relationshipType ? escape(relationshipType) : ABSTRACT_STIX_CORE_RELATIONSHIP;
  const distDateAttribute = dateAttribute || 'created_at';
  // Using elastic can only be done if the distribution is a count on types
  const opts = { ...options, dateAttribute: distDateAttribute };
  const distributionData = await elAggregationRelationsCount(user, entityType, opts);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field === ID_INTERNAL) {
    return convertAggregateDistributions(user, limit, orderingFunction, distributionData);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
// endregion

// region mutation common
const TRX_CREATION = 'creation';
const TRX_UPDATE = 'update';
const depsKeys = [
  { src: 'fromId', dst: 'from' },
  { src: 'toId', dst: 'to' },
  { src: INPUT_CREATED_BY },
  { src: INPUT_MARKINGS },
  { src: INPUT_LABELS },
  { src: INPUT_KILLCHAIN },
  { src: INPUT_EXTERNAL_REFS },
  { src: INPUT_OBJECTS },
];
const idLabel = (label) => {
  return isAnId(label) ? label : generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(label) });
};
const inputResolveRefs = async (user, input, type) => {
  const fetchingIds = [];
  const expectedIds = [];
  for (let index = 0; index < depsKeys.length; index += 1) {
    const { src, dst } = depsKeys[index];
    const destKey = dst || src;
    const id = input[src];
    if (!R.isNil(id) && !R.isEmpty(id)) {
      const isListing = Array.isArray(id);
      // Handle specific case of object label that can be directly the value instead of the key.
      if (src === INPUT_LABELS) {
        const elements = R.map((label) => ({ id: idLabel(label), destKey, multiple: true }), id);
        fetchingIds.push(...elements);
        expectedIds.push(...elements.map((e) => e.id));
      } else if (isListing) {
        const elements = R.uniq(id).map((i) => ({ id: i, destKey, multiple: true }));
        expectedIds.push(...R.uniq(id));
        fetchingIds.push(...elements);
      } else {
        expectedIds.push(id);
        fetchingIds.push({ id, destKey, multiple: false });
      }
    }
  }
  // eslint-disable-next-line prettier/prettier
  const resolvedElements = await internalFindByIds(user, fetchingIds.map((i) => i.id));
  const resolvedElementWithConfGroup = resolvedElements.map((d) => {
    const elementIds = getInstanceIds(d);
    const matchingConfigs = R.filter((a) => elementIds.includes(a.id), fetchingIds);
    return matchingConfigs.map((c) => ({ ...d, i_group: c }));
  });
  const allResolvedElements = R.flatten(resolvedElementWithConfGroup);
  const uniqElement = (a, b) => a.internal_id === b.internal_id && a.i_group.destKey === b.i_group.destKey;
  const filteredElements = R.uniqWith(uniqElement, allResolvedElements);
  const groupByTypeElements = R.groupBy((e) => e.i_group.destKey, filteredElements);
  const resolved = Object.entries(groupByTypeElements).map(([k, val]) => {
    const isMultiple = R.head(val).i_group.multiple;
    if (val.length === 1) {
      return { [k]: isMultiple ? val : R.head(val) };
    }
    if (!isMultiple) {
      throw UnsupportedError('Resolve to multiple');
    }
    return { [k]: val };
  });
  const resolvedIds = R.flatten(
    R.map((r) => {
      const [, val] = R.head(Object.entries(r));
      if (isNotEmptyField(val)) {
        const values = Array.isArray(val) ? val : [val];
        return R.map((v) => getInstanceIds(v), values);
      }
      return [];
    }, resolved)
  );
  const unresolvedIds = R.filter((n) => !R.includes(n, resolvedIds), expectedIds);
  if (unresolvedIds.length > 0) {
    throw MissingReferenceError({ input, unresolvedIds });
  }
  const complete = { ...input, entity_type: type };
  const resolvedRefs = R.mergeAll(resolved);
  return R.mergeRight(complete, resolvedRefs);
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
const computeConfidenceLevel = (input) => {
  let confidence = 15;
  const creator = input.createdBy;
  if (creator) {
    switch (creator.x_opencti_reliability) {
      case 'A':
        confidence = 85;
        break;
      case 'B':
        confidence = 75;
        break;
      case 'C':
        confidence = 50;
        break;
      default:
        confidence = 15;
    }
  }
  return confidence;
};
// endregion

// region mutation update
const mergeDeepRightAll = R.unapply(R.reduce(R.mergeDeepRight, {}));
const updatedInputsToData = (inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value } = input;
    const val = R.includes(key, multipleAttributes) ? value : R.head(value);
    return { [key]: val };
  }, inputs);
  return mergeDeepRightAll(...inputPairs);
};
const replacedInputsToData = (inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value, previous } = input;
    const val = R.includes(key, multipleAttributes) ? value : R.head(value);
    return { [key]: { current: val, previous } };
  }, inputs);
  return mergeDeepRightAll(...inputPairs);
};
const mergeInstanceWithInputs = (instance, inputs) => {
  const data = updatedInputsToData(inputs);
  return R.mergeRight(instance, data);
};
const partialInstanceWithInputs = (instance, inputs) => {
  const inputData = updatedInputsToData(inputs);
  return {
    _index: instance._index,
    internal_id: instance.internal_id,
    entity_type: instance.entity_type,
    ...inputData,
  };
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
    if (currentJson && currentJson[targetKey] === compareValue) {
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
    const isDate = dateAttributes.includes(key);
    if (!forceUpdate) {
      if (isDate && utcDate(instance[key]).isSame(utcDate(R.head(value)))) {
        return {};
      }
      if (R.equals(instance[key], R.head(value))) {
        return {}; // No need to update the attribute
      }
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
                entity_type: key,
                connect: val.internal_id,
                connect_index: val._index,
                relation: val.i_relation,
                internal_id: val.i_relation.internal_id,
                standard_id: val.i_relation.standard_id,
              };
            }, values)
          );
        }
      }
      return relations;
    }, entities)
  );
};

const ed = (date) => isEmptyField(date) || date === FROM_START_STR || date === UNTIL_END_STR;
const noDate = (e) => ed(e.first_seen) && ed(e.last_seen) && ed(e.start_time) && ed(e.stop_time);
const filterTargetByExisting = (sources, targets) => {
  const filtered = [];
  const cache = [];
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index];
    // If the relation source is already in target = filtered
    const finder = (t) => t.entity_type === source.entity_type && t.connect === source.connect && noDate(t.relation);
    const id = `${source.entity_type}-${source.connect}`;
    if (!R.find(finder, targets) && !cache.includes(id)) {
      filtered.push(source);
      cache.push(id);
    }
  }
  return filtered;
};

const mergeEntitiesRaw = async (user, targetEntity, sourceEntities, opts = {}) => {
  const { chosenFields = {} } = opts;
  // 01 Check if everything is fully resolved.
  const elements = [targetEntity, ...sourceEntities];
  const notFullyResolved = elements.filter((e) => e.i_fully_resolved).length !== elements.length;
  if (notFullyResolved) {
    throw UnsupportedError('[OPENCTI] Merging required full resolved inputs');
  }
  logApp.info(`[OPENCTI] Merging ${sourceEntities.map((i) => i.internal_id).join(',')} in ${targetEntity.internal_id}`);
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
  // 2. EACH SOURCE (Ignore createdBy)
  // - EVERYTHING I TARGET (->to) ==> We change to relationship FROM -> TARGET ENTITY
  // - EVERYTHING TARGETING ME (-> from) ==> We change to relationship TO -> TARGET ENTITY
  // region CHANGING FROM
  const allTargetToRelations = targetedRelations([targetEntity], 'from');
  const allSourcesToRelations = targetedRelations(sourceEntities, 'from');
  const relationsToRedirectFrom = filterTargetByExisting(allSourcesToRelations, allTargetToRelations);
  // region CHANGING TO
  const allTargetFromRelations = targetedRelations([targetEntity], 'to');
  const allSourcesFromRelations = targetedRelations(sourceEntities, 'to');
  const relationsFromRedirectTo = filterTargetByExisting(allSourcesFromRelations, allTargetFromRelations);
  const updateConnections = [];
  const updateEntities = [];
  // FROM (x -> MERGED TARGET) --- (from) relation (to) ---- RELATED_ELEMENT
  // noinspection DuplicatedCode
  for (let indexFrom = 0; indexFrom < relationsToRedirectFrom.length; indexFrom += 1) {
    const r = relationsToRedirectFrom[indexFrom];
    const sideToRedirect = r.relation.fromId;
    const sideToKeep = r.relation.toId;
    const sideToKeepType = r.relation.toType;
    const sideTarget = targetEntity.internal_id;
    const relationType = r.relation.entity_type;
    // Replace relation connection fromId with the new TARGET
    const relUpdate = {
      _index: r.relation._index,
      id: r.internal_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    if (isImpactedTypeAndSide(r.entity_type, ROLE_TO)) {
      updateEntities.push({
        _index: r.connect_index,
        id: sideToKeep,
        toReplace: sideToRedirect,
        relationType,
        entity_type: sideToKeepType,
        data: { internal_id: sideTarget },
      });
    }
    // Update the MERGED TARGET (Need to add the relation side)
    if (isImpactedTypeAndSide(r.entity_type, ROLE_FROM)) {
      updateEntities.push({
        _index: targetEntity._index,
        id: sideTarget,
        toReplace: null,
        relationType,
        entity_type: targetEntity.entity_type,
        data: { internal_id: sideToKeep },
      });
    }
  }
  // RELATED_ELEMENT --- (from) relation (to) ---- TO (x -> MERGED TARGET)
  // noinspection DuplicatedCode
  for (let indexTo = 0; indexTo < relationsFromRedirectTo.length; indexTo += 1) {
    const r = relationsFromRedirectTo[indexTo];
    const sideToRedirect = r.relation.toId;
    const sideToKeep = r.relation.fromId;
    const sideToKeepType = r.relation.fromType;
    const sideTarget = targetEntity.internal_id;
    const relationType = r.relation.entity_type;
    const relUpdate = {
      _index: r.relation._index,
      id: r.internal_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    if (isImpactedTypeAndSide(r.entity_type, ROLE_FROM)) {
      updateEntities.push({
        _index: r.connect_index,
        id: sideToKeep,
        toReplace: sideToRedirect,
        relationType,
        entity_type: sideToKeepType,
        data: { internal_id: sideTarget },
      });
    }
    // Update the MERGED TARGET (Need to add the relation side)
    if (isImpactedTypeAndSide(r.entity_type, ROLE_TO)) {
      updateEntities.push({
        _index: targetEntity._index,
        id: sideTarget,
        toReplace: null,
        relationType,
        entity_type: targetEntity.entity_type,
        data: { internal_id: sideToKeep },
      });
    }
  }
  // Update all impacted relations.
  logApp.info(`[OPENCTI] Merging updating ${updateConnections.length} relations for ${targetEntity.internal_id}`);
  let currentRelsUpdateCount = 0;
  const groupsOfRelsUpdate = R.splitEvery(MAX_SPLIT, updateConnections);
  const concurrentRelsUpdate = async (connsToUpdate) => {
    await elUpdateRelationConnections(connsToUpdate);
    currentRelsUpdateCount += connsToUpdate.length;
    logApp.info(`[OPENCTI] Merging, updating relations ${currentRelsUpdateCount} / ${updateConnections.length}`);
  };
  await Promise.map(groupsOfRelsUpdate, concurrentRelsUpdate, { concurrency: ES_MAX_CONCURRENCY });
  // Update all impacted entities
  logApp.info(`[OPENCTI] Merging impacting ${updateEntities.length} entities for ${targetEntity.internal_id}`);
  const updatesByEntity = R.groupBy((i) => i.id, updateEntities);
  const entries = Object.entries(updatesByEntity);
  let currentEntUpdateCount = 0;
  // eslint-disable-next-line prettier/prettier
  const updateBulkEntities = entries
    .filter(([, values]) => values.length === 1)
    .map(([, values]) => values)
    .flat();
  const groupsOfEntityUpdate = R.splitEvery(MAX_SPLIT, updateBulkEntities);
  const concurrentEntitiesUpdate = async (entitiesToUpdate) => {
    await elUpdateEntityConnections(entitiesToUpdate);
    currentEntUpdateCount += entitiesToUpdate.length;
    logApp.info(`[OPENCTI] Merging updating bulk entities ${currentEntUpdateCount} / ${updateBulkEntities.length}`);
  };
  await Promise.map(groupsOfEntityUpdate, concurrentEntitiesUpdate, { concurrency: ES_MAX_CONCURRENCY });
  // Take care of multi update
  const updateMultiEntities = entries.filter(([, values]) => values.length > 1);
  await Promise.map(
    updateMultiEntities,
    async ([id, values]) => {
      logApp.info(`[OPENCTI] Merging, updating single entity ${id} / ${values.length}`);
      const changeOperations = values.filter((element) => element.toReplace !== null);
      const addOperations = values.filter((element) => element.toReplace === null);
      // Group all simple add into single operation
      const groupedAddOperations = R.groupBy((s) => s.relationType, addOperations);
      const operations = Object.entries(groupedAddOperations)
        .map(([key, vals]) => {
          // eslint-disable-next-line camelcase
          const { _index, entity_type } = R.head(vals);
          const ids = vals.map((v) => v.data.internal_id);
          return { id, _index, toReplace: null, relationType: key, entity_type, data: { internal_id: ids } };
        })
        .flat();
      operations.push(...changeOperations);
      // then execute each other one by one
      for (let index = 0; index < operations.length; index += 1) {
        const operation = operations[index];
        await elUpdateEntityConnections([operation]);
      }
    },
    { concurrency: ES_MAX_CONCURRENCY }
  );
  // All not move relations will be deleted, so we need to remove impacted rel in entities.
  await elDeleteElements(user, sourceEntities);
  // Everything if fine update remaining attributes
  const updateAttributes = [];
  // 1. Update all possible attributes
  const attributes = await queryAttributes(targetType);
  const sourceFields = R.map((a) => a.node.value, attributes.edges).filter((s) => !s.startsWith('i_'));
  for (let fieldIndex = 0; fieldIndex < sourceFields.length; fieldIndex += 1) {
    const sourceFieldKey = sourceFields[fieldIndex];
    const mergedEntityCurrentFieldValue = targetEntity[sourceFieldKey];
    const chosenSourceEntityId = chosenFields[sourceFieldKey];
    // Select the one that will fill the empty MONO value of the target
    const takenFrom = chosenSourceEntityId
      ? R.find((i) => i.standard_id === chosenSourceEntityId, sourceEntities)
      : R.head(sourceEntities); // If not specified, take the first one.
    const sourceFieldValue = takenFrom[sourceFieldKey];
    const fieldValues = R.flatten(sourceEntities.map((s) => s[sourceFieldKey])).filter((s) => isNotEmptyField(s));
    // Check if we need to do something
    if (isDictionaryAttribute(sourceFieldKey)) {
      // Special case of dictionary
      const mergedDict = R.mergeAll([...fieldValues, mergedEntityCurrentFieldValue]);
      const dictInputs = Object.entries(mergedDict).map(([k, v]) => ({
        key: `${sourceFieldKey}.${k}`,
        value: [v],
      }));
      updateAttributes.push(...dictInputs);
    } else if (isMultipleAttribute(sourceFieldKey)) {
      const sourceValues = fieldValues || [];
      // For aliased entities, get name of the source to add it as alias of the target
      if (sourceFieldKey === ATTRIBUTE_ALIASES || sourceFieldKey === ATTRIBUTE_ALIASES_OPENCTI) {
        sourceValues.push(...sourceEntities.map((s) => s.name));
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
  // eslint-disable-next-line no-use-before-define
  const data = updateAttributeRaw(targetEntity, updateAttributes);
  const { impactedInputs } = data;
  // region Update elasticsearch
  // Elastic update with partial instance to prevent data override
  if (impactedInputs.length > 0) {
    const updateAsInstance = partialInstanceWithInputs(targetEntity, impactedInputs);
    await elUpdateElement(updateAsInstance);
    logApp.info(`[OPENCTI] Merging attributes success for ${targetEntity.internal_id}`, { update: updateAsInstance });
  }
};
const computeParticipants = (entities) => {
  const participants = [];
  for (let i = 0; i < entities.length; i += 1) {
    const entity = entities[i];
    const froms = Object.entries(entity[INTERNAL_FROM_FIELD] || []);
    for (let index = 0; index < froms.length; index += 1) {
      const [key, values] = froms[index];
      if (isImpactedTypeAndSide(key, ROLE_TO)) {
        participants.push(...values.map((v) => v.internal_id));
      }
    }
    const tos = Object.entries(entity[INTERNAL_TO_FIELD] || []);
    for (let index = 0; index < tos.length; index += 1) {
      const [key, values] = tos[index];
      if (isImpactedTypeAndSide(key, ROLE_FROM)) {
        participants.push(...values.map((v) => v.internal_id));
      }
    }
  }
  return participants;
};
export const mergeEntities = async (user, targetEntityId, sourceEntityIds, opts = {}) => {
  // Pre-checks
  if (R.includes(targetEntityId, sourceEntityIds)) {
    throw FunctionalError(`Cannot merge entities, same ID detected in source and destination`, {
      targetEntityId,
      sourceEntityIds,
    });
  }
  // targetEntity and sourceEntities must be fully resolved elements
  const { locks = [] } = opts;
  const targetEntityPromise = fullLoadById(user, targetEntityId, ABSTRACT_STIX_CORE_OBJECT);
  const sourceEntitiesPromise = Promise.all(sourceEntityIds.map((sourceId) => fullLoadById(user, sourceId)));
  const [target, sources] = await Promise.all([targetEntityPromise, sourceEntitiesPromise]);
  if (!target) {
    throw FunctionalError('Cannot merge the other objects, Stix-Object cannot be found.');
  }
  // We need to lock all elements not locked yet.
  const participantIds = computeParticipants([target, ...sources]).filter((e) => !locks.includes(e));
  let lock;
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    // - TRANSACTION PART
    const initialInstance = await stixLoadById(user, targetEntityId);
    await mergeEntitiesRaw(user, target, sources, opts);
    const mergedInstance = await stixLoadById(user, targetEntityId);
    await storeMergeEvent(user, initialInstance, mergedInstance, sources);
    // Temporary stored the deleted elements to prevent concurrent problem at creation
    await redisAddDeletions(sources.map((s) => s.internal_id));
    // - END TRANSACTION
    return loadById(user, target.id, ABSTRACT_STIX_CORE_OBJECT).then((finalStixCoreObject) =>
      notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalStixCoreObject, user)
    );
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
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
const checkAttributeConsistency = (entityType, key) => {
  if (key.startsWith(RULE_PREFIX)) {
    return;
  }
  let masterKey = key;
  if (key.includes('.')) {
    const [firstPart] = key.split('.');
    masterKey = firstPart;
  }
  if (!R.includes(masterKey, schemaTypes.getAttributes(entityType))) {
    throw FunctionalError(`This attribute key ${key} is not allowed on the type ${entityType}`);
  }
};
const innerUpdateAttribute = (instance, rawInput, options = {}) => {
  const { key } = rawInput;
  // Check consistency
  checkAttributeConsistency(instance.entity_type, key);
  const input = rebuildAndMergeInputFromExistingData(rawInput, instance, options);
  if (R.isEmpty(input)) return [];
  const updatedInputs = [input];
  // --- 01 Get the current attribute types
  // Adding dates elements
  if (R.includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(R.head(input.value));
    const monthValue = monthFormat(R.head(input.value));
    const yearValue = yearFormat(R.head(input.value));
    const dayInput = { key: `i_${key}_day`, value: [dayValue] };
    updatedInputs.push(dayInput);
    const monthInput = { key: `i_${key}_month`, value: [monthValue] };
    updatedInputs.push(monthInput);
    const yearInput = { key: `i_${key}_year`, value: [yearValue] };
    updatedInputs.push(yearInput);
  }
  const today = now();
  // Update updated_at
  if (isUpdatedAtObject(instance.entity_type) && key !== 'modified' && key !== 'updated_at') {
    const updatedAtInput = { key: 'updated_at', value: [today] };
    updatedInputs.push(updatedAtInput);
  }
  // Update modified
  if (isModifiedObject(instance.entity_type) && key !== 'modified' && key !== 'updated_at') {
    const modifiedAtInput = { key: 'modified', value: [today] };
    updatedInputs.push(modifiedAtInput);
  }
  // Update created
  if (instance.entity_type === ENTITY_TYPE_CONTAINER_REPORT && key === 'published') {
    const createdInput = { key: 'created', value: input.value };
    updatedInputs.push(createdInput);
  }
  return updatedInputs;
};
const prepareAttributes = (elements) => {
  return R.map((input) => {
    // Check integer
    if (R.includes(input.key, numericAttributes)) {
      return {
        key: input.key,
        value: R.map((value) => {
          const parsedValue = parseInt(value, 10);
          return Number.isNaN(parsedValue) ? null : parsedValue;
        }, input.value),
      };
    }
    // Check boolean
    if (R.includes(input.key, booleanAttributes)) {
      return {
        key: input.key,
        value: R.map((value) => {
          return value === true || value === 'true';
        }, input.value),
      };
    }
    return input;
  }, elements);
};

const getInstanceValue = (key, instance) => {
  if (key.includes('.')) {
    const [base, target] = key.split('.');
    return instance[base]?.[target];
  }
  return instance[key];
};

export const updateAttributeRaw = (instance, inputs, options = {}) => {
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const updatedInputs = [];
  const impactedInputs = [];
  const instanceType = instance.entity_type;
  // Prepare attributes
  const preparedElements = prepareAttributes(elements);
  // Update all needed attributes
  for (let index = 0; index < preparedElements.length; index += 1) {
    const input = preparedElements[index];
    const ins = innerUpdateAttribute(instance, input, options);
    if (ins.length > 0) {
      // Updated inputs must not be internals
      if (!input.key.startsWith(INTERNAL_PREFIX)) {
        updatedInputs.push({ ...input, previous: getInstanceValue(input.key, instance) });
      }
      impactedInputs.push(...ins);
    }
    // If named entity name updated, modify the aliases ids
    if (input.key === NAME_FIELD && isStixObjectAliased(instanceType) && isTypeHasAliasIDs(instanceType)) {
      const name = R.head(input.value);
      const aliases = [name, ...(instance[ATTRIBUTE_ALIASES] || []), ...(instance[ATTRIBUTE_ALIASES_OPENCTI] || [])];
      const aliasesId = generateAliasesId(aliases, instance);
      const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
      const aliasIns = innerUpdateAttribute(instance, aliasInput, options);
      impactedInputs.push(...aliasIns);
    }
    // If is valid_until modification, update also revoked
    if (input.key === VALID_UNTIL) {
      const untilDate = R.head(input.value);
      const untilDateTime = utcDate(untilDate).toDate();
      const revokedInput = { key: REVOKED, value: [untilDateTime < utcDate().toDate()] };
      const revokedIn = innerUpdateAttribute(instance, revokedInput, options);
      if (revokedIn.length > 0) {
        updatedInputs.push({ ...revokedInput, previous: getInstanceValue(revokedInput.key, instance) });
        impactedInputs.push(...revokedIn);
      }
      if (instance.entity_type === ENTITY_TYPE_INDICATOR && untilDateTime <= utcDate().toDate()) {
        const detectionInput = { key: 'x_opencti_detection', value: [false] };
        const detectionIn = innerUpdateAttribute(instance, detectionInput, options);
        if (detectionIn.length > 0) {
          updatedInputs.push(detectionInput);
          impactedInputs.push(...detectionIn);
        }
      }
    }
    // If input impact aliases (aliases or x_opencti_aliases), regenerate internal ids
    const aliasesAttrs = [ATTRIBUTE_ALIASES, ATTRIBUTE_ALIASES_OPENCTI];
    const isAliasesImpacted = aliasesAttrs.includes(input.key) && !R.isEmpty(ins.length);
    if (isTypeHasAliasIDs(instanceType) && isAliasesImpacted) {
      const aliasesId = generateAliasesId([instance.name, ...input.value], instance);
      const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
      const aliasIns = innerUpdateAttribute(instance, aliasInput, options);
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
    const ins = innerUpdateAttribute(instance, standardInput, options);
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
// noinspection ExceptionCaughtLocallyJS
export const updateAttribute = async (user, id, type, inputs, opts = {}) => {
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const { operation = UPDATE_OPERATION_REPLACE } = opts;
  if (operation !== UPDATE_OPERATION_REPLACE && elements.length > 1) {
    throw FunctionalError(`Unsupported operation`, { operation, elements });
  }
  const instance = await loadById(user, id, type);
  if (!instance) {
    throw FunctionalError(`Cant find element to update`, { id, type });
  }
  const participantIds = getInstanceIds(instance);
  // 01. Check if updating alias lead to entity conflict
  const keys = R.map((t) => t.key, elements);
  if (isStixObjectAliased(instance.entity_type)) {
    // If user ask for aliases modification, we need to check if it not already belong to another entity.
    const isInputAliases = (input) => input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI;
    const aliasedInputs = R.filter((input) => isInputAliases(input), elements);
    if (aliasedInputs.length > 0) {
      const aliases = R.uniq(R.flatten(R.map((a) => a.value, aliasedInputs)));
      const aliasesIds = generateAliasesId(aliases, instance);
      const existingEntities = await internalFindByIds(user, aliasesIds, { type: instance.entity_type });
      const differentEntities = R.filter((e) => e.internal_id !== id, existingEntities);
      if (differentEntities.length > 0) {
        throw FunctionalError(`This update will produce a duplicate`, { id: instance.id, type });
      }
    }
  }
  // 02. Check if this update is not resulting to an entity merging
  let eventualNewStandardId = null;
  if (isFieldContributingToStandardId(instance, keys)) {
    // In this case we need to reconstruct the data like if an update already appears
    // Based on that we will be able to generate the correct standard id
    const mergeInput = (input) => rebuildAndMergeInputFromExistingData(input, instance, opts);
    const remappedInputs = R.map((i) => mergeInput(i), elements);
    const resolvedInputs = R.filter((f) => !R.isEmpty(f), remappedInputs);
    const updatedInstance = mergeInstanceWithInputs(instance, resolvedInputs);
    const targetStandardId = generateStandardId(instance.entity_type, updatedInstance);
    if (targetStandardId !== instance.standard_id) {
      participantIds.push(targetStandardId);
      eventualNewStandardId = targetStandardId;
    }
  }
  // --- take lock, ensure no one currently create or update this element
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // Only for StixCyberObservable
    if (eventualNewStandardId) {
      const existingEntity = await internalLoadById(user, eventualNewStandardId);
      if (existingEntity) {
        // If stix observable, we can merge. If not throw an error.
        if (isStixCyberObservable(existingEntity.entity_type)) {
          const mergeOpts = { locks: participantIds };
          const sourceEntityIds = [instance.internal_id];
          // noinspection UnnecessaryLocalVariableJS
          const merged = await mergeEntities(user, existingEntity.internal_id, sourceEntityIds, mergeOpts);
          // Return merged element after waiting for it.
          return merged;
        }
        // noinspection ExceptionCaughtLocallyJS
        throw FunctionalError(`This update will produce a duplicate`, { id: instance.id, type });
      }
    }
    // noinspection UnnecessaryLocalVariableJS
    const data = updateAttributeRaw(instance, inputs, opts);
    const { updatedInstance, impactedInputs } = data;
    // Check the consistency of the observable.
    if (isStixCyberObservable(instance.entity_type)) {
      const observableSyntaxResult = checkObservableSyntax(instance.entity_type, updatedInstance);
      if (observableSyntaxResult !== true) {
        throw FunctionalError(`Observable of type ${instance.entity_type} is not correctly formatted.`, { id, type });
      }
    }
    if (impactedInputs.length > 0) {
      const updateAsInstance = partialInstanceWithInputs(instance, impactedInputs);
      await elUpdateElement(updateAsInstance);
    }
    // Only push event in stream if modifications really happens
    if (data.updatedInputs.length > 0) {
      const isUpdate = operation === UPDATE_OPERATION_REPLACE;
      const updatedData = isUpdate ? replacedInputsToData(data.updatedInputs) : updatedInputsToData(data.updatedInputs);
      await storeUpdateEvent(user, instance, [{ [operation]: updatedData }]);
    }
    // Return updated element after waiting for it.
    return updatedInstance;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
export const patchAttributeRaw = (instance, patch, options = {}) => {
  const inputs = transformPathToInput(patch);
  return updateAttributeRaw(instance, inputs, options);
};
export const patchAttribute = async (user, id, type, patch, options = {}) => {
  const inputs = transformPathToInput(patch);
  return updateAttribute(user, id, type, inputs, options);
};
// endregion

// region mutation relation
const buildRelationInput = (input) => {
  const { relationship_type: relationshipType } = input;
  // 03. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // 05. Prepare the relation to be created
  const today = now();
  let relationAttributes = {};
  relationAttributes._index = inferIndexFromConceptType(relationshipType);
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
  return { relation: relationAttributes };
};
const buildInnerRelation = (from, to, type) => {
  const targets = Array.isArray(to) ? to : [to];
  if (!to || R.isEmpty(targets)) return [];
  const relations = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i];
    const input = { from, to: target, relationship_type: type };
    const { relation } = buildRelationInput(input);
    const basicRelation = {
      id: relation.internal_id,
      from,
      fromId: from.internal_id,
      fromRole: `${type}_from`,
      fromType: from.entity_type,
      to: target,
      toId: target.internal_id,
      toRole: `${type}_to`,
      toType: target.entity_type,
      base_type: BASE_TYPE_RELATION,
      parent_types: getParentTypes(relation.entity_type),
      ...relation,
    };
    relations.push({ relation: basicRelation });
  }
  return relations;
};
const upsertIdentifiedFields = (element, input, fields) => {
  const upsertUpdated = [];
  const upsertImpacted = [];
  if (fields) {
    const patch = {};
    for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
      const fieldKey = fields[fieldIndex];
      const inputData = input[fieldKey];
      if (isNotEmptyField(inputData)) {
        patch[fieldKey] = Array.isArray(inputData) ? inputData : [inputData];
      }
    }
    if (!R.isEmpty(patch)) {
      const patched = patchAttributeRaw(element, patch);
      upsertImpacted.push(...patched.impactedInputs);
      upsertUpdated.push(...patched.updatedInputs);
    }
  }
  return { upsertImpacted, upsertUpdated };
};

const ALIGN_OLDEST = 'oldest';
const ALIGN_NEWEST = 'newest';
const computeExtendedDateValues = (newValue, currentValue, mode) => {
  if (isNotEmptyField(newValue)) {
    const newValueDate = moment(newValue);
    // If a first_seen already exists
    if (isNotEmptyField(currentValue)) {
      // If the new first_seen is before the existing one, we update
      const currentValueDate = moment(currentValue);
      if (mode === ALIGN_OLDEST) {
        if (newValueDate.isBefore(currentValueDate)) {
          return newValueDate.utc().toISOString();
        }
      }
      if (mode === ALIGN_NEWEST) {
        if (newValueDate.isAfter(currentValueDate)) {
          return newValueDate.utc().toISOString();
        }
      }
      // If no first_seen exists, we update
    } else {
      return newValueDate.utc().toISOString();
    }
  }
  return null;
};

const handleRelationTimeUpdate = (input, instance, startField, stopField, extendRelationTime) => {
  const patch = {};
  if (input[startField]) {
    if (extendRelationTime) {
      const extendedStart = computeExtendedDateValues(input[startField], instance[startField], ALIGN_OLDEST);
      if (extendedStart) {
        patch[startField] = extendedStart;
      }
    } else {
      patch[startField] = input[startField];
    }
  }
  if (input[stopField]) {
    if (extendRelationTime) {
      const extendedStop = computeExtendedDateValues(input[stopField], instance[stopField], ALIGN_NEWEST);
      if (extendedStop) {
        patch[stopField] = extendedStop;
      }
    } else {
      patch[stopField] = input[stopField];
    }
  }
  return patch;
};
const upsertElementRule = async (user, instance, type, input) => {
  const impactedInputs = []; // Inputs impacted by updated inputs + updated inputs
  const rulesKeys = Object.keys(input).filter((k) => k.startsWith(RULE_PREFIX));
  for (let indexKey = 0; indexKey < rulesKeys.length; indexKey += 1) {
    const rulesKey = rulesKeys[indexKey];
    const ruleDefinition = input[rulesKey];
    const patched = patchAttributeRaw(instance, { [rulesKey]: ruleDefinition });
    impactedInputs.push(...patched.impactedInputs);
  }
  const updatedInstance = mergeInstanceWithInputs(instance, impactedInputs);
  // Build the input to reindex in elastic
  const indexInput = partialInstanceWithInputs(updatedInstance, impactedInputs);
  return { type: TRX_UPDATE, element: updatedInstance, relations: [], streamInputs: [], indexInput };
};
const upsertElementRaw = async (user, instance, type, input, opts = {}) => {
  const { extendRelationTime = true, overrideMarkings = false } = opts;
  // Check consistency
  checkInferenceRight(user, instance);
  // Upsert relation
  const forceUpdate = input.update === true;
  const updatedAddInputs = []; // Direct modified inputs (add)
  const updatedReplaceInputs = []; // Direct modified inputs (replace)
  const impactedInputs = []; // Inputs impacted by updated inputs + updated inputs
  const rawRelations = [];
  const targetsPerType = [];
  // Handle attributes updates
  if (isNotEmptyField(input.stix_id)) {
    const patch = { x_opencti_stix_ids: [input.stix_id] };
    const patched = patchAttributeRaw(instance, patch, { operation: UPDATE_OPERATION_ADD });
    impactedInputs.push(...patched.impactedInputs);
    updatedAddInputs.push(...patched.updatedInputs);
  }
  // Upsert the aliases
  if (isStixObjectAliased(type)) {
    const { name } = input;
    const key = resolveAliasesField(type);
    const aliases = [...(input[ATTRIBUTE_ALIASES] || []), ...(input[ATTRIBUTE_ALIASES_OPENCTI] || [])];
    if (normalizeName(instance.name) !== normalizeName(name)) aliases.push(name);
    const patch = { [key]: aliases };
    const patched = patchAttributeRaw(instance, patch, { operation: UPDATE_OPERATION_ADD });
    impactedInputs.push(...patched.impactedInputs);
    updatedAddInputs.push(...patched.updatedInputs);
  }
  // Upsert relationships
  if (isStixSightingRelationship(type)) {
    const basePatch = { attribute_count: instance.attribute_count + input.attribute_count };
    const timePatch = handleRelationTimeUpdate(input, instance, 'first_seen', 'last_seen', extendRelationTime);
    const patch = { ...basePatch, ...timePatch };
    const patched = patchAttributeRaw(instance, patch);
    impactedInputs.push(...patched.impactedInputs);
    updatedReplaceInputs.push(...patched.updatedInputs);
  }
  // Upsert SDOs
  if (isStixCoreRelationship(type)) {
    const basePatch = {};
    if (input.confidence && forceUpdate) {
      basePatch.confidence = input.confidence;
    }
    if (input.description && forceUpdate) {
      basePatch.description = input.description;
    }
    const timePatch = handleRelationTimeUpdate(input, instance, 'start_time', 'stop_time', extendRelationTime);
    const patch = { ...basePatch, ...timePatch };
    const patched = patchAttributeRaw(instance, patch);
    impactedInputs.push(...patched.impactedInputs);
    updatedReplaceInputs.push(...patched.updatedInputs);
  }
  // Upsert entities
  if (isInternalObject(type) && forceUpdate) {
    const fields = internalObjectsFieldsToBeUpdated[type];
    const { upsertImpacted, upsertUpdated } = upsertIdentifiedFields(instance, input, fields);
    impactedInputs.push(...upsertImpacted);
    updatedReplaceInputs.push(...upsertUpdated);
  }
  if (isStixDomainObject(type) && forceUpdate) {
    const fields = stixDomainObjectFieldsToBeUpdated[type];
    const { upsertImpacted, upsertUpdated } = upsertIdentifiedFields(instance, input, fields);
    impactedInputs.push(...upsertImpacted);
    updatedReplaceInputs.push(...upsertUpdated);
  }
  // Upsert SCOs
  if (isStixCyberObservable(type) && forceUpdate) {
    const fields = stixCyberObservableFieldsToBeUpdated[type];
    const { upsertImpacted, upsertUpdated } = upsertIdentifiedFields(instance, input, fields);
    impactedInputs.push(...upsertImpacted);
    updatedReplaceInputs.push(...upsertUpdated);
  }
  // Upsert rules
  const rulesKeys = Object.keys(input).filter((k) => k.startsWith(RULE_PREFIX));
  for (let indexKey = 0; indexKey < rulesKeys.length; indexKey += 1) {
    const rulesKey = rulesKeys[indexKey];
    const ruleDefinition = input[rulesKey];
    const patched = patchAttributeRaw(instance, { [rulesKey]: ruleDefinition });
    impactedInputs.push(...patched.impactedInputs);
  }
  // Upsert markings
  if (input.objectMarking && input.objectMarking.length > 0) {
    // Clear the marking if needed
    const markingsIds = instance.object_marking_refs || [];
    if (overrideMarkings && markingsIds.length > 0) {
      const currentMarkingRels = await listAllRelations(user, RELATION_OBJECT_MARKING, {
        fromId: instance.internal_id,
      });
      await elDeleteElements(SYSTEM_USER, currentMarkingRels);
    }
    // When upsert stable relations, we decide to only add the missing markings
    const instanceMarkings = overrideMarkings ? [] : markingsIds;
    const markingToCreate = R.filter((m) => !instanceMarkings.includes(m.internal_id), input.objectMarking);
    const newRelations = markingToCreate.map(
      (to) => R.head(buildInnerRelation(instance, to, RELATION_OBJECT_MARKING)).relation
    );
    rawRelations.push(...newRelations);
    targetsPerType.push({ objectMarking: markingToCreate });
  }
  // Build the stream input
  const streamInputs = [];
  if (updatedReplaceInputs.length > 0) {
    streamInputs.push({ [UPDATE_OPERATION_REPLACE]: updatedInputsToData(updatedReplaceInputs) });
  }
  if (updatedAddInputs.length > 0 || rawRelations.length > 0) {
    let streamInput = updatedInputsToData(updatedAddInputs);
    if (rawRelations.length > 0) {
      streamInput = { ...streamInput, ...R.mergeAll(targetsPerType) };
    }
    streamInputs.push({ [UPDATE_OPERATION_ADD]: streamInput });
  }
  if (impactedInputs.length > 0) {
    const updatedInstance = mergeInstanceWithInputs(instance, impactedInputs);
    // Build the input to reindex in elastic
    const indexInput = partialInstanceWithInputs(updatedInstance, impactedInputs);
    return { type: TRX_UPDATE, element: updatedInstance, relations: rawRelations, streamInputs, indexInput };
  }
  // Return all elements requirement for stream and indexation
  return { type: TRX_UPDATE, element: instance, relations: rawRelations, streamInputs };
};

export const buildRelationTimeFilter = (input) => {
  const args = {};
  const { relationship_type: relationshipType } = input;
  if (isStixCoreRelationship(relationshipType)) {
    if (!R.isNil(input.start_time)) {
      args.startTimeStart = prepareDate(moment(input.start_time).subtract(1, 'months').utc());
      args.startTimeStop = prepareDate(moment(input.start_time).add(1, 'months').utc());
    }
    if (!R.isNil(input.stop_time)) {
      args.stopTimeStart = prepareDate(moment(input.stop_time).subtract(1, 'months').utc());
      args.stopTimeStop = prepareDate(moment(input.stop_time).add(1, 'months').utc());
    }
  } else if (isStixSightingRelationship(relationshipType)) {
    if (!R.isNil(input.first_seen)) {
      args.firstSeenStart = prepareDate(moment(input.first_seen).subtract(1, 'months').utc());
      args.firstSeenStop = prepareDate(moment(input.first_seen).add(1, 'months').utc());
    }
    if (!R.isNil(input.last_seen)) {
      args.lastSeenStart = prepareDate(moment(input.last_seen).subtract(1, 'months').utc());
      args.lastSeenStop = prepareDate(moment(input.last_seen).add(1, 'months').utc());
    }
  }
  return args;
};

const buildRelationData = async (user, input, opts = {}) => {
  const { fromRule } = opts;
  const { from, to, relationship_type: relationshipType } = input;
  // 01. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // 02. Check existing relationship
  const timeFilters = fromRule ? {} : buildRelationTimeFilter(input);
  const listingArgs = { fromId: from.internal_id, toId: to.internal_id, connectionFormat: false, ...timeFilters };
  const existingRelationships = await listRelations(SYSTEM_USER, relationshipType, listingArgs);
  let existingRelationship = null;
  if (existingRelationships.length > 0) {
    // We need to filter what we found with the user rights
    const filteredRelations = filterElementsAccordingToUser(user, existingRelationships);
    // If nothing accessible for this user, throw ForbiddenAccess
    if (filteredRelations.length === 0) {
      throw UnsupportedError('Restricted relation already exists');
    }
    // Meta single relation check
    if (isStixSingleMetaRelationship(relationshipType)) {
      // If relation already exist, we fail
      throw UnsupportedError('Relation cant be created (single cardinality)', {
        relationshipType,
        fromId: from.internal_id,
      });
    }
    // TODO Handling merging relation when updating to prevent multiple relations finding
    existingRelationship = R.head(filteredRelations);
  }
  // 03. Prepare the relation to be created
  const today = now();
  const data = {};
  // Check existing
  if (existingRelationship) {
    // If user try to create an existing inferred relationship but she's already exists
    // we need to delete the inference and create the real relation.
    const isDirectCreation = isEmptyField(fromRule);
    const isRuleCreation = !isDirectCreation;
    const wasCreatedByRule = isInferredIndex(existingRelationship._index);
    if (wasCreatedByRule) {
      // If the element was created by a rule
      if (isDirectCreation) {
        // If the creation is asked by a user.
        // We can delete the current element. It will be recreated as manual creation
        const rulesToKeep = Object.keys(existingRelationship)
          .filter((k) => k.startsWith(RULE_PREFIX))
          .map((key) => ({ key, val: existingRelationship[key] }));
        for (let index = 0; index < rulesToKeep.length; index += 1) {
          const rulesToKeepElement = rulesToKeep[index];
          data[rulesToKeepElement.key] = rulesToKeepElement.val;
        }
        // eslint-disable-next-line no-use-before-define
        await deleteElementById(RULE_MANAGER_USER, existingRelationship.id, existingRelationship.entity_type);
      } else {
        // Rule reapply on existing element, simple upsert to execute
        return upsertElementRaw(user, existingRelationship, relationshipType, input, opts);
      }
    } else {
      // If the element was directly created
      if (isRuleCreation) {
        // If the creation is asked by a rule.
        // We ust update the rule element without touching the rest
        return upsertElementRule(user, existingRelationship, relationshipType, input);
      }
      // User reapply on existing element, simple upsert to execute
      return upsertElementRaw(user, existingRelationship, relationshipType, input, opts);
    }
  }
  // Default attributes
  // basic-relationship
  const inferred = isNotEmptyField(fromRule);
  data._index = inferIndexFromConceptType(relationshipType, inferred);
  if (inferred) {
    data[RULE_PREFIX + fromRule] = input[RULE_PREFIX + fromRule];
  }
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
    data.confidence = R.isNil(input.confidence) ? computeConfidenceLevel(input) : input.confidence;
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
      data[`i_${dataKeys[index]}_day`] = dayValue;
      data[`i_${dataKeys[index]}_month`] = monthValue;
      data[`i_${dataKeys[index]}_year`] = yearValue;
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
  if (isStixSightingRelationship(relationshipType)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
    relToCreate.push(...buildInnerRelation(data, input.objectMarking, RELATION_OBJECT_MARKING));
  }
  // 05. Prepare the final data
  const created = R.pipe(
    R.assoc('id', internalId),
    R.assoc('from', from),
    R.assoc('fromId', from.internal_id),
    R.assoc('fromRole', fromRole),
    R.assoc('fromType', from.entity_type),
    R.assoc('to', to),
    R.assoc('toId', to.internal_id),
    R.assoc('toRole', toRole),
    R.assoc('toType', to.entity_type),
    R.assoc('entity_type', relationshipType),
    R.assoc('parent_types', getParentTypes(relationshipType)),
    R.assoc('base_type', BASE_TYPE_RELATION)
  )(data);
  // 06. Return result if no need to reverse the relations from and to
  const relations = relToCreate.map((r) => r.relation);
  return { type: TRX_CREATION, element: created, relations };
};
const checkRelationConsistency = (relationshipType, fromType, toType) => {
  // Check if StixCoreRelationship is allowed
  if (isStixCoreRelationship(relationshipType)) {
    if (!checkStixCoreRelationshipMapping(fromType, toType, relationshipType)) {
      throw FunctionalError(
        `The relationship type ${relationshipType} is not allowed between ${fromType} and ${toType}`
      );
    }
  }
  // Check if StixCyberObservableRelationship is allowed
  if (isStixCyberObservableRelationship(relationshipType)) {
    if (!checkStixCyberObservableRelationshipMapping(fromType, toType, relationshipType)) {
      throw FunctionalError(
        `The relationship type ${relationshipType} is not allowed between ${fromType} and ${toType}`
      );
    }
  }
};

export const createRelationRaw = async (user, input, opts = {}) => {
  let lock;
  const { fromId, toId, relationship_type: relationshipType } = input;
  // Pre check before inputs resolution
  if (fromId === toId) {
    /* istanbul ignore next */
    const errorData = { from: input.fromId, relationshipType };
    throw UnsupportedError(`Relation cant be created with the same source and target`, errorData);
  }
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(user, input, relationshipType);
  const { from, to } = resolvedInput;
  // In some case from and to can be resolved to the same element (because of automatic merging)
  if (from.internal_id === to.internal_id) {
    /* istanbul ignore next */
    if (relationshipType === RELATION_REVOKED_BY) {
      // Because of entity merging, we can receive some revoked-by on the same internal id element
      // In this case we need to revoke the fromId stixId of the relation
      // TODO
    }
    const errorData = { from: input.fromId, to: input.toId, relationshipType };
    throw UnsupportedError(`Relation cant be created with the same source and target`, errorData);
  }
  // Check consistency
  checkRelationConsistency(relationshipType, from.entity_type, to.entity_type);
  // Build lock ids
  const participantIds = getInputIds(relationshipType, resolvedInput);
  if (isImpactedTypeAndSide(relationshipType, ROLE_FROM)) participantIds.push(from.internal_id);
  if (isImpactedTypeAndSide(relationshipType, ROLE_TO)) participantIds.push(to.internal_id);
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // - TRANSACTION PART
    const dataRel = await buildRelationData(user, resolvedInput, opts);
    // Index the created element
    await indexCreatedElement(dataRel);
    // Push the input in the stream
    let event;
    if (dataRel.type === TRX_CREATION) {
      const relWithConnections = { ...dataRel.element, from, to };
      event = await storeCreateEvent(user, relWithConnections, resolvedInput, stixLoadById);
    } else if (dataRel.streamInputs.length > 0) {
      // If upsert with new data
      event = await storeUpdateEvent(user, dataRel.element, dataRel.streamInputs);
    }
    // - TRANSACTION END
    return { element: dataRel.element, event };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const createRelation = async (user, input) => {
  const data = await createRelationRaw(user, input);
  return data.element;
};

export const createInferredRelation = async (rule, input) => {
  const opts = { fromRule: rule, extendRelationTime: false, overrideMarkings: true };
  const data = await createRelationRaw(RULE_MANAGER_USER, input, opts);
  return data.event;
};

/* istanbul ignore next */
export const createRelations = async (user, inputs) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improve by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    const relation = await createRelation(user, inputs[i]);
    createdRelations.push(relation);
  }
  return createdRelations;
};
// endregion

// region mutation entity
const createEntityRaw = async (user, participantIds, input, type) => {
  // Generate the internal id if needed
  const internalId = input.internal_id || generateInternalId();
  const standardId = input.standard_id || generateStandardId(type, input);
  // Check if the entity exists, must be done with SYSTEM USER to really find it.
  const existingEntities = await internalFindByIds(SYSTEM_USER, participantIds, { type });
  // If existing entities have been found and type is a STIX Core Object
  if (existingEntities.length > 0) {
    // We need to filter what we found with the user rights
    const filteredEntities = filterElementsAccordingToUser(user, existingEntities);
    // If nothing accessible for this user, throw ForbiddenAccess
    if (filteredEntities.length === 0) {
      throw UnsupportedError('Restricted entity already exists');
    }
    if (filteredEntities.length === 1) {
      return upsertElementRaw(user, R.head(filteredEntities), type, input);
    }
    // If creation is not by a reference
    // We can in best effort try to merge a common stix_id
    if (input.update === true) {
      // The new one is new reference, merge all found entities
      // Target entity is existingByStandard by default or any other
      const target = R.find((e) => e.standard_id === standardId, filteredEntities) || R.head(filteredEntities);
      const sourcesEntities = R.filter((e) => e.internal_id !== target.internal_id, filteredEntities);
      const sources = sourcesEntities.map((s) => s.internal_id);
      await mergeEntities(user, target.internal_id, sources, { locks: participantIds });
      return upsertElementRaw(user, target, type, input);
    }
    // Sometimes multiple entities can match
    // Looking for aliasA, aliasB, find in different entities for example
    // In this case, we try to find if one match the standard id
    const existingByStandard = R.find((e) => e.standard_id === standardId, filteredEntities);
    if (existingByStandard) {
      // If a STIX ID has been passed in the creation
      if (input.stix_id) {
        // Find the entity corresponding to this STIX ID
        const stixIdFinder = (e) => e.standard_id === input.stix_id || e.x_opencti_stix_ids.includes(input.stix_id);
        const existingByGivenStixId = R.find(stixIdFinder, filteredEntities);
        // If the entity exists by the stix id and not the same as the previously founded.
        if (existingByGivenStixId && existingByGivenStixId.internal_id !== existingByStandard.internal_id) {
          // Merge this entity into the one matching the standard id
          await mergeEntities(user, existingByStandard.internal_id, [existingByGivenStixId.internal_id], {
            locks: participantIds,
          });
        }
      }
      // In this mode we can safely consider this entity like the existing one.
      // We can upsert element except the aliases that are part of other entities
      const concurrentEntities = R.filter((e) => e.standard_id !== standardId, filteredEntities);
      const key = resolveAliasesField(type);
      const concurrentAliases = R.flatten(R.map((c) => [c[key], c.name], concurrentEntities));
      const normedAliases = R.uniq(concurrentAliases.map((c) => normalizeName(c)));
      const filteredAliases = R.filter((i) => !normedAliases.includes(normalizeName(i)), input[key] || []);
      const inputAliases = { ...input, [key]: filteredAliases };
      return upsertElementRaw(user, existingByStandard, type, inputAliases);
    }
    // If not we dont know what to do, just throw an exception.
    const entityIds = R.map((i) => i.standard_id, filteredEntities);
    throw UnsupportedError('Cant upsert entity. Too many entities resolved', { input, entityIds });
  }
  // Complete with identifiers
  const today = now();
  // Default attributes
  let data = R.pipe(
    R.assoc('_index', inferIndexFromConceptType(type)),
    R.assoc(ID_INTERNAL, internalId),
    R.assoc(ID_STANDARD, standardId),
    R.assoc('entity_type', type),
    R.dissoc('update'),
    R.dissoc(INPUT_CREATED_BY),
    R.dissoc(INPUT_MARKINGS),
    R.dissoc(INPUT_LABELS),
    R.dissoc(INPUT_KILLCHAIN),
    R.dissoc(INPUT_EXTERNAL_REFS),
    R.dissoc(INPUT_OBJECTS)
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
      R.assoc('confidence', R.isNil(data.confidence) ? computeConfidenceLevel(input) : data.confidence),
      R.assoc('lang', R.isNil(data.lang) ? 'en' : data.lang),
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    data = R.assoc(INTERNAL_IDS_ALIASES, generateAliasesIdsForInstance(input), data);
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
  const resolvedInput = await inputResolveRefs(user, input, type);
  // Generate all the possibles ids
  // For marking def, we need to force the standard_id
  const participantIds = getInputIds(type, resolvedInput);
  // Create the element
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // Create the object
    const dataEntity = await createEntityRaw(user, participantIds, resolvedInput, type);
    // Index the created element
    await indexCreatedElement(dataEntity);
    // Push the input in the stream
    if (dataEntity.type === TRX_CREATION) {
      await storeCreateEvent(user, dataEntity.element, resolvedInput, stixLoadById);
    } else if (dataEntity.streamInputs.length > 0) {
      // If upsert with new data
      await storeUpdateEvent(user, dataEntity.element, dataEntity.streamInputs);
    }
    // Return created element after waiting for it.
    return R.assoc('i_upserted', dataEntity.type !== TRX_CREATION, dataEntity.element);
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
// endregion

// region mutation deletion
export const deleteElementById = async (user, elementId, type) => {
  let lock;
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting an entity`);
  }
  // Check consistency
  const element = await stixLoadById(user, elementId, type);
  if (!element) {
    throw FunctionalError('Cant find element to delete', { elementId });
  }
  checkInferenceRight(user, element);
  // Apply deletion
  const participantIds = [element.internal_id];
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    await deleteAllFiles(user, `import/${element.entity_type}/${element.internal_id}`);
    await elDeleteElements(user, [element]);
    await storeDeleteEvent(user, element, stixLoadById);
    // Temporary stored the deleted elements to prevent concurrent problem at creation
    await redisAddDeletions(participantIds);
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
  // Return id
  return elementId;
};
export const deleteInferredRuleElement = async (rule, element) => {
  const events = [];
  const rules = Object.keys(element).filter((k) => k.startsWith(RULE_PREFIX));
  const completeRuleName = RULE_PREFIX + rule;
  if (!rules.includes(completeRuleName)) {
    throw UnsupportedError('Cant ask a deletion on element not inferred by this rule', { rule });
  }
  const isPurelyInferred = isInferredIndex(element._index);
  const monoRule = rules.length === 1;
  // If purely inferred and mono rule we can safely delete it.
  if (isPurelyInferred && monoRule) {
    await deleteElementById(RULE_MANAGER_USER, element.id, element.entity_type);
    const event = await buildDeleteEvent(RULE_MANAGER_USER, element, stixLoadById, { withoutMessage: true });
    events.push(event);
  } else {
    // In others case you need to clean the rule and keep the element
    const patch = createClearRulePatch(rule);
    await patchAttribute(RULE_MANAGER_USER, element.id, element.entity_type, patch);
  }
  return events;
};
export const deleteRelationsByFromAndTo = async (user, fromId, toId, relationshipType, scopeType, opts = {}) => {
  /* istanbul ignore if */
  if (R.isNil(scopeType) || R.isNil(fromId) || R.isNil(toId)) {
    throw FunctionalError(`You need to specify a scope type when deleting a relation with from and to`);
  }
  const fromThing = await internalLoadById(user, fromId, opts);
  const toThing = await internalLoadById(user, toId, opts);
  // Looks like the caller doesnt give the correct from, to currently
  const relationsToDelete = await elFindByFromAndTo(user, fromThing.internal_id, toThing.internal_id, relationshipType);
  for (let i = 0; i < relationsToDelete.length; i += 1) {
    const r = relationsToDelete[i];
    await deleteElementById(user, r.internal_id, r.entity_type);
  }
  return true;
};
// endregion
