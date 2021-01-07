import moment from 'moment';
import * as R from 'ramda';
import DataLoader from 'dataloader';
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
  isEmptyField,
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
  elDeleteElement,
  elDeleteElements,
  elFindByFromAndTo,
  elFindByIds,
  elHistogramCount,
  elIndexElements,
  elLoadByIds,
  elPaginate,
  elUpdateElement,
  elUpdateEntityConnections,
  elUpdateRelationConnections,
  ENTITIES_INDICES,
  isUnimpactedEntity,
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
import { lockResource, notify, storeCreateEvent, storeDeleteEvent, storeMergeEvent, storeUpdateEvent } from './redis';
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
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INTERNAL_IDS_ALIASES,
  REL_INDEX_PREFIX,
  schemaTypes,
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
  booleanAttributes,
  dictAttributes,
  isDictionaryAttribute,
  isMultipleAttribute,
  multipleAttributes,
  numericAttributes,
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
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { BUS_TOPICS, logger } from '../config/conf';

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
// endregion

// region Loader common
export const initBatchLoader = (loader) => {
  const opts = { cache: false, maxBatchSize: MAX_BATCH_SIZE };
  return new DataLoader((ids) => loader(ids), opts);
};
export const querySubTypes = async ({ type }) => {
  const sortByLabel = R.sortBy(R.toLower);
  const types = schemaTypes.get(type);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } }))
  )(types);
  return buildPagination(0, 0, finalResult, finalResult.length);
};
export const queryAttributes = async (type) => {
  const attributes = schemaTypes.getAttributes(type);
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: n, value: n } }))
  )(attributes);
  return buildPagination(0, 0, finalResult, finalResult.length);
};
// endregion

// region bulk loading method
// Listing handle
const batchListThrough = async (sources, sourceSide, relationType, targetEntityType, opts = {}) => {
  const { paginate = true, batched = true } = opts;
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
  const relations = await elPaginate(RELATIONSHIPS_INDICES, {
    connectionFormat: false,
    filters,
    types: [relationType],
  });
  // For each relation resolved the target entity
  const targets = await elFindByIds(R.uniq(relations.map((s) => s[`${opposite}Id`])));
  // Group and rebuild the result
  const elGrouped = R.groupBy((e) => e[`${sourceSide}Id`], relations);
  if (paginate) {
    return ids.map((id) => {
      const values = elGrouped[id];
      let edges = [];
      if (values) edges = values.map((i) => ({ node: R.find((s) => s.internal_id === i[`${opposite}Id`], targets) }));
      return buildPagination(0, 0, edges, edges.length);
    });
  }
  const elements = ids.map((id) => {
    const values = elGrouped[id];
    return values?.map((i) => R.find((s) => s.internal_id === i[`${opposite}Id`], targets)) || [];
  });
  if (batched) {
    return elements;
  }
  return R.flatten(elements);
};
export const batchListThroughGetFrom = async (sources, relationType, targetEntityType, opts = {}) => {
  return batchListThrough(sources, 'to', relationType, targetEntityType, opts);
};
export const listThroughGetFrom = async (sources, relationType, targetEntityType, opts = { paginate: false }) => {
  const options = { ...opts, batched: false };
  return batchListThrough(sources, 'to', relationType, targetEntityType, options);
};
export const batchListThroughGetTo = async (sources, relationType, targetEntityType, opts = {}) => {
  return batchListThrough(sources, 'from', relationType, targetEntityType, opts);
};
export const listThroughGetTo = async (sources, relationType, targetEntityType, opts = { paginate: false }) => {
  const options = { ...opts, batched: false };
  return batchListThrough(sources, 'from', relationType, targetEntityType, options);
};
// Unary handle
const loadThrough = async (sources, sourceSide, relationType, targetEntityType) => {
  const elements = await batchListThrough(sources, sourceSide, relationType, targetEntityType, {
    paginate: false,
    batched: false,
  });
  if (elements.length > 1) {
    throw DatabaseError('Expected one element only through relation', { sources, relationType, targetEntityType });
  }
  return R.head(elements);
};
export const batchLoadThroughGetFrom = async (sources, relationType, targetEntityType) => {
  const data = await batchListThroughGetFrom(sources, relationType, targetEntityType, { paginate: false });
  return data.map((b) => b && R.head(b));
};
export const loadThroughGetFrom = async (sources, relationType, targetEntityType) => {
  return loadThrough(sources, 'to', relationType, targetEntityType);
};
export const batchLoadThroughGetTo = async (sources, relationType, targetEntityType) => {
  const data = await batchListThroughGetTo(sources, relationType, targetEntityType, { paginate: false });
  return data.map((b) => b && R.head(b));
};
export const loadThroughGetTo = async (sources, relationType, targetEntityType) => {
  return loadThrough(sources, 'from', relationType, targetEntityType);
};
// Standard listing
export const listEntities = async (entityTypes, args = {}) => {
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
  const finalFilters = filters;
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
    nestedFrom.push({ key: 'internal_id', values: [fromId] });
    if (fromRole) {
      nestedFrom.push({ key: 'role', values: [fromRole] });
    }
  }
  if (fromTypes && fromTypes.length > 0) {
    nestedFrom.push({ key: 'types', values: fromTypes });
    if (toRole) {
      nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
    }
  }
  if (nestedFrom.length > 0) {
    finalFilters.push({ key: 'connections', nested: nestedFrom });
  }
  // endregion
  // region to filtering
  const nestedTo = [];
  if (toId) {
    nestedTo.push({ key: 'internal_id', values: [toId] });
    if (toRole) {
      nestedTo.push({ key: 'role', values: [toRole] });
    }
  }
  if (toTypes && toTypes.length > 0) {
    nestedTo.push({ key: 'types', values: toTypes });
    if (fromRole) {
      nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
    }
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
export const loadEntity = async (entityTypes, args = {}) => {
  const opts = { ...args, connectionFormat: false };
  const entities = await listEntities(entityTypes, opts);
  if (entities.length > 1) {
    throw DatabaseError('Expect only one response', { entityTypes, args });
  }
  return entities && R.head(entities);
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
        return { ...i.target, i_connected_rel: i.rel };
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
        return { rel: e.node, to };
      }, relations.edges);
    });
  }
  let rawData;
  const data = {};
  if (isRelation && !onlyMarking) {
    const fromPromise = loadByIdFullyResolved(instance.fromId, null, { onlyMarking: true, noCache });
    const toPromise = loadByIdFullyResolved(instance.toId, null, { onlyMarking: true, noCache });
    const [rFrom, rTo, rData] = await Promise.all([fromPromise, toPromise, rawDataPromise]);
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
  if (field.includes('.') && !field.endsWith('internal_id')) {
    throw FunctionalError('Distribution entities does not support relation aggregation field');
  }
  let finalField = field;
  if (field.includes('.')) {
    finalField = REL_INDEX_PREFIX + field;
  }
  const distributionData = await elAggregationCount(entityType, finalField, startDate, endDate, filters);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL)) {
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
// endregion

// region mutation common
const TRX_CREATION = 'creation';
const TRX_UPDATE = 'update';
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

// const buildMergeParticipants = (entities) => {
//   // TODO NEED ALSO TO RESOLVE ALL RELATIONS AND IMPACTED ENTITIES
//   return entities.map((e) => `merge_${e.internal_id}`);
// };
const mergeEntitiesRaw = async (user, targetEntity, sourceEntities, opts = {}) => {
  // chosenFields = { 'description': 'source1EntityStandardId', 'hashes': 'source2EntityStandardId' } ]
  logger.debug(`[OPENCTI] Merging ${sourceEntities.map((i) => i.instance)} in ${targetEntity.internal_id}`);
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
  const data = await updateAttributeRaw(user, targetEntity, updateAttributes);
  const { impactedInputs } = data;
  // region Update elasticsearch
  // Elastic update with partial instance to prevent data override
  if (impactedInputs.length > 0) {
    const updateAsInstance = partialInstanceWithInputs(targetEntity, impactedInputs);
    await elUpdateElement(updateAsInstance);
    logger.info(`[OPENCTI] Merging attributes success for ${targetEntity.internal_id}`, { update: updateAsInstance });
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
      id: r.internal_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    updateEntities.push({
      id: sideToKeep,
      toReplace: sideToRedirect,
      relationType,
      entity_type: sideToKeepType,
      data: { internal_id: sideTarget },
    });
    // Update the MERGED TARGET (Need to add the relation side)
    updateEntities.push({
      id: sideTarget,
      toReplace: null,
      relationType,
      entity_type: targetEntity.entity_type,
      data: { internal_id: sideToKeep },
    });
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
      id: r.internal_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    updateEntities.push({
      id: sideToKeep,
      toReplace: sideToRedirect,
      relationType,
      entity_type: sideToKeepType,
      data: { internal_id: sideTarget },
    });
    // Update the MERGED TARGET (Need to add the relation side)
    updateEntities.push({
      id: sideTarget,
      toReplace: null,
      relationType,
      entity_type: targetEntity.entity_type,
      data: { internal_id: sideToKeep },
    });
  }
  // Update all impacted relations.
  logger.debug(`[OPENCTI] Merging, updating ${updateConnections.length} relations for ${targetEntity.internal_id}`);
  await elUpdateRelationConnections(updateConnections);
  // Update all impacted entities
  logger.debug(`[OPENCTI] Merging, impacting ${updateEntities.length} entities for ${targetEntity.internal_id}`);
  await elUpdateEntityConnections(updateEntities);
  // All not move relations will be deleted, so we need to remove impacted rel in entities.
  await elDeleteElements(sourceEntities);
};
export const mergeEntities = async (user, targetEntity, sourceEntities, opts = {}) => {
  // targetEntity and sourceEntities must be fully resolved elements
  const { locks = [] } = opts;
  // We need to lock all elements not locked yet.
  const allTargets = [targetEntity, ...sourceEntities].map((entity) => [
    entity,
    Object.values(entity.i_relations_from || []),
    Object.values(entity.i_relations_to || []),
  ]);
  const participantIds = R.uniq(
    R.flatten(allTargets)
      .filter((f) => !isUnimpactedEntity(f))
      .map((i) => i.internal_id)
      .filter((a) => !locks.includes(a))
  );
  let lock;
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    // - TRANSACTION PART
    await mergeEntitiesRaw(user, targetEntity, sourceEntities, opts);
    await storeMergeEvent(user, targetEntity, sourceEntities);
    // - END TRANSACTION
    return loadById(targetEntity.id, ABSTRACT_STIX_CORE_OBJECT).then((finalStixCoreObject) =>
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
  let masterKey = key;
  if (key.includes('.')) {
    const [firstPart] = key.split('.');
    masterKey = firstPart;
  }
  if (!R.includes(masterKey, schemaTypes.getAttributes(entityType))) {
    throw FunctionalError(`This attribute key ${key} is not allowed on the type ${entityType}`);
  }
};
const innerUpdateAttribute = async (user, instance, rawInput, options = {}) => {
  const { key } = rawInput;
  // Check consistency
  checkAttributeConsistency(instance.entity_type, key);
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

function prepareAttributes(elements) {
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
}

export const updateAttributeRaw = async (user, instance, inputs, options = {}) => {
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const updatedInputs = [];
  const impactedInputs = [];
  const instanceType = instance.entity_type;
  // Prepare attributes
  const preparedElements = prepareAttributes(elements);
  // Update all needed attributes
  for (let index = 0; index < preparedElements.length; index += 1) {
    const input = preparedElements[index];
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
  const participantIds = [instance.internal_id, instance.standard_id];
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
  let eventualNewStandardId = null;
  if (isFieldContributingToStandardId(instance, keys)) {
    // In this case we need to reconstruct the data like if an update already appears
    // Based on that we will be able to generate the correct standard id
    const mergeInput = (input) => rebuildAndMergeInputFromExistingData(input, instance, options);
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
      const existingEntity = await loadByIdFullyResolved(eventualNewStandardId);
      if (existingEntity) {
        // If stix observable, we can merge. If not throw an error.
        if (isStixCyberObservable(existingEntity.entity_type)) {
          // noinspection UnnecessaryLocalVariableJS
          const merged = await mergeEntities(user, existingEntity, [instance], { locks: participantIds });
          // Return merged element after waiting for it.
          return merged;
        }
        throw FunctionalError(`This update will produce a duplicate`, { id: instance.id, type });
      }
    }
    // noinspection UnnecessaryLocalVariableJS
    const data = await updateAttributeRaw(user, instance, inputs, options);
    const { updatedInstance, impactedInputs } = data;
    if (impactedInputs.length > 0) {
      const updateAsInstance = partialInstanceWithInputs(instance, impactedInputs);
      await elUpdateElement(updateAsInstance);
    }
    // Only push event in stream if modifications really happens
    if (data.updatedInputs.length > 0) {
      const updatedData = updatedInputsToData(data.updatedInputs);
      await storeUpdateEvent(user, instance, [{ [operation]: updatedData }]);
    }
    // Return updated element after waiting for it.
    return updatedInstance;
  } finally {
    if (lock) await lock.unlock();
  }
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
const buildRelationInput = (input) => {
  const { relationship_type: relationshipType } = input;
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
      streamInput = { ...streamInput, ...R.mergeAll(targetsPerType) };
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

const getLocksFromInput = (type, input) => {
  const standardId = input.standard_id || generateStandardId(type, input);
  const inputIds = [...(input.externalReferences || []), ...(input.objects || [])].map((e) => e.internal_id);
  const lockIds = [standardId, ...inputIds];
  if (isNotEmptyField(input.stix_id)) {
    lockIds.push(input.stix_id);
  }
  if (isStixObjectAliased(type)) {
    const aliases = [input.name, ...(input.aliases || []), ...(input.x_opencti_aliases || [])];
    if (type === ENTITY_TYPE_ATTACK_PATTERN && input.x_mitre_id && !aliases.includes(input.x_mitre_id)) {
      aliases.push(input.x_mitre_id);
    }
    lockIds.push(...generateAliasesId(aliases));
  }
  return lockIds;
};

const createRelationRaw = async (user, input) => {
  const { from, to, relationship_type: relationshipType } = input;
  // 01. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // region 02. Check existing relationship
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
  // 03. Prepare the relation to be created
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
    // Types
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
  // Check consistency
  checkRelationConsistency(relationshipType, from.entity_type, to.entity_type);
  // Build lock ids
  const lockIds = getLocksFromInput(relationshipType, resolvedInput);
  if (!isUnimpactedEntity(from)) lockIds.push(from.internal_id);
  if (!isUnimpactedEntity(to)) lockIds.push(to.internal_id);
  try {
    // Try to get the lock in redis
    lock = await lockResource(lockIds);
    // - TRANSACTION PART
    const dataRel = await createRelationRaw(user, resolvedInput);
    // Index the created element
    await indexCreatedElement(dataRel);
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
        const relWithConnections = { ...dataRel.element, from, to };
        await storeCreateEvent(user, relWithConnections, resolvedInput);
      }
    } else if (dataRel.streamInputs.length > 0) {
      // If upsert with new data
      await storeUpdateEvent(user, dataRel.element, dataRel.streamInputs);
    }
    // - TRANSACTION END
    return dataRel.element;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ lockIds });
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
      // If a STIX ID has been passed in the creation
      if (input.stix_id) {
        // Find the entity corresponding to this STIX ID
        const stixIdFinder = (e) => e.standard_id === input.stix_id || e.x_opencti_stix_ids.includes(input.stix_id);
        const existingByGivenStixId = R.find(stixIdFinder, existingEntities);
        // If the entity exists by the stix id and not the same as the previously founded.
        if (existingByGivenStixId && existingByGivenStixId.internal_id !== existingByStandard.internal_id) {
          // Merge this entity into the one matching the standard id
          await mergeEntities(user, existingByStandard, [existingByGivenStixId], { locks: participantIds });
        }
      }
      // In this mode we can safely consider this entity like the existing one.
      // We can upsert element except the aliases that are part of other entities
      const concurrentEntities = R.filter((e) => e.standard_id !== standardId, existingEntities);
      const key = resolveAliasesField(type);
      const concurrentAliases = R.uniq(R.flatten(R.map((c) => c[key], concurrentEntities)));
      const filteredAliases = input[key] ? R.filter((i) => !concurrentAliases.includes(i), input[key]) : [];
      const inputAliases = { ...input, [key]: filteredAliases };
      return upsertElementRaw(user, existingByStandard.id, type, inputAliases);
    }
    // If not we dont know what to do, just throw an exception.
    const entityIds = R.map((i) => i.standard_id, existingEntities);
    throw UnsupportedError('Cant upsert entity. Too many entities resolved', { input, entityIds });
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
      R.assoc('confidence', R.isNil(data.confidence) ? computeConfidenceLevel(input) : data.confidence),
      R.assoc('lang', R.isNil(data.lang) ? 'en' : data.lang),
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    const aliases = [input.name, ...(data[ATTRIBUTE_ALIASES] || []), ...(data[ATTRIBUTE_ALIASES_OPENCTI] || [])];
    if (type === ENTITY_TYPE_ATTACK_PATTERN && input.x_mitre_id && !aliases.includes(input.x_mitre_id)) {
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
  const resolvedInput = await inputResolveRefs(input);
  // Generate all the possibles ids
  // For marking def, we need to force the standard_id
  const standardId = input.standard_id || generateStandardId(type, resolvedInput);
  const participantIds = getLocksFromInput(type, resolvedInput);
  // Create the element
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // - TRANSACTION PART
    const dataEntity = await createEntityRaw(user, standardId, participantIds, resolvedInput, type);
    // Index the created element
    await indexCreatedElement(dataEntity);
    // Push the input in the stream
    if (dataEntity.type === TRX_CREATION) {
      await storeCreateEvent(user, dataEntity.element, resolvedInput);
    } else if (dataEntity.streamInputs.length > 0) {
      // If upsert with new data
      await storeUpdateEvent(user, dataEntity.element, dataEntity.streamInputs);
    }
    // - TRANSACTION END
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
export const deleteElementByIdRaw = async (element) => {
  await elDeleteElement(element);
};
export const deleteElementById = async (user, elementId, type, options = {}) => {
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting an entity`);
  }
  // Check consistency
  const element = await loadByIdFullyResolved(elementId, type, options);
  await deleteElementByIdRaw(element);
  await storeDeleteEvent(user, element);
  // Return id
  return elementId;
};
export const deleteRelationsByFromAndTo = async (user, fromId, toId, relationshipType, scopeType, opts = {}) => {
  /* istanbul ignore if */
  if (R.isNil(scopeType)) {
    throw FunctionalError(`You need to specify a scope type when deleting a relation with from and to`);
  }
  const fromThing = await internalLoadById(fromId, opts);
  const toThing = await internalLoadById(toId, opts);
  // Looks like the caller doesnt give the correct from, to currently
  const relationsToDelete = await elFindByFromAndTo(fromThing.internal_id, toThing.internal_id, relationshipType);
  for (let i = 0; i < relationsToDelete.length; i += 1) {
    const r = relationsToDelete[i];
    // eslint-disable-next-line no-await-in-loop
    await deleteElementById(user, r.internal_id, r.entity_type, opts);
  }
  return true;
};
// endregion
