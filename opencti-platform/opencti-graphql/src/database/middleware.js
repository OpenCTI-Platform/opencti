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
  ValidationError,
} from '../config/errors';
import {
  buildPagination,
  computeAverage,
  fillTimeSeries,
  inferIndexFromConceptType,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  READ_DATA_INDICES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
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
} from './engine';
import {
  FIRST_OBSERVED,
  FIRST_SEEN,
  generateAliasesId,
  generateAliasesIdsForInstance,
  generateInternalId,
  generateStandardId,
  getInputIds,
  getInstanceIds,
  idGenFromData,
  INTERNAL_FROM_FIELD,
  INTERNAL_TO_FIELD,
  isFieldContributingToStandardId,
  isTypeHasAliasIDs,
  LAST_OBSERVED,
  LAST_SEEN,
  NAME_FIELD,
  normalizeName,
  REVOKED,
  START_TIME,
  STOP_TIME,
  VALID_FROM,
  VALID_UNTIL,
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
  convertInstanceToStix,
  checkStixCoreRelationshipMapping,
  checkStixCyberObservableRelationshipMapping,
  cleanStixIds,
  isTrustedStixId,
  mergeDeepRightAll,
  STIX_SPEC_VERSION,
  stixCyberObservableRelationshipsMapping,
  stixCyberObservableTypeFields,
} from './stix';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
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
  MULTIPLE_META_RELATIONSHIPS_INPUTS,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
  schemaTypes,
  STIX_META_RELATIONSHIPS_INPUTS,
} from '../schema/general';
import { getParentTypes, isAnId } from '../schema/schemaUtils';
import {
  isStixCyberObservableRelationship,
  MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
  STIX_ATTRIBUTE_TO_CYBER_RELATIONS,
  STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE,
  STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
} from '../schema/stixCyberObservableRelationship';
import {
  FIELD_TO_META_RELATION,
  META_FIELD_TO_STIX_ATTRIBUTE,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_MARKING,
  STIX_ATTRIBUTE_TO_META_RELATIONS,
} from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_STATUS,
  internalObjectsFieldsToBeUpdated,
  isDatedInternalObject,
  isInternalObject,
} from '../schema/internalObject';
import { isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationShipExceptMeta } from '../schema/stixRelationship';
import {
  booleanAttributes,
  dateAttributes,
  dateForEndAttributes,
  dateForLimitsAttributes,
  dateForStartAttributes,
  dictAttributes,
  isDateAttribute,
  isDictionaryAttribute,
  isModifiedObject,
  isMultipleAttribute,
  isNumericAttribute,
  isUpdatedAtObject,
  noReferenceAttributes,
  numericAttributes,
  statsDateAttributes,
} from '../schema/fieldDataAdapter';
import { isStixCoreRelationship, RELATION_REVOKED_BY } from '../schema/stixCoreRelationship';
import {
  ATTRIBUTE_ADDITIONAL_NAMES,
  ATTRIBUTE_ALIASES,
  ATTRIBUTE_ALIASES_OPENCTI,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INDICATOR,
  isStixDomainObject,
  isStixObjectAliased,
  resolveAliasesField,
  stixDomainObjectFieldsToBeUpdated,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_LABEL, isStixMetaObject } from '../schema/stixMetaObject';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import {
  isStixCyberObservable,
  isStixCyberObservableHashedObservable,
  stixCyberObservableFieldsToBeUpdated,
} from '../schema/stixCyberObservable';
import conf, { BUS_TOPICS, logApp } from '../config/conf';
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
import { deleteAllFiles, rawFilesListing, stixFileConverter } from './minio';
import { BYPASS, BYPASS_REFERENCE, filterElementsAccordingToUser, SYSTEM_USER } from '../utils/access';
import { isRuleUser, RULE_MANAGER_USER, RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules';
import {
  FIELD_ATTRIBUTE_TO_EMBEDDED_RELATION,
  instanceMetaRefsExtractor,
  isSingleStixEmbeddedRelationship,
  isSingleStixEmbeddedRelationshipInput,
  isStixEmbeddedRelationship,
  META_FIELD_ATTRIBUTES,
  META_STIX_ATTRIBUTES,
  STIX_ATTRIBUTE_TO_META_FIELD,
  STIX_EMBEDDED_RELATION_TO_FIELD,
} from '../schema/stixEmbeddedRelationship';
import { buildFilters, listEntities } from './repository';
import { askEnrich } from '../domain/enrichment';

// region global variables
export const MAX_BATCH_SIZE = 300;
const FUZZY_HASH_ALGORITHMS = ['SSDEEP', 'SDHASH', 'TLSH', 'LZJD'];
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
export const querySubType = async (subTypeId) => {
  const attributes = schemaTypes.getAttributes(subTypeId);
  if (attributes.length > 0) {
    return {
      id: subTypeId,
      label: subTypeId,
    };
  }
  return null;
};
export const queryDefaultSubTypes = async () => {
  const sortByLabel = R.sortBy(R.toLower);
  const types = schemaTypes.get(ABSTRACT_STIX_DOMAIN_OBJECT);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, label: n } })),
    R.append({ node: { id: ABSTRACT_STIX_CORE_RELATIONSHIP, label: ABSTRACT_STIX_CORE_RELATIONSHIP } }),
    R.append({ node: { id: STIX_SIGHTING_RELATIONSHIP, label: STIX_SIGHTING_RELATIONSHIP } })
  )(types);
  return buildPagination(0, null, finalResult, finalResult.length);
};
export const querySubTypes = async ({ type = null }) => {
  if (type === null) {
    return queryDefaultSubTypes();
  }
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
    R.map((n) => ({ node: { id: n, key: type, value: n } }))
  )(attributes);
  return buildPagination(0, null, finalResult, finalResult.length);
};
const checkIfInferenceOperationIsValid = (user, element) => {
  const isRuleManaged = isRuleUser(user);
  const ifElementInferred = isInferredIndex(element._index);
  if (ifElementInferred && !isRuleManaged) {
    throw UnsupportedError('Manual inference deletion is not allowed', { id: element.id });
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
        edges = (values || [])
          .map((i) => R.find((s) => s.internal_id === i[`${opposite}Id`], targets))
          .filter((n) => isNotEmptyField(n))
          .map((n) => ({ node: n }));
      }
      return buildPagination(0, null, edges, edges.length);
    });
  }
  const elements = ids.map((id) => {
    let values = elGrouped[id];
    if (first) {
      values = R.take(first, values);
    }
    return (values || [])
      .map((i) => R.find((s) => s.internal_id === i[`${opposite}Id`], targets))
      .filter((n) => isNotEmptyField(n));
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
const buildRelationsFilter = (relationshipTypes, args) => {
  const relationsToGet = Array.isArray(relationshipTypes)
    ? relationshipTypes
    : [relationshipTypes || 'stix-core-relationship'];
  const { relationFilter = false } = args;
  const {
    filters = [],
    elementId,
    fromId,
    fromRole,
    toId,
    toRole,
    fromTypes = [],
    toTypes = [],
    elementWithTargetTypes = [],
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
  // Handle relation type(s)
  // 0 - Check if we can support the query by Elastic
  const finalFilters = filters;
  if (relationFilter) {
    const { relation, id, relationId } = relationFilter;
    finalFilters.push({ key: buildRefRelationKey(relation), values: [id] });
    if (relationId) {
      finalFilters.push({ key: 'internal_id', values: [relationId] });
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
  return R.pipe(R.assoc('types', relationsToGet), R.assoc('filters', finalFilters))(args);
};
export const listThings = async (user, thingsTypes, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildFilters({ types: thingsTypes, ...args });
  return elPaginate(user, indices, paginateArgs);
};
export const listAllThings = async (user, thingsTypes, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildFilters({ types: thingsTypes, ...args });
  return elList(user, indices, paginateArgs);
};
export const paginateAllThings = async (user, thingsTypes, args = {}) => {
  const result = await listAllThings(user, thingsTypes, args);
  const nodeResult = result.map((n) => ({ node: n }));
  return buildPagination(0, null, nodeResult, nodeResult.length);
};
export const listRelations = async (user, relationshipType, args = {}) => {
  const { indices = READ_RELATIONSHIPS_INDICES } = args;
  const paginateArgs = buildRelationsFilter(relationshipType, args);
  return elPaginate(user, indices, paginateArgs);
};
export const listAllRelations = async (user, relationshipType, args = {}) => {
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
    throw FunctionalError('You need to specify a type when loading a element');
  }
  const loadArgs = R.assoc('type', type, args);
  return internalLoadById(user, id, loadArgs);
};
export const connectionLoaders = async (user, instance) => {
  if (isBasicRelationship(instance.entity_type)) {
    const fromPromise = internalLoadById(user, instance.fromId);
    const toPromise = internalLoadById(user, instance.toId);
    const [from, to] = await Promise.all([fromPromise, toPromise]);
    if (!from) {
      throw FunctionalError('Inconsistent relation to update (from)', { id: instance.id, from: instance.fromId });
    }
    if (!to) {
      throw FunctionalError('Inconsistent relation to update (to)', { id: instance.id, to: instance.toId });
    }
    return R.mergeRight(instance, { from, to });
  }
  return instance;
};
const transformRawRelationsToAttributes = (data) => {
  return R.mergeAll(Object.entries(R.groupBy((a) => a.i_relation.entity_type, data)).map(([k, v]) => ({ [k]: v })));
};
const loadElementDependencies = async (user, element, args = {}) => {
  const { dependencyTypes = [ABSTRACT_STIX_RELATIONSHIP] } = args;
  const { onlyMarking = true, fullResolve = false } = args;
  const elementId = element.internal_id;
  const relTypes = onlyMarking ? [RELATION_OBJECT_MARKING] : dependencyTypes;
  // Resolve all relations
  // noinspection ES6MissingAwait
  const toRelationsPromise = fullResolve ? listAllRelations(user, relTypes, { toId: elementId }) : [];
  const fromRelationsPromise = listAllRelations(user, relTypes, { fromId: elementId });
  const [fromRelations, toRelations] = await Promise.all([fromRelationsPromise, toRelationsPromise]);
  const data = {};
  // Parallel resolutions
  const toResolvedIds = R.uniq(fromRelations.map((rel) => rel.toId));
  const fromResolvedIds = R.uniq(toRelations.map((rel) => rel.fromId));
  const toResolvedPromise = elFindByIds(user, toResolvedIds, { toMap: true });
  const fromResolvedPromise = elFindByIds(user, fromResolvedIds, { toMap: true });
  const [toResolved, fromResolved] = await Promise.all([toResolvedPromise, fromResolvedPromise]);
  if (fromRelations.length > 0) {
    // Build the flatten view inside the data for stix meta
    const metaRels = fromRelations.filter((r) => isStixEmbeddedRelationship(r.entity_type));
    const grouped = R.groupBy((a) => STIX_EMBEDDED_RELATION_TO_FIELD[a.entity_type], metaRels);
    const entries = Object.entries(grouped);
    for (let index = 0; index < entries.length; index += 1) {
      const [key, values] = entries[index];
      data[key] = R.map((v) => {
        const resolvedElement = toResolved[v.toId];
        if (resolvedElement) {
          return { ...resolvedElement, i_relation: v };
        }
        return {};
      }, values).filter((d) => isNotEmptyField(d));
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
export const loadByIdWithMetaRels = async (user, id, opts = {}) => {
  const { type = null, withFiles = false } = opts;
  const instance = await loadByIdWithDependencies(user, id, type, {
    dependencyTypes: [ABSTRACT_STIX_META_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP],
    onlyMarking: false,
    fullResolve: false,
  });
  if (instance && withFiles) {
    const filesList = await rawFilesListing(user, `import/${instance.entity_type}/${instance.id}/`);
    instance.x_opencti_files = filesList.map((f) => stixFileConverter(user, f));
  }
  return instance;
};
export const loadStixById = async (user, id, opts = {}) => {
  const instance = await loadByIdWithMetaRels(user, id, opts);
  if (instance) {
    return convertInstanceToStix(instance);
  }
  return undefined;
};
export const convertDataToRawStix = async (user, id) => {
  const data = await loadStixById(user, id, { withFiles: true });
  return data ? JSON.stringify(data) : '';
};
// endregion

// region Graphics
const convertAggregateDistributions = async (user, limit, orderingFunction, distribution) => {
  const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distribution));
  const resolveLabels = await elFindByIds(user, data.map((d) => d.label), { toMap: true });
  return data // Depending of user access, info can be empty, must be filtered
    .filter((n) => isNotEmptyField(resolveLabels[n.label]))
    .map((n) => R.assoc('entity', resolveLabels[n.label], n));
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
export const distributionEntities = async (user, entityType, filters, options = {}) => {
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
  ...STIX_META_RELATIONSHIPS_INPUTS.map((e) => ({ src: e })),
  ...STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS.map((e) => ({ src: e })),
];
const idLabel = (label) => {
  return isAnId(label) ? label : generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(label) });
};
const inputResolveRefs = async (user, input, type) => {
  const fetchingIds = [];
  const expectedIds = [];
  const cleanedInput = { ...input };
  for (let index = 0; index < depsKeys.length; index += 1) {
    const { src, dst } = depsKeys[index];
    const destKey = dst || src;
    const id = input[src];
    if (!R.isNil(id) && !R.isEmpty(id)) {
      const isListing = Array.isArray(id);
      // Handle specific case of object label that can be directly the value instead of the key.
      if (src === INPUT_LABELS) {
        const elements = R.uniq(id.map((label) => idLabel(label))).map((lid) => ({ id: lid, destKey, multiple: true }));
        fetchingIds.push(...elements);
        expectedIds.push(...elements.map((e) => e.id));
      } else if (isListing) {
        const elements = R.uniq(id).map((i) => ({ id: i, destKey, multiple: true }));
        fetchingIds.push(...elements);
        expectedIds.push(...elements.map((e) => e.id));
      } else if (!expectedIds.includes(id)) {
        fetchingIds.push({ id, destKey, multiple: false });
        expectedIds.push(id);
      }
      cleanedInput[src] = null;
    }
  }
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
  // We only accepts missing objects_refs (Report, Opinion, Note, Observed-data)
  const expectedUnresolvedIds = unresolvedIds.filter((u) => !(input[INPUT_OBJECTS] || []).includes(u));
  if (expectedUnresolvedIds.length > 0) {
    throw MissingReferenceError({ input, unresolvedIds: expectedUnresolvedIds });
  }
  const complete = { ...cleanedInput, entity_type: type };
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
const updatedInputsToData = (inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value } = input;
    let val = value;
    if (!isMultipleAttribute(key) && val) {
      val = R.head(value);
    }
    return { [key]: val };
  }, inputs);
  return mergeDeepRightAll(...inputPairs);
};
const mergeInstanceWithInputs = (instance, inputs) => {
  // standard_id must be maintained
  const inputsWithoutId = inputs.filter((i) => i.key !== ID_STANDARD);
  const data = updatedInputsToData(inputsWithoutId);
  const updatedInstance = R.mergeRight(instance, data);
  return R.reject(R.equals(null))(updatedInstance);
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
const rebuildAndMergeInputFromExistingData = (rawInput, instance) => {
  const { key, value, operation = UPDATE_OPERATION_REPLACE } = rawInput; // value can be multi valued
  const isMultiple = isMultipleAttribute(key);
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
    if (R.equals((finalVal ?? []).sort(), currentValues.sort())) {
      return {}; // No need to update the attribute
    }
  } else {
    finalVal = value;
    const isDate = dateAttributes.includes(key);
    const evaluateValue = value ? R.head(value) : null;
    if (isDate) {
      if (isEmptyField(evaluateValue)) {
        if (instance[key] === FROM_START_STR || instance[key] === UNTIL_END_STR) {
          return {};
        }
      } else if (utcDate(instance[key]).isSame(utcDate(evaluateValue))) {
        return {};
      }
    }
    if (R.equals(instance[key], evaluateValue) || (isEmptyField(instance[key]) && isEmptyField(evaluateValue))) {
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
  if (dateAttributes.includes(finalKey)) {
    const finalValElement = R.head(finalVal);
    if (isEmptyField(finalValElement)) {
      finalVal = [null];
    }
  }
  if (dateForLimitsAttributes.includes(finalKey)) {
    const finalValElement = R.head(finalVal);
    if (dateForStartAttributes.includes(finalKey) && isEmptyField(finalValElement)) {
      finalVal = [FROM_START_STR];
    }
    if (dateForEndAttributes.includes(finalKey) && isEmptyField(finalValElement)) {
      finalVal = [UNTIL_END_STR];
    }
  }
  return { key: finalKey, value: finalVal, operation };
};
const mergeInstanceWithUpdateInputs = (instance, inputs) => {
  const updates = Array.isArray(inputs) ? inputs : [inputs];
  const metaKeys = [...META_STIX_ATTRIBUTES, ...META_FIELD_ATTRIBUTES];
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  const mergeInput = (input) => rebuildAndMergeInputFromExistingData(input, instance);
  const remappedInputs = R.map((i) => mergeInput(i), attributes);
  const resolvedInputs = R.filter((f) => !R.isEmpty(f), remappedInputs);
  return mergeInstanceWithInputs(instance, resolvedInputs);
};
const listEntitiesByHashes = (user, type, hashes) => {
  if (isEmptyField(hashes)) {
    return [];
  }
  // Search hashes must filter the fuzzy hashes
  const searchHashes = Object.entries(hashes)
    .filter(([hashKey]) => !FUZZY_HASH_ALGORITHMS.includes(hashKey.toUpperCase()))
    .map(([, hashValue]) => hashValue)
    .filter((hashValue) => isNotEmptyField(hashValue));
  return listEntities(user, [type], {
    filters: [{ key: 'hashes.*', values: searchHashes, operator: 'wildcard' }],
    connectionFormat: false,
  });
};
export const hashMergeValidation = (instances) => {
  // region Specific check for observables with hashes
  // If multiple results start by checking the possible merge validity
  const allHashes = instances.map((h) => h.hashes).filter((e) => isNotEmptyField(e));
  if (allHashes.length > 0) {
    const elements = allHashes.map((e) => Object.entries(e)).flat();
    const groupElements = R.groupBy(([key]) => key, elements);
    Object.entries(groupElements).forEach(([algo, values]) => {
      const hashes = R.uniq(values.map(([, data]) => data));
      if (hashes.length > 1) {
        const field = `hashes_${algo.toUpperCase()}`;
        const message = { message: `Hashes collision for ${algo} algorithm` };
        throw ValidationError(field, message);
      }
    });
  }
};
// endregion

// region mutation update
const targetedRelations = (entities, direction) => {
  return R.flatten(
    R.map((s) => {
      const relations = [];
      const directedRelations = s[`i_relations_${direction}`];
      const info = directedRelations ? Object.entries(directedRelations) : [];
      for (let index = 0; index < info.length; index += 1) {
        const [key, values] = info[index];
        if (!isSingleStixEmbeddedRelationship(key)) {
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
  // - No self merge
  const sourceIds = R.map((e) => e.internal_id, sourceEntities);
  if (R.includes(targetEntity.internal_id, sourceIds)) {
    throw FunctionalError('Cannot merge an entity on itself', {
      dest: targetEntity.internal_id,
      source: sourceIds,
    });
  }
  // - No inferences
  const elementsInferences = elements.filter((s) => isInferredIndex(s._index));
  if (elementsInferences.length > 0) {
    throw FunctionalError('Cannot merge inferred entities', {
      inferences: elementsInferences.map((e) => e.internal_id)
    });
  }
  // - No different types
  const targetType = targetEntity.entity_type;
  const sourceTypes = R.map((s) => s.entity_type, sourceEntities);
  const isWorkingOnSameType = sourceTypes.every((v) => v === targetType);
  if (!isWorkingOnSameType) {
    throw FunctionalError('Cannot merge entities of different types', {
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
      standard_id: r.standard_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      side: 'source_ref',
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
      standard_id: r.standard_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      side: 'target_ref',
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
  const updatedRelations = updateConnections
    .filter((u) => isStixRelationShipExceptMeta(u.entity_type))
    .map((c) => ({ id: c.standard_id }));
  // Update all impacted entities
  logApp.info(`[OPENCTI] Merging impacting ${updateEntities.length} entities for ${targetEntity.internal_id}`);
  const updatesByEntity = R.groupBy((i) => i.id, updateEntities);
  const entries = Object.entries(updatesByEntity);
  let currentEntUpdateCount = 0;
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
  const dependencyDeletions = await elDeleteElements(user, sourceEntities, {
    stixLoadById: loadByIdWithMetaRels,
  });
  // Everything if fine update remaining attributes
  const updateAttributes = [];
  // 1. Update all possible attributes
  const attributes = schemaTypes.getAttributes(targetType);
  const targetFields = attributes.filter((s) => !s.startsWith(INTERNAL_PREFIX));
  for (let fieldIndex = 0; fieldIndex < targetFields.length; fieldIndex += 1) {
    const targetFieldKey = targetFields[fieldIndex];
    const mergedEntityCurrentFieldValue = targetEntity[targetFieldKey];
    const chosenSourceEntityId = chosenFields[targetFieldKey];
    // Select the one that will fill the empty MONO value of the target
    const takenFrom = chosenSourceEntityId
      ? R.find((i) => i.standard_id === chosenSourceEntityId, sourceEntities)
      : R.head(sourceEntities); // If not specified, take the first one.
    const sourceFieldValue = takenFrom[targetFieldKey];
    const fieldValues = R.flatten(sourceEntities.map((s) => s[targetFieldKey])).filter((s) => isNotEmptyField(s));
    // Check if we need to do something
    if (isDictionaryAttribute(targetFieldKey)) {
      // Special case of dictionary
      const mergedDict = R.mergeAll([...fieldValues, mergedEntityCurrentFieldValue]);
      const dictInputs = Object.entries(mergedDict).map(([k, v]) => ({
        key: `${targetFieldKey}.${k}`,
        value: [v],
      }));
      updateAttributes.push(...dictInputs);
    } else if (isMultipleAttribute(targetFieldKey)) {
      const sourceValues = fieldValues || [];
      // For aliased entities, get name of the source to add it as alias of the target
      if (targetFieldKey === ATTRIBUTE_ALIASES || targetFieldKey === ATTRIBUTE_ALIASES_OPENCTI) {
        sourceValues.push(...sourceEntities.map((s) => s.name));
      }
      // For x_opencti_additional_names exists, add the source name inside
      if (targetFieldKey === ATTRIBUTE_ADDITIONAL_NAMES) {
        sourceValues.push(...sourceEntities.map((s) => s.name));
      }
      // standard_id of merged entities must be kept in x_opencti_stix_ids
      if (targetFieldKey === IDS_STIX) {
        sourceValues.push(...sourceEntities.map((s) => s.standard_id));
      }
      // If multiple attributes, concat all values
      if (sourceValues.length > 0) {
        const multipleValues = R.uniq(R.concat(mergedEntityCurrentFieldValue || [], sourceValues));
        updateAttributes.push({ key: targetFieldKey, value: multipleValues, operation: UPDATE_OPERATION_ADD });
      }
    } else if (isEmptyField(mergedEntityCurrentFieldValue) && isNotEmptyField(sourceFieldValue)) {
      // Single value. Put the data in the merged field only if empty.
      updateAttributes.push({ key: targetFieldKey, value: [sourceFieldValue] });
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
  // Return extra deleted stix relations
  return { updatedRelations, dependencyDeletions };
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
    throw FunctionalError('Cannot merge entities, same ID detected in source and destination', {
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
    const initialInstance = await loadByIdWithMetaRels(user, targetEntityId);
    const mergeImpacts = await mergeEntitiesRaw(user, target, sources, opts);
    const mergedInstance = await loadByIdWithMetaRels(user, targetEntityId);
    await storeMergeEvent(user, initialInstance, mergedInstance, sources, mergeImpacts);
    // Temporary stored the deleted elements to prevent concurrent problem at creation
    await redisAddDeletions(sources.map((s) => s.internal_id));
    // - END TRANSACTION
    return loadById(user, target.id, ABSTRACT_STIX_CORE_OBJECT).then((finalStixCoreObject) => notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalStixCoreObject, user));
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

const transformPatchToInput = (patch, operations = {}) => {
  return R.pipe(
    R.toPairs,
    R.map((t) => {
      const val = R.last(t);
      const key = R.head(t);
      const operation = operations[key] || UPDATE_OPERATION_REPLACE;
      if (!R.isNil(val)) {
        return { key, value: Array.isArray(val) ? val : [val], operation };
      }
      return { key, value: null, operation };
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
const innerUpdateAttribute = (instance, rawInput) => {
  const { key } = rawInput;
  // Check consistency
  checkAttributeConsistency(instance.entity_type, key);
  const input = rebuildAndMergeInputFromExistingData(rawInput, instance);
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

const getPreviousInstanceValue = (key, instance) => {
  if (key.includes('.')) {
    const [base, target] = key.split('.');
    const data = instance[base]?.[target];
    return data ? [data] : data;
  }
  const data = instance[key];
  if (isEmptyField(data)) {
    return undefined;
  }
  return isMultipleAttribute(key) ? data : [data];
};

const updateDateRangeValidation = (instance, inputs, from, to) => {
  const fromVal = R.head(R.find((e) => e.key === from, inputs)?.value || [instance[from]]);
  const toVal = R.head(R.find((e) => e.key === to, inputs)?.value || [instance[to]]);
  if (utcDate(fromVal) > utcDate(toVal)) {
    const data = { inputs, [from]: fromVal, [to]: toVal };
    throw DatabaseError(`You cant update an element with ${to} less than ${from}`, data);
  }
};
export const updateAttributeRaw = (instance, inputs, opts = {}) => {
  const { impactStandardId = true } = opts;
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const updatedInputs = [];
  const impactedInputs = [];
  const instanceType = instance.entity_type;
  // Prepare attributes
  const preparedElements = prepareAttributes(elements);
  // Check date range
  const inputKeys = inputs.map((i) => i.key);
  if (inputKeys.includes(START_TIME) || inputKeys.includes(STOP_TIME)) {
    updateDateRangeValidation(instance, inputs, START_TIME, STOP_TIME);
  }
  if (inputKeys.includes(FIRST_SEEN) || inputKeys.includes(LAST_SEEN)) {
    updateDateRangeValidation(instance, inputs, FIRST_SEEN, LAST_SEEN);
  }
  if (inputKeys.includes(VALID_FROM) || inputKeys.includes(VALID_UNTIL)) {
    updateDateRangeValidation(instance, inputs, VALID_FROM, VALID_UNTIL);
  }
  if (inputKeys.includes(FIRST_OBSERVED) || inputKeys.includes(LAST_OBSERVED)) {
    updateDateRangeValidation(instance, inputs, FIRST_OBSERVED, LAST_OBSERVED);
  }
  // Update all needed attributes
  for (let index = 0; index < preparedElements.length; index += 1) {
    const input = preparedElements[index];
    const { operation = UPDATE_OPERATION_REPLACE } = input;
    const ins = innerUpdateAttribute(instance, input);
    if (ins.length > 0) {
      // Updated inputs must not be internals
      const filteredIns = ins
        .filter((n) => n.key === input.key)
        .filter((o) => {
          if (input.key !== IDS_STIX) {
            return true;
          }
          const previous = getPreviousInstanceValue(o.key, instance);
          if (o.operation === UPDATE_OPERATION_ADD) {
            const newValues = o.value.filter((p) => !(previous || []).includes(p));
            return newValues.filter((p) => isTrustedStixId(p)).length > 0;
          }
          if (o.operation === UPDATE_OPERATION_REMOVE) {
            const newValues = (previous || []).filter((p) => !o.value.includes(p));
            return newValues.filter((p) => isTrustedStixId(p)).length > 0;
          }
          return o.value.filter((p) => isTrustedStixId(p)).length > 0;
        });
      if (filteredIns.length > 0) {
        const updatedInputsFiltered = filteredIns.map((filteredInput) => {
          const previous = getPreviousInstanceValue(filteredInput.key, instance);
          if (filteredInput.operation === UPDATE_OPERATION_ADD) {
            return {
              operation: filteredInput.operation,
              key: filteredInput.key,
              value: filteredInput.value.filter((n) => !(previous || []).includes(n)),
              previous,
            };
          }
          if (filteredInput.operation === UPDATE_OPERATION_REMOVE) {
            return {
              operation: filteredInput.operation,
              key: filteredInput.key,
              value: (previous || []).filter((n) => !filteredInput.value.includes(n)),
              previous,
            };
          }
          return { ...filteredInput, previous };
        });
        updatedInputs.push(...updatedInputsFiltered);
      }
      impactedInputs.push(...ins);
    }
    // If named entity name updated, modify the aliases ids
    if (input.key === NAME_FIELD && isStixObjectAliased(instanceType) && isTypeHasAliasIDs(instanceType)) {
      const name = R.head(input.value);
      const aliases = [name, ...(instance[ATTRIBUTE_ALIASES] || []), ...(instance[ATTRIBUTE_ALIASES_OPENCTI] || [])];
      const aliasesId = generateAliasesId(aliases, instance);
      const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
      const aliasIns = innerUpdateAttribute(instance, aliasInput);
      impactedInputs.push(...aliasIns);
    }
    // If is valid_until modification, update also revoked
    if (input.key === VALID_UNTIL) {
      const untilDate = R.head(input.value);
      const untilDateTime = utcDate(untilDate).toDate();

      const revokedInput = { key: REVOKED, value: [untilDateTime < utcDate().toDate()] };
      const revokedIn = innerUpdateAttribute(instance, revokedInput);
      if (revokedIn.length > 0) {
        updatedInputs.push({ ...revokedInput, previous: getPreviousInstanceValue(revokedInput.key, instance) });
        impactedInputs.push(...revokedIn);
      }
      if (instance.entity_type === ENTITY_TYPE_INDICATOR && untilDateTime <= utcDate().toDate()) {
        const detectionInput = { key: 'x_opencti_detection', value: [false] };
        const detectionIn = innerUpdateAttribute(instance, detectionInput);
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
      const inputAliases = [...input.value];
      if (operation === UPDATE_OPERATION_REPLACE) {
        inputAliases.push(instance.name);
      }
      const aliasesId = generateAliasesId(inputAliases, instance);
      const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId, operation };
      const aliasIns = innerUpdateAttribute(instance, aliasInput);
      if (aliasIns.length > 0) {
        impactedInputs.push(...aliasIns);
      }
    }
  }
  // If update is part of the key, update the standard_id
  const keys = R.map((t) => t.key, impactedInputs);
  if (impactStandardId && isFieldContributingToStandardId(instance, keys)) {
    const updatedInstance = mergeInstanceWithInputs(instance, impactedInputs);
    const standardId = generateStandardId(instanceType, updatedInstance);
    const standardInput = { key: ID_STANDARD, value: [standardId] };
    const ins = innerUpdateAttribute(instance, standardInput);
    if (ins.length > 0) {
      updatedInputs.push({ key: 'id', value: [standardId], previous: [instance.standard_id] });
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
export const updateAttribute = async (user, id, type, inputs, opts = {}) => {
  const { locks = [], impactStandardId = true } = opts;
  const updates = Array.isArray(inputs) ? inputs : [inputs];
  // Pre check
  const elementsByKey = R.groupBy((e) => e.key, updates);
  const multiOperationKeys = Object.values(elementsByKey).filter((n) => n.length > 1);
  if (multiOperationKeys.length > 1) {
    throw UnsupportedError('We cant update the same attribute multiple times in the same operation');
  }
  // Split attributes and meta
  // Supports inputs meta or stix meta
  const metaKeys = [...META_STIX_ATTRIBUTES, ...META_FIELD_ATTRIBUTES];
  const meta = updates.filter((e) => metaKeys.includes(e.key));
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  // Load the element to update
  const instance = await loadByIdWithMetaRels(user, id, { type });
  if (!instance) {
    throw FunctionalError('Cant find element to update', { id, type });
  }
  const instanceMergeWithInputs = mergeInstanceWithUpdateInputs(instance, inputs);
  const enforceReferences = conf.get('app:enforce_references') || [];
  const keys = R.map((t) => t.key, attributes);
  if (
    enforceReferences.includes(instance.entity_type)
    || (enforceReferences.includes('stix-core-relationship') && isStixCoreRelationship(instance.entity_type))
  ) {
    const isNoReferenceKey = noReferenceAttributes.includes(R.head(keys)) && keys.length === 1;
    if (!isNoReferenceKey && isEmptyField(opts.references)) {
      throw ValidationError('references', { message: 'You must provide at least one external reference to update' });
    }
  }
  let locksIds = getInstanceIds(instance);
  // 01. Check if updating alias lead to entity conflict
  if (isStixObjectAliased(instance.entity_type)) {
    // If user ask for aliases modification, we need to check if it not already belong to another entity.
    const isInputAliases = (input) => input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI;
    const aliasedInputs = R.filter((input) => isInputAliases(input), attributes);
    if (aliasedInputs.length > 0) {
      const aliases = R.uniq(R.flatten(R.map((a) => a.value, aliasedInputs)));
      const aliasesIds = generateAliasesId(aliases, instance);
      const existingEntities = await internalFindByIds(user, aliasesIds, { type: instance.entity_type });
      const differentEntities = R.filter((e) => e.internal_id !== instance.id, existingEntities);
      if (differentEntities.length > 0) {
        throw FunctionalError('This update will produce a duplicate', { id: instance.id, type });
      }
    }
  }
  // 02. Check if this update is not resulting to an entity merging
  let eventualNewStandardId = null;
  const standardIdImpacted = impactStandardId && isFieldContributingToStandardId(instance, keys);
  if (standardIdImpacted) {
    // In this case we need to reconstruct the data like if an update already appears
    // Based on that we will be able to generate the correct standard id
    locksIds = getInstanceIds(instanceMergeWithInputs); // Take lock ids on the new merged instance.
    const targetStandardId = generateStandardId(instance.entity_type, instanceMergeWithInputs);
    if (targetStandardId !== instance.standard_id) {
      locksIds.push(targetStandardId);
      eventualNewStandardId = targetStandardId;
    }
  }
  // --- take lock, ensure no one currently create or update this element
  let lock;
  const participantIds = R.uniq(locksIds.filter((e) => !locks.includes(e)));
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // region handle attributes
    // Only for StixCyberObservable
    const lookingEntities = [];
    let existingEntityPromise = Promise.resolve(undefined);
    let existingByHashedPromise = Promise.resolve([]);
    if (eventualNewStandardId) {
      existingEntityPromise = internalLoadById(user, eventualNewStandardId);
    }
    if (isStixCyberObservableHashedObservable(instance.entity_type)) {
      existingByHashedPromise = listEntitiesByHashes(user, instance.entity_type, instanceMergeWithInputs.hashes).then(
        (entities) => entities.filter((e) => e.id !== id)
      );
    }
    const [existingEntity, existingByHashed] = await Promise.all([existingEntityPromise, existingByHashedPromise]);
    if (existingEntity) {
      lookingEntities.push(existingEntity);
    }
    lookingEntities.push(...existingByHashed);
    const existingEntities = R.uniqBy((e) => e.internal_id, lookingEntities);
    // If already exist entities
    if (existingEntities.length > 0) {
      // If stix observable, we can merge. If not throw an error.
      if (isStixCyberObservable(type)) {
        // There is a potential merge, in this mode we doest not support multi update
        const noneStandardKeys = Object.keys(elementsByKey).filter(
          (k) => !isFieldContributingToStandardId(instance, [k])
        );
        const haveExtraKeys = noneStandardKeys.length > 0;
        if (haveExtraKeys) {
          throw UnsupportedError('This update can produce a merge, only one update action supported');
        }
        // Everything ok, let merge
        const target = existingEntities.shift();
        const sources = [instanceMergeWithInputs, ...existingEntities];
        hashMergeValidation([target, ...sources]);

        const merged = await mergeEntities(
          user,
          target.internal_id,
          sources.map((c) => c.internal_id),
          { locks: participantIds }
        );
        logApp.info(`[OPENCTI] Success merge of entity ${merged.id}`);
        // Return merged element after waiting for it.
        return { element: merged };
      }
      // noinspection ExceptionCaughtLocallyJS
      throw FunctionalError('This update will produce a duplicate', { id: instance.id, type });
    }
    // noinspection UnnecessaryLocalVariableJS
    const data = updateAttributeRaw(instance, attributes, opts);
    const { updatedInstance, impactedInputs, updatedInputs } = data;
    // Check the consistency of the observable.
    if (isStixCyberObservable(updatedInstance.entity_type)) {
      const observableSyntaxResult = checkObservableSyntax(updatedInstance.entity_type, updatedInstance);
      if (observableSyntaxResult !== true) {
        const reason = `Observable of type ${updatedInstance.entity_type} is not correctly formatted.`;
        throw FunctionalError(reason, { id, type });
      }
    }
    if (impactedInputs.length > 0) {
      const updateAsInstance = partialInstanceWithInputs(updatedInstance, impactedInputs);
      await elUpdateElement(updateAsInstance);
    }
    // endregion
    // region metas
    let mustBeRepublished = false;
    const streamOpts = { publishStreamEvent: false, locks: participantIds };
    for (let metaIndex = 0; metaIndex < meta.length; metaIndex += 1) {
      const { key: metaKey } = meta[metaIndex];
      const key = STIX_ATTRIBUTE_TO_META_FIELD[metaKey] || metaKey;
      // ref and _refs are expecting direct identifier in the value
      // We dont care about the operation here, the only thing we can do is replace
      if (isSingleStixEmbeddedRelationshipInput(key)) {
        const relType = FIELD_ATTRIBUTE_TO_EMBEDDED_RELATION[key];
        const currentValue = R.head(updatedInstance[key] || []);
        const { value: refIds } = meta[metaIndex];
        const targetCreated = R.head(refIds);
        // If asking for a real change
        if (currentValue?.standard_id !== targetCreated && currentValue?.id !== targetCreated) {
          // Delete the current relation
          if (currentValue?.standard_id) {
            const currentRels = await listAllRelations(user, relType, { fromId: instance.id });
            // eslint-disable-next-line no-use-before-define
            await deleteElements(user, currentRels, streamOpts);
          }
          // Create the new one
          if (isNotEmptyField(targetCreated)) {
            const inputRel = { fromId: id, toId: targetCreated, relationship_type: relType };
            // eslint-disable-next-line no-use-before-define
            await createRelationRaw(user, inputRel, streamOpts);
            const element = await internalLoadById(user, targetCreated);
            const previous = currentValue ? [currentValue] : currentValue;
            updatedInputs.push({ key, value: [element], previous });
            updatedInstance[key] = element;
          } else if (currentValue) {
            // Just replace by nothing
            updatedInputs.push({ key, value: null, previous: [currentValue] });
            updatedInstance[key] = null;
          }
        }
      } else {
        const relType = FIELD_ATTRIBUTE_TO_EMBEDDED_RELATION[key];
        const { value: refs, operation = UPDATE_OPERATION_REPLACE } = meta[metaIndex];
        if (operation === UPDATE_OPERATION_REPLACE) {
          // Delete all relations
          const currentRels = await listAllRelations(user, relType, { fromId: id });
          const currentRelsToIds = currentRels.map((n) => n.toId);
          const newTargets = await internalFindByIds(user, refs);
          const newTargetsIds = newTargets.map((n) => n.id);
          if (R.symmetricDifference(newTargetsIds, currentRelsToIds).length > 0) {
            if (currentRels.length > 0) {
              // eslint-disable-next-line no-use-before-define
              await deleteElements(user, currentRels, streamOpts);
            }
            // 02. Create the new relations
            if (newTargets.length > 0) {
              for (let delIndex = 0; delIndex < refs.length; delIndex += 1) {
                const ref = refs[delIndex];
                const inputRel = { fromId: id, toId: ref, relationship_type: relType };
                // eslint-disable-next-line no-use-before-define
                await createRelationRaw(user, inputRel, streamOpts);
              }
            }
            updatedInputs.push({ key, value: newTargets, previous: updatedInstance[key] });
            updatedInstance[key] = newTargets;
            mustBeRepublished = relType === RELATION_OBJECT_MARKING;
          }
        }
        if (operation === UPDATE_OPERATION_ADD) {
          const currentIds = (updatedInstance[key] || []).map((o) => [o.id, o.standard_id]).flat();
          const refsToCreate = refs.filter((r) => !currentIds.includes(r));
          if (refsToCreate.length > 0) {
            const newTargets = await internalFindByIds(user, refsToCreate);
            for (let createIndex = 0; createIndex < refsToCreate.length; createIndex += 1) {
              const refToCreate = refsToCreate[createIndex];
              const inputRel = { fromId: id, toId: refToCreate, relationship_type: relType };
              // eslint-disable-next-line no-use-before-define
              await createRelationRaw(user, inputRel, streamOpts);
            }
            updatedInputs.push({ key, value: newTargets, operation });
            mustBeRepublished = relType === RELATION_OBJECT_MARKING;
            updatedInstance[key] = [...(updatedInstance[key] || []), ...newTargets];
          }
        }
        if (operation === UPDATE_OPERATION_REMOVE) {
          const targets = await internalFindByIds(user, refs);
          const targetIds = targets.map((t) => t.internal_id);
          const currentRels = await listAllRelations(user, relType, { fromId: id });
          const relsToDelete = currentRels.filter((c) => targetIds.includes(c.internal_id));
          if (relsToDelete.length > 0) {
            // eslint-disable-next-line no-use-before-define
            await deleteElements(user, relsToDelete, streamOpts);
            updatedInputs.push({ key, value: relsToDelete, operation });
            mustBeRepublished = relType === RELATION_OBJECT_MARKING;
            updatedInstance[key] = (updatedInstance[key] || []).filter((c) => !targetIds.includes(c.internal_id));
          }
        }
      }
    }
    // endregion
    // Only push event in stream if modifications really happens
    if (updatedInputs.length > 0) {
      const event = await storeUpdateEvent(user, updatedInstance, updatedInputs, {
        mustBeRepublished,
        commitMessage: opts.commitMessage,
        references: opts.references,
      });
      return { element: updatedInstance, event };
    }
    // Return updated element after waiting for it.
    return { element: updatedInstance };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
export const patchAttributeRaw = (instance, patch, opts = {}) => {
  const inputs = transformPatchToInput(patch, opts.operations);
  return updateAttributeRaw(instance, inputs);
};
export const patchAttribute = async (user, id, type, patch, opts = {}) => {
  const inputs = transformPatchToInput(patch, opts.operations);
  return updateAttribute(user, id, type, inputs, opts);
};
// endregion

// region rules
const getAllRulesField = (instance, field) => {
  return Object.keys(instance)
    .filter((key) => key.startsWith(RULE_PREFIX))
    .map((key) => instance[key])
    .flat()
    .map((rule) => rule.data?.[field])
    .flat()
    .filter((val) => isNotEmptyField(val));
};
const convertRulesTimeValues = (timeValues) => timeValues.map((d) => moment(d));
const createRuleDataPatch = (instance) => {
  // 01 - Compute the attributes
  const weight = Object.keys(instance)
    .filter((key) => key.startsWith(RULE_PREFIX))
    .map((key) => instance[key])
    .flat().length;
  const patch = {};
  // weight is only useful on relationships
  if (isBasicRelationship(instance.entity_type)) {
    patch.i_inference_weight = weight;
  }
  const attributes = RULES_ATTRIBUTES_BEHAVIOR.supportedAttributes();
  for (let index = 0; index < attributes.length; index += 1) {
    const attribute = attributes[index];
    const values = getAllRulesField(instance, attribute);
    if (values.length > 0) {
      const operation = RULES_ATTRIBUTES_BEHAVIOR.getOperation(attribute);
      if (operation === RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.AVG) {
        if (!isNumericAttribute(attribute)) {
          throw UnsupportedError('Can apply avg on non numeric attribute');
        }
        patch[attribute] = computeAverage(values);
      }
      if (operation === RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.SUM) {
        if (!isNumericAttribute(attribute)) {
          throw UnsupportedError('Can apply sum on non numeric attribute');
        }
        patch[attribute] = R.sum(values);
      }
      if (operation === RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.MIN) {
        if (isNumericAttribute(attribute)) {
          patch[attribute] = R.min(values);
        } else if (isDateAttribute(attribute)) {
          const timeValues = convertRulesTimeValues(values);
          patch[attribute] = moment.min(timeValues).utc().toISOString();
        } else {
          throw UnsupportedError('Can apply min on non numeric or date attribute');
        }
      }
      if (operation === RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.MAX) {
        if (isNumericAttribute(attribute)) {
          patch[attribute] = R.max(values);
        } else if (isDateAttribute(attribute)) {
          const timeValues = convertRulesTimeValues(values);
          patch[attribute] = moment.max(timeValues).utc().toISOString();
        } else {
          throw UnsupportedError('Can apply max on non numeric or date attribute');
        }
      }
      if (operation === RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.AGG) {
        patch[attribute] = R.uniq(values);
      }
    }
  }
  return patch;
};
const upsertEntityRule = async (instance, input, opts = {}) => {
  return patchAttribute(RULE_MANAGER_USER, instance.id, instance.entity_type, input, opts);
};
const upsertRelationRule = async (instance, input, opts = {}) => {
  const { fromRule, ruleOverride = false } = opts;
  // 01 - Update the rule
  const updatedRule = input[fromRule];
  if (!ruleOverride) {
    const keepRuleHashes = input[fromRule].map((i) => i.hash);
    const instanceRuleToKeep = (instance[fromRule] ?? []).filter((i) => !keepRuleHashes.includes(i.hash));
    updatedRule.push(...instanceRuleToKeep);
  }
  const rulePatch = { [fromRule]: updatedRule };
  const ruleInstance = R.mergeRight(instance, rulePatch);
  const innerPatch = createRuleDataPatch(ruleInstance);
  const patch = { ...rulePatch, ...innerPatch };
  return patchAttribute(RULE_MANAGER_USER, instance.id, instance.entity_type, patch, opts);
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
  relationAttributes.relationship_type = relationshipType;
  relationAttributes.created_at = today;
  relationAttributes.updated_at = today;
  // stix-relationship
  if (isStixRelationShipExceptMeta(relationshipType)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    relationAttributes.x_opencti_stix_ids = stixIds;
    relationAttributes.spec_version = STIX_SPEC_VERSION;
    relationAttributes.revoked = R.isNil(input.revoked) ? false : input.revoked;
    relationAttributes.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
    relationAttributes.lang = R.isNil(input.lang) ? 'en' : input.lang;
    relationAttributes.created = R.isNil(input.created) ? today : input.created;
    relationAttributes.modified = R.isNil(input.modified) ? today : input.modified;
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    relationAttributes.description = input.description ? input.description : '';
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with stop_time less than start_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-observable-relationship
  if (isStixCyberObservableRelationship(relationshipType)) {
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with stop_time less than start_time', {
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
      throw DatabaseError('You cant create a relation with a first_seen greater than the last_seen', {
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
        if (isDictionaryAttribute(fieldKey)) {
          Object.entries(inputData).forEach(([k, v]) => {
            patch[`${fieldKey}.${k}`] = v;
          });
        } else {
          patch[fieldKey] = Array.isArray(inputData) ? inputData : [inputData];
        }
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
const handleRelationTimeUpdate = (input, instance, startField, stopField) => {
  const patch = {};
  // If not coming from a rule, compute extended time.
  if (input[startField]) {
    const extendedStart = computeExtendedDateValues(input[startField], instance[startField], ALIGN_OLDEST);
    if (extendedStart) {
      patch[startField] = extendedStart;
    }
  }
  if (input[stopField]) {
    const extendedStop = computeExtendedDateValues(input[stopField], instance[stopField], ALIGN_NEWEST);
    if (extendedStop) {
      patch[stopField] = extendedStop;
    }
  }
  return patch;
};
const buildRelationTimeFilter = (input) => {
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
  } else if (isStixCyberObservableRelationship(relationshipType)) {
    if (!R.isNil(input.start_time)) {
      args.startTimeStart = prepareDate(moment(input.start_time).subtract(1, 'days').utc());
      args.startTimeStop = prepareDate(moment(input.start_time).add(1, 'days').utc());
    }
    if (!R.isNil(input.stop_time)) {
      args.stopTimeStart = prepareDate(moment(input.stop_time).subtract(1, 'days').utc());
      args.stopTimeStop = prepareDate(moment(input.stop_time).add(1, 'days').utc());
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

const upsertElementRaw = (instance, type, input) => {
  // Upsert relation
  const forceUpdate = input.update === true;
  const patchInputs = []; // Direct modified inputs (add)
  // const updatedReplaceInputs = []; // Direct modified inputs (replace)
  const impactedInputs = []; // Inputs impacted by updated inputs + updated inputs
  const rawRelations = [];
  // Handle attributes updates
  if (isNotEmptyField(input.stix_id) || isNotEmptyField(input.x_opencti_stix_ids)) {
    const ids = [...(input.x_opencti_stix_ids || [])];
    if (isNotEmptyField(input.stix_id) && input.stix_id !== instance.standard_id) {
      ids.push(input.stix_id);
    }
    if (ids.length > 0) {
      const patch = { x_opencti_stix_ids: ids };
      const operations = { x_opencti_stix_ids: UPDATE_OPERATION_ADD };
      const patched = patchAttributeRaw(instance, patch, { operations });
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  // Upsert the aliases
  if (isStixObjectAliased(type)) {
    const { name } = input;
    const key = resolveAliasesField(type);
    const aliases = [...(input[ATTRIBUTE_ALIASES] || []), ...(input[ATTRIBUTE_ALIASES_OPENCTI] || [])];
    if (normalizeName(instance.name) !== normalizeName(name)) aliases.push(instance.name);
    const patch = { [key]: aliases };
    const operations = { [key]: UPDATE_OPERATION_ADD };
    const patched = patchAttributeRaw(instance, patch, { operations });
    impactedInputs.push(...patched.impactedInputs);
    patchInputs.push(...patched.updatedInputs);
  }
  // Upsert relationships
  if (isStixSightingRelationship(type)) {
    const timePatch = handleRelationTimeUpdate(input, instance, 'first_seen', 'last_seen');
    // Upsert the count only if a time patch is applied.
    if (isNotEmptyField(timePatch)) {
      const basePatch = { attribute_count: instance.attribute_count + input.attribute_count };
      const patch = { ...basePatch, ...timePatch };
      const patched = patchAttributeRaw(instance, patch);
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  // Upsert observed data
  if (type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    const timePatch = handleRelationTimeUpdate(input, instance, 'first_observed', 'last_observed');
    // Upsert the count only if a time patch is applied.
    if (isNotEmptyField(timePatch)) {
      const basePatch = { number_observed: instance.number_observed + input.number_observed };
      const patch = { ...basePatch, ...timePatch };
      const patched = patchAttributeRaw(instance, patch);
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  if (isStixCoreRelationship(type)) {
    const basePatch = {};
    if (input.confidence && forceUpdate) {
      basePatch.confidence = input.confidence;
    }
    if (input.description && forceUpdate) {
      basePatch.description = input.description;
    }
    const timePatch = handleRelationTimeUpdate(input, instance, 'start_time', 'stop_time');
    const patch = { ...basePatch, ...timePatch };
    const patched = patchAttributeRaw(instance, patch);
    impactedInputs.push(...patched.impactedInputs);
    patchInputs.push(...patched.updatedInputs);
  }
  // Upsert entities
  if (isInternalObject(type) && forceUpdate) {
    const fields = internalObjectsFieldsToBeUpdated[type];
    const { upsertImpacted, upsertUpdated } = upsertIdentifiedFields(instance, input, fields);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  if (isStixDomainObject(type) && forceUpdate) {
    const fields = stixDomainObjectFieldsToBeUpdated[type];
    const { upsertImpacted, upsertUpdated } = upsertIdentifiedFields(instance, input, fields);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  // Upsert SCOs
  if (isStixCyberObservable(type) && forceUpdate) {
    const fields = stixCyberObservableFieldsToBeUpdated[type];
    const { upsertImpacted, upsertUpdated } = upsertIdentifiedFields(instance, input, fields);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  // region upsert refs
  const buildInstanceRelTo = (to, relType) => buildInnerRelation(instance, to, relType);
  if (isStixCyberObservable(type)) {
    const inputFields = stixCyberObservableTypeFields()[type] || [];
    for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
      const inputField = inputFields[fieldIndex];
      if (input[inputField] && MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS.includes(inputField)) {
        const stixField = STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[inputField];
        const existingInstances = instance[stixField] || [];
        const instancesToCreate = R.filter((m) => !existingInstances.includes(m.internal_id), input[inputField]);
        const relType = STIX_ATTRIBUTE_TO_CYBER_RELATIONS[stixField];
        if (instancesToCreate.length > 0) {
          const newRelations = instancesToCreate.map((to) => {
            const authorizedRelationTypes = stixCyberObservableRelationshipsMapping[`${type}_${to.entity_type}`];
            if (!authorizedRelationTypes.includes(relType)) {
              throw UnsupportedError(`${relType} is not allowed for this`);
            }
            return R.head(buildInstanceRelTo(to, relType)).relation;
          });
          rawRelations.push(...newRelations);
          patchInputs.push({ key: inputField, value: instancesToCreate, operation: UPDATE_OPERATION_ADD });
        }
      }
    }
  }
  if (isStixCoreObject(type)) {
    const inputFields = STIX_META_RELATIONSHIPS_INPUTS;
    for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
      const inputField = inputFields[fieldIndex];
      if (input[inputField] && MULTIPLE_META_RELATIONSHIPS_INPUTS.includes(inputField)) {
        const stixField = META_FIELD_TO_STIX_ATTRIBUTE[inputField];
        const existingInstances = instance[stixField] || [];
        const instancesToCreate = R.filter((m) => !existingInstances.includes(m.internal_id), input[inputField]);
        const relType = STIX_ATTRIBUTE_TO_META_RELATIONS[stixField];
        if (instancesToCreate.length > 0) {
          const newRelations = instancesToCreate.map((to) => {
            return R.head(buildInstanceRelTo(to, relType)).relation;
          });
          rawRelations.push(...newRelations);
          patchInputs.push({ key: inputField, value: instancesToCreate, operation: UPDATE_OPERATION_ADD });
        }
      }
    }
  }
  // endregion
  // Build result
  if (impactedInputs.length > 0) {
    const updatedInstance = mergeInstanceWithInputs(instance, impactedInputs);
    const indexInput = partialInstanceWithInputs(instance, impactedInputs);
    return { type: TRX_UPDATE, element: updatedInstance, relations: rawRelations, patchInputs, indexInput };
  }
  // Return all elements requirement for stream and indexation
  return { type: TRX_UPDATE, element: instance, relations: rawRelations, patchInputs };
};
const checkRelationConsistency = (relationshipType, from, to) => {
  // 01 - check type consistency
  const fromType = from.entity_type;
  const toType = to.entity_type;
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
const isRelationConsistent = (relationshipType, from, to) => {
  try {
    checkRelationConsistency(relationshipType, from, to);
    return true;
  } catch {
    return false;
  }
};
const buildRelationData = async (user, input, opts = {}) => {
  const { fromRule } = opts;
  const { from, to, relationship_type: relationshipType } = input;
  // 01. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // 02. Prepare the relation to be created
  const today = now();
  const data = {};
  // Default attributes
  // basic-relationship
  const inferred = isNotEmptyField(fromRule);
  data._index = inferIndexFromConceptType(relationshipType, inferred);
  if (inferred) {
    // Simply add the rule
    // start/stop confidence was computed by the rule directly
    data[fromRule] = input[fromRule];
  }
  data.internal_id = internalId;
  data.standard_id = standardId;
  data.entity_type = relationshipType;
  data.created_at = today;
  data.updated_at = today;
  // stix-relationship
  if (isStixRelationShipExceptMeta(relationshipType)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    data.x_opencti_stix_ids = stixIds;
    data.spec_version = STIX_SPEC_VERSION;
    data.revoked = R.isNil(input.revoked) ? false : input.revoked;
    data.confidence = R.isNil(input.confidence) ? computeConfidenceLevel(input) : input.confidence;
    data.lang = R.isNil(input.lang) ? 'en' : input.lang;
    data.created = R.isNil(input.created) ? today : input.created;
    data.modified = R.isNil(input.modified) ? today : input.modified;
    // Get statuses
    let type = null;
    if (isStixCoreRelationship(relationshipType)) {
      type = 'stix-core-relationship';
    } else if (isStixSightingRelationship(relationshipType)) {
      type = 'stix-sighting-relationship';
    }
    if (type) {
      const statuses = await listEntities(user, [ENTITY_TYPE_STATUS], {
        first: 1,
        orderBy: 'order',
        orderMode: 'asc',
        filters: [{ key: 'type', values: [type] }],
        connectionFormat: false,
      });
      if (statuses.length > 0) {
        data.x_opencti_workflow_id = R.head(statuses).id;
      }
    }
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    data.relationship_type = relationshipType;
    data.description = input.description ? input.description : '';
    data.start_time = isEmptyField(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = isEmptyField(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
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
      throw DatabaseError('You cant create a relation with last_seen less than first_seen', {
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
    relToCreate.push(...buildInnerRelation(data, input.externalReferences, RELATION_EXTERNAL_REFERENCE));
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
export const createRelationRaw = async (user, input, opts = {}) => {
  let lock;
  const { publishStreamEvent = true, fromRule, locks = [] } = opts;
  const { fromId, toId, relationship_type: relationshipType } = input;
  if (isStixCoreRelationship(relationshipType)) {
    const enforceReferences = conf.get('app:enforce_references');
    if (enforceReferences && enforceReferences.includes('stix-core-relationship')) {
      if (isEmptyField(input.externalReferences)) {
        throw ValidationError('externalReferences', {
          message: 'You must provide at least one external reference to create a relationship',
        });
      }
    }
  }
  // Pre check before inputs resolution
  if (fromId === toId) {
    /* istanbul ignore next */
    const errorData = { from: input.fromId, relationshipType };
    throw UnsupportedError('Relation cant be created with the same source and target', errorData);
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
    throw UnsupportedError('Relation cant be created with the same source and target', errorData);
  }
  // Check consistency
  checkRelationConsistency(relationshipType, from, to);
  // Build lock ids
  const inputIds = getInputIds(relationshipType, resolvedInput);
  if (isImpactedTypeAndSide(relationshipType, ROLE_FROM)) inputIds.push(from.internal_id);
  if (isImpactedTypeAndSide(relationshipType, ROLE_TO)) inputIds.push(to.internal_id);
  const participantIds = inputIds.filter((e) => !locks.includes(e));
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // region check existing relationship
    const existingRelationships = [];
    const listingArgs = { fromId: from.internal_id, toId: to.internal_id, connectionFormat: false };
    if (fromRule) {
      // In case inferred rule, try to find the relation with basic filters
      // Only in inferred indices.
      const fromRuleArgs = { ...listingArgs, indices: [READ_INDEX_INFERRED_RELATIONSHIPS] };
      const inferredRelationships = await listRelations(SYSTEM_USER, relationshipType, fromRuleArgs);
      existingRelationships.push(...inferredRelationships);
    } else {
      // In case of direct relation, try to find the relation with time filters
      // Only in standard indices.
      const timeFilters = buildRelationTimeFilter(resolvedInput);
      const manualArgs = { ...listingArgs, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, ...timeFilters };
      const manualRelationships = await listRelations(SYSTEM_USER, relationshipType, manualArgs);
      existingRelationships.push(...manualRelationships);
    }
    let existingRelationship = null;
    if (existingRelationships.length > 0) {
      // We need to filter what we found with the user rights
      const filteredRelations = filterElementsAccordingToUser(user, existingRelationships);
      // If nothing accessible for this user, throw ForbiddenAccess
      if (filteredRelations.length === 0) {
        throw UnsupportedError('Restricted relation already exists');
      }
      // Meta single relation check
      if (isSingleStixEmbeddedRelationship(relationshipType)) {
        // If relation already exist, we fail
        throw UnsupportedError('Relation cant be created (single cardinality)', {
          relationshipType,
          fromId: from.internal_id,
        });
      }
      // TODO Handling merging relation when updating to prevent multiple relations finding
      existingRelationship = R.head(filteredRelations);
    }
    // endregion
    let dataRel;
    if (existingRelationship) {
      // If upsert come from a rule, do a specific upsert.
      if (fromRule) {
        return upsertRelationRule(existingRelationship, input, { ...opts, locks: participantIds });
      }
      // If not upsert the element
      dataRel = upsertElementRaw(existingRelationship, relationshipType, resolvedInput);
    } else {
      // Check cyclic reference consistency for embedded relationships before creation
      if (isStixEmbeddedRelationship(relationshipType)) {
        const toRefs = instanceMetaRefsExtractor(to);
        // We are using rel_ to resolve STIX embedded refs, but in some cases it's not a cyclic relationships
        // Checking the direction of the relation to allow relationships
        if (toRefs.includes(from.internal_id) && isRelationConsistent(relationshipType, to, from)) {
          throw FunctionalError(`You cant create a cyclic relation between ${from.standard_id} and ${to.standard_id}`);
        }
      }
      // Just build a standard relationship
      dataRel = await buildRelationData(user, resolvedInput, opts);
    }
    // Index the created element
    await indexCreatedElement(dataRel);
    // Push the input in the stream
    let event;
    if (publishStreamEvent) {
      const relWithConnections = { ...dataRel.element, from, to };
      if (dataRel.type === TRX_CREATION) {
        const loaders = { stixLoadById: loadByIdWithMetaRels, connectionLoaders };
        event = await storeCreateEvent(user, relWithConnections, resolvedInput, loaders);
      } else if (dataRel.patchInputs.length > 0) {
        event = await storeUpdateEvent(user, relWithConnections, dataRel.patchInputs);
      }
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
export const createInferredRelation = async (input, ruleContent) => {
  const opts = { fromRule: ruleContent.field };
  // eslint-disable-next-line camelcase
  const { fromId, toId, relationship_type } = input;
  logApp.info('Create inferred relation', { fromId, toId, relationshipType: relationship_type });
  // In some cases, we can try to create with the same from and to, ignore
  if (fromId === toId) {
    return undefined;
  }
  // Build the instance
  const instance = { fromId, toId, relationship_type, [ruleContent.field]: [ruleContent.content] };
  const patch = createRuleDataPatch(instance);
  const inputRelation = { ...instance, ...patch };
  const data = await createRelationRaw(RULE_MANAGER_USER, inputRelation, opts);
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
const buildEntityData = async (user, input, type, opts = {}) => {
  const { fromRule } = opts;
  const internalId = input.internal_id || generateInternalId();
  const standardId = input.standard_id || generateStandardId(type, input);
  // Complete with identifiers
  const today = now();
  const inferred = isNotEmptyField(fromRule);
  // Default attributes
  let data = R.pipe(
    R.assoc('_index', inferIndexFromConceptType(type, inferred)),
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
  if (inferred) {
    // Simply add the rule
    // start/stop confidence was computed by the rule directly
    data[fromRule] = input[fromRule];
  }
  // Some internal objects have dates
  if (isDatedInternalObject(type)) {
    data = R.pipe(R.assoc('created_at', today), R.assoc('updated_at', today))(data);
  }
  // Stix-Object
  if (isStixObject(type)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    data = R.pipe(
      R.assoc(IDS_STIX, stixIds),
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
    // Get statuses
    const statuses = await listEntities(user, [ENTITY_TYPE_STATUS], {
      first: 1,
      orderBy: 'order',
      orderMode: 'asc',
      filters: [{ key: 'type', values: [type] }],
      connectionFormat: false,
    });
    if (statuses.length > 0) {
      data = R.assoc('x_opencti_workflow_id', R.head(statuses).id, data);
    }
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
    const inputFields = STIX_META_RELATIONSHIPS_INPUTS;
    for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
      const inputField = inputFields[fieldIndex];
      if (input[inputField]) {
        const relType = FIELD_TO_META_RELATION[inputField];
        relToCreate.push(...buildInnerRelation(data, input[inputField], relType));
      }
    }
  }
  if (isStixCyberObservable(type)) {
    const inputFields = stixCyberObservableTypeFields()[type] || [];
    for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
      const inputField = inputFields[fieldIndex];
      if (input[inputField]) {
        const instancesToCreate = Array.isArray(input[inputField]) ? input[inputField] : [input[inputField]];
        const stixField = STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[inputField];
        const relType = STIX_ATTRIBUTE_TO_CYBER_RELATIONS[stixField];
        const newRelations = instancesToCreate
          .map((to) => {
            const authorizedRelationTypes = stixCyberObservableRelationshipsMapping[`${type}_${to.entity_type}`];
            if (!authorizedRelationTypes.includes(relType)) {
              throw UnsupportedError(`${relType} is not allowed for this`);
            }
            return buildInnerRelation(data, input[inputField], relType);
          })
          .flat();
        relToCreate.push(...newRelations);
      }
    }
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
export const createEntityRaw = async (user, input, type, opts = {}) => {
  const enforceReferences = conf.get('app:enforce_references');
  const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
  const isAllowedToByPass = userCapabilities.includes(BYPASS) || userCapabilities.includes(BYPASS_REFERENCE);
  if (!isAllowedToByPass && enforceReferences && enforceReferences.includes(type)) {
    if (isEmptyField(input.externalReferences)) {
      throw ValidationError('externalReferences', {
        message: 'You must provide at least one external reference for this type of entity',
      });
    }
  }
  const { fromRule } = opts;
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(user, input, type);
  // Generate all the possibles ids
  // For marking def, we need to force the standard_id
  const participantIds = getInputIds(type, resolvedInput);
  // Create the element
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // Generate the internal id if needed
    const standardId = resolvedInput.standard_id || generateStandardId(type, resolvedInput);
    // Check if the entity exists, must be done with SYSTEM USER to really find it.
    const existingEntities = [];
    const existingByIdsPromise = internalFindByIds(SYSTEM_USER, participantIds, { type });
    // Hash are per definition keys.
    // When creating a hash, we can check all hashes to update or merge the result
    // Generating multiple standard ids could be a solution but to complex to implements
    // For now, we will look for any observables that have any hashes of this input.
    let existingByHashedPromise = Promise.resolve([]);
    if (isStixCyberObservableHashedObservable(type)) {
      existingByHashedPromise = listEntitiesByHashes(user, type, input.hashes);
      resolvedInput.update = true;
    }
    // Resolve the existing entity
    const [existingByIds, existingByHashed] = await Promise.all([existingByIdsPromise, existingByHashedPromise]);
    existingEntities.push(...R.uniqBy((e) => e.internal_id, [...existingByIds, ...existingByHashed]));
    // If existing entities have been found and type is a STIX Core Object
    let dataEntity;
    if (existingEntities.length > 0) {
      // We need to filter what we found with the user rights
      const filteredEntities = filterElementsAccordingToUser(user, existingEntities);
      const entityIds = R.map((i) => i.standard_id, filteredEntities);
      // If nothing accessible for this user, throw ForbiddenAccess
      if (filteredEntities.length === 0) {
        throw UnsupportedError('Restricted entity already exists');
      }
      // If inferred entity
      if (fromRule) {
        // Entity reference must be uniq to be upserted
        if (filteredEntities.length > 1) {
          throw UnsupportedError('Cant upsert inferred entity. Too many entities resolved', { input, entityIds });
        }
        // If upsert come from a rule, do a specific upsert.
        return upsertEntityRule(R.head(filteredEntities), resolvedInput, { ...opts, locks: participantIds });
      }
      if (filteredEntities.length === 1) {
        dataEntity = upsertElementRaw(R.head(filteredEntities), type, resolvedInput);
      } else {
        // If creation is not by a reference
        // We can in best effort try to merge a common stix_id
        const existingByStandard = R.find((e) => e.standard_id === standardId, filteredEntities);
        if (resolvedInput.update === true) {
          // The new one is new reference, merge all found entities
          // Target entity is existingByStandard by default or any other
          const target = R.find((e) => e.standard_id === standardId, filteredEntities) || R.head(filteredEntities);
          const sources = R.filter((e) => e.internal_id !== target.internal_id, filteredEntities);
          hashMergeValidation([target, ...sources]);
          await mergeEntities(user, target.internal_id, sources.map((s) => s.internal_id), { locks: participantIds });
          dataEntity = upsertElementRaw(target, type, resolvedInput);
        } else if (existingByStandard) {
          // Sometimes multiple entities can match
          // Looking for aliasA, aliasB, find in different entities for example
          // In this case, we try to find if one match the standard id
          // If a STIX ID has been passed in the creation
          if (resolvedInput.stix_id) {
            // Find the entity corresponding to this STIX ID

            const stixIdFinder = (e) => e.standard_id === resolvedInput.stix_id || e.x_opencti_stix_ids.includes(resolvedInput.stix_id);
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
          const filteredAliases = R.filter((i) => !normedAliases.includes(normalizeName(i)), resolvedInput[key] || []);
          const inputAliases = { ...resolvedInput, [key]: filteredAliases };
          dataEntity = upsertElementRaw(existingByStandard, type, inputAliases);
        } else {
          // If not we dont know what to do, just throw an exception.
          throw UnsupportedError('Cant upsert entity. Too many entities resolved', { input, entityIds });
        }
      }
    } else {
      // Create the object
      dataEntity = await buildEntityData(user, resolvedInput, type, opts);
    }
    // Index the created element
    await indexCreatedElement(dataEntity);
    // Push the input in the stream
    let event;
    if (dataEntity.type === TRX_CREATION) {
      const loaders = { stixLoadById: loadByIdWithMetaRels, connectionLoaders };
      event = await storeCreateEvent(user, dataEntity.element, resolvedInput, loaders);
    } else if (dataEntity.patchInputs.length > 0) {
      event = await storeUpdateEvent(user, dataEntity.element, dataEntity.patchInputs);
    }
    // Return created element after waiting for it.
    const element = R.assoc('i_upserted', dataEntity.type !== TRX_CREATION, dataEntity.element);
    return { element, event };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const createEntity = async (user, input, type) => {
  // volumes of objects relationships must be controlled
  if (input.objects && input.objects.length > MAX_BATCH_SIZE) {
    const objectSequences = R.splitEvery(MAX_BATCH_SIZE, input.objects);
    const firstSequence = objectSequences.shift();
    const subObjectsEntity = R.assoc(INPUT_OBJECTS, firstSequence, input);
    const created = await createEntityRaw(user, subObjectsEntity, type);
    // For each subsequences of objects
    // We need to produce a batch upsert of object that will be upserted.
    for (let index = 0; index < objectSequences.length; index += 1) {
      const objectSequence = objectSequences[index];
      const upsertInput = R.assoc(INPUT_OBJECTS, objectSequence, input);
      await createEntityRaw(user, upsertInput, type);
    }
    return created.element;
  }
  const data = await createEntityRaw(user, input, type);
  if (!data.element.i_upserted) {
    await askEnrich(user, data.element.id, type);
  }
  return data.element;
};
export const createInferredEntity = async (input, ruleContent, type) => {
  const opts = { fromRule: ruleContent.field, impactStandardId: false };
  logApp.info('Create inferred entity', { type });
  // Inferred entity have a specific standardId generated from dependencies data.
  const standardId = idGenFromData(type, ruleContent.content.dependencies.sort());
  const instance = { standard_id: standardId, ...input, [ruleContent.field]: [ruleContent.content] };
  const patch = createRuleDataPatch(instance);
  const inputEntity = { ...instance, ...patch };
  return createEntityRaw(RULE_MANAGER_USER, inputEntity, type, opts);
};
// endregion

// region mutation deletion
export const deleteElement = async (user, element, opts = {}) => {
  let lock;
  const { publishStreamEvent = true } = opts;
  // Check inference operation
  checkIfInferenceOperationIsValid(user, element);
  // Apply deletion
  const participantIds = [element.internal_id];
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // Start by deleting external files
    const importDeletePromise = deleteAllFiles(user, `import/${element.entity_type}/${element.internal_id}/`);
    const exportDeletePromise = deleteAllFiles(user, `export/${element.entity_type}/${element.internal_id}/`);
    await Promise.all([importDeletePromise, exportDeletePromise]);
    // Delete all linked elements
    const dependencyDeletions = await elDeleteElements(user, [element], {
      stixLoadById: loadByIdWithMetaRels,
    });
    // Publish event in the stream
    if (publishStreamEvent) {
      const loaders = { stixLoadById: loadByIdWithMetaRels, connectionLoaders };
      await storeDeleteEvent(user, element, dependencyDeletions, loaders);
    }
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
  return element.internal_id;
};
const deleteElements = async (user, elements, opts = {}) => {
  const deletedIds = [];
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const deletedId = await deleteElement(user, element, opts);
    deletedIds.push(deletedId);
  }
  return deletedIds;
};
export const deleteElementById = async (user, elementId, type, opts = {}) => {
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError('You need to specify a type when deleting an entity');
  }
  // Check consistency
  const element = await loadByIdWithMetaRels(user, elementId, { type });
  if (!element) {
    throw FunctionalError('Cant find element to delete', { elementId });
  }
  return deleteElement(user, element, opts);
};
export const deleteInferredRuleElement = async (rule, instance, deletedDependencies) => {
  // Check if deletion is really targeting an inference
  const isInferred = isInferredIndex(instance._index);
  if (!isInferred) {
    throw UnsupportedError('Instance is not inferred, cant be deleted');
  }
  // Delete inference
  const fromRule = RULE_PREFIX + rule;
  const rules = Object.keys(instance).filter((k) => k.startsWith(RULE_PREFIX));
  const completeRuleName = RULE_PREFIX + rule;
  if (!rules.includes(completeRuleName)) {
    throw UnsupportedError('Cant ask a deletion on element not inferred by this rule', { rule });
  }
  const monoRule = rules.length === 1;
  // Cleanup all explanation that match the dependency id
  const derivedEvents = [];
  const elementsRule = instance[completeRuleName];
  const rebuildRuleContent = [];
  for (let index = 0; index < elementsRule.length; index += 1) {
    const ruleContent = elementsRule[index];
    const { dependencies } = ruleContent;
    // Keep the element only if not include any deleted dependencies
    if (deletedDependencies.length > 0 && !deletedDependencies.some((d) => dependencies.includes(d))) {
      rebuildRuleContent.push(ruleContent);
    }
  }
  try {
    // Current rule doesnt have any more explanation
    if (rebuildRuleContent.length === 0) {
      // If current inference is only base on one rule, we can safely delete it.
      if (monoRule) {
        await deleteElementById(RULE_MANAGER_USER, instance.id, instance.entity_type);
        const loaders = { stixLoadById: loadByIdWithMetaRels, connectionLoaders };
        const opts = { withoutMessage: true };
        const event = await buildDeleteEvent(RULE_MANAGER_USER, instance, [], loaders, opts);
        derivedEvents.push(event);
      } else {
        // If not we need to clean the rule and keep the element for other rules.
        const input = { [completeRuleName]: null };
        const { event } = await upsertRelationRule(instance, input, { fromRule, ruleOverride: true });
        if (event) {
          derivedEvents.push(event);
        }
      }
    } else {
      // Rule still have other explanation, update the rule
      const input = { [completeRuleName]: rebuildRuleContent };
      const { event } = await upsertRelationRule(instance, input, { fromRule, ruleOverride: true });
      if (event) {
        derivedEvents.push(event);
      }
    }
  } catch (e) {
    logApp.error('Error deleting inference', { error: e.message });
  }
  return derivedEvents;
};
export const deleteRelationsByFromAndTo = async (user, fromId, toId, relationshipType, scopeType, opts = {}) => {
  /* istanbul ignore if */
  if (R.isNil(scopeType) || R.isNil(fromId) || R.isNil(toId)) {
    throw FunctionalError('You need to specify a scope type when deleting a relation with from and to');
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
