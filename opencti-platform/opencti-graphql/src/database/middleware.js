import moment from 'moment';
import * as R from 'ramda';
import DataLoader from 'dataloader';
import { Promise } from 'bluebird';
import { compareUnsorted } from 'js-deep-equals';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { JSONPath } from 'jsonpath-plus';
import * as jsonpatch from 'fast-json-patch';

import {
  ALREADY_DELETED_ERROR,
  AlreadyDeletedError,
  DatabaseError,
  ForbiddenAccess,
  FunctionalError,
  LockTimeoutError,
  MissingReferenceError,
  TYPE_LOCK_ERROR,
  UnsupportedError,
  ValidationError,
} from '../config/errors';
import { extractEntityRepresentativeName, extractRepresentative } from './entity-representative';
import {
  buildPagination,
  computeAverage,
  extractIdsFromStoreObject,
  fillTimeSeries,
  INDEX_INFERRED_RELATIONSHIPS,
  inferIndexFromConceptType,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  isPointersTargetMultipleAttribute,
  READ_DATA_INDICES,
  READ_DATA_INDICES_INFERRED,
  READ_INDEX_HISTORY,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE
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
  elPaginate,
  elUpdateElement,
  elUpdateEntityConnections,
  elUpdateRelationConnections,
  ES_MAX_CONCURRENCY,
  isImpactedTypeAndSide,
  MAX_BULK_OPERATIONS,
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
  isStandardIdDowngraded,
  isStandardIdUpgraded,
  LAST_OBSERVED,
  LAST_SEEN,
  NAME_FIELD,
  normalizeName,
  REVOKED,
  START_TIME,
  STOP_TIME,
  VALID_FROM,
  VALID_UNTIL,
  VALUE_FIELD,
  X_DETECTION,
  X_WORKFLOW_ID,
} from '../schema/identifier';
import { lockResource, notify, redisAddDeletions, storeCreateEntityEvent, storeCreateRelationEvent, storeDeleteEvent, storeMergeEvent, storeUpdateEvent } from './redis';
import { cleanStixIds } from './stix';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  buildRefRelationKey,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INPUT_AUTHORIZED_MEMBERS,
  INPUT_EXTERNAL_REFS,
  INPUT_GRANTED_REFS,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INTERNAL_IDS_ALIASES,
  INTERNAL_PREFIX,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
} from '../schema/general';
import { getParentTypes, isAnId } from '../schema/schemaUtils';
import {
  INPUT_FROM,
  isStixRefRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  STIX_REF_RELATIONSHIP_TYPES
} from '../schema/stixRefRelationship';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_USER, isDatedInternalObject } from '../schema/internalObject';
import { isStixCoreObject, isStixObject } from '../schema/stixCoreObject';
import { isBasicRelationship, isStixRelationshipExceptRef } from '../schema/stixRelationship';
import {
  dateForEndAttributes,
  dateForLimitsAttributes,
  dateForStartAttributes,
  extractNotFuzzyHashValues,
  isModifiedObject,
  isUpdatedAtObject,
  noReferenceAttributes,
} from '../schema/fieldDataAdapter';
import { isStixCoreRelationship, RELATION_REVOKED_BY } from '../schema/stixCoreRelationship';
import {
  ATTRIBUTE_ADDITIONAL_NAMES,
  ATTRIBUTE_ALIASES,
  ATTRIBUTE_ALIASES_OPENCTI,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  isStixDomainObject,
  isStixDomainObjectShareableContainer,
  isStixObjectAliased,
  resolveAliasesField,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_LABEL, isStixMetaObject } from '../schema/stixMetaObject';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, isStixCyberObservable, isStixCyberObservableHashedObservable } from '../schema/stixCyberObservable';
import conf, { BUS_TOPICS, logApp } from '../config/conf';
import { FROM_START, FROM_START_STR, mergeDeepRightAll, now, prepareDate, UNTIL_END, UNTIL_END_STR, utcDate } from '../utils/format';
import { checkObservableSyntax } from '../utils/syntax';
import { deleteAllObjectFiles, storeFileConverter, upload } from './file-storage';
import {
  BYPASS_REFERENCE,
  executionContext,
  INTERNAL_USERS,
  isBypassUser,
  isUserCanAccessStoreElement,
  isUserHasCapability,
  KNOWLEDGE_ORGANIZATION_RESTRICT,
  MEMBER_ACCESS_CREATOR,
  RULE_MANAGER_USER,
  SYSTEM_USER,
  userFilterStoreElements,
  validateUserAccessOperation
} from '../utils/access';
import { isRuleUser, RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules-utils';
import { instanceMetaRefsExtractor, isSingleRelationsRef, } from '../schema/stixEmbeddedRelationship';
import { createEntityAutoEnrichment } from '../domain/enrichment';
import { convertExternalReferenceToStix, convertStoreToStix, isTrustedStixId } from './stix-converter';
import {
  buildAggregationRelationFilter,
  buildEntityFilters,
  internalFindByIds,
  internalLoadById,
  listAllRelations,
  listEntities,
  listRelations,
  storeLoadById
} from './middleware-loader';
import { checkRelationConsistency, isRelationConsistent } from '../utils/modelConsistency';
import { getEntitiesListFromCache } from './cache';
import { ACTION_TYPE_SHARE, ACTION_TYPE_UNSHARE, createListTask } from '../domain/backgroundTask-common';
import { ENTITY_TYPE_VOCABULARY, vocabularyDefinitions } from '../modules/vocabulary/vocabulary-types';
import { getVocabulariesCategories, getVocabularyCategoryForField, isEntityFieldAnOpenVocabulary, updateElasticVocabularyValue } from '../modules/vocabulary/vocabulary-utils';
import {
  depsKeysRegister,
  isBooleanAttribute,
  isDateAttribute,
  isDictionaryAttribute,
  isMultipleAttribute,
  isNumericAttribute,
  isObjectAttribute,
  schemaAttributesDefinition
} from '../schema/schema-attributes';
import { getAttributesConfiguration, getDefaultValues, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { validateInputCreation, validateInputUpdate } from '../schema/schema-validator';
import { getMandatoryAttributesForSetting } from '../domain/attribute';
import { telemetry } from '../config/tracing';
import { cleanMarkings, handleMarkingOperations } from '../utils/markingDefinition-utils';
import { generateCreateMessage, generateUpdateMessage } from './generate-message';
import { confidence } from '../schema/attribute-definition';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';

// region global variables
const MAX_BATCH_SIZE = 300;
// endregion

// region Loader common
export const batchLoader = (loader) => {
  const dataLoader = new DataLoader(
    (objects) => {
      const { context, user, args } = R.head(objects);
      const ids = objects.map((i) => i.id);
      return loader(context, user, ids, args);
    },
    { maxBatchSize: MAX_BATCH_SIZE, cache: false }
  );
  return {
    load: (id, context, user, args = {}) => {
      return dataLoader.load({ id, context, user, args });
    },
  };
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
const batchListThrough = async (context, user, sources, sourceSide, relationType, targetEntityType, opts = {}) => {
  const { paginate = true, withInferences = true, batched = true, first = null, search = null, elementId = null } = opts;
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
      { key: 'types', values: Array.isArray(targetEntityType) ? targetEntityType : [targetEntityType] },
      { key: 'role', values: [`*_${opposite}`], operator: 'wildcard' },
    ],
  };
  const filtersContent = [directionInternalIdFilter, oppositeTypeFilter];
  const filters = {
    mode: 'and',
    filters: filtersContent,
    filterGroups: [],
  };
  // region Resolve all relations (can be inferred or not)
  const indices = withInferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
  const relations = await elList(context, user, indices, {
    filters,
    types: [relationType],
    connectionFormat: false,
    noFiltersChecking: true,
    search,
  });
  // endregion
  // region Resolved all targets for all relations
  // Filter on element id if necessary
  // TODO replace that post filters by a real filters in previous elList
  let targetIds = R.uniq(relations.map((s) => s[`${opposite}Id`]));
  if (isNotEmptyField(opts.elementId)) {
    const elementIds = Array.isArray(elementId) ? elementId : [elementId];
    targetIds = targetIds.filter((id) => elementIds.includes(id));
  }
  const targets = await elFindByIds(context, user, targetIds, opts);
  // endregion
  // region Enrich all targets with internal types [manual and/or inferred]
  const targetsWithTypes = {};
  relations.forEach((relation) => {
    const relationTarget = targets.find((i) => i.id === relation[`${opposite}Id`]);
    const isInferred = isInferredIndex(relation._index);
    const targetType = isInferred ? 'inferred' : 'manual';
    if (targetsWithTypes[relationTarget.id] && !targetsWithTypes[relationTarget.id].i_types.includes(targetType)) {
      targetsWithTypes[relationTarget.id].i_types.push(targetType);
    } else {
      targetsWithTypes[relationTarget.id] = { ...relationTarget, i_types: [targetType] };
    }
  });
  // endregion
  // Group and rebuild the result
  const processedTargets = Object.values(targetsWithTypes);
  const elGrouped = R.groupBy((e) => e[`${sourceSide}Id`], relations);
  if (paginate) {
    return ids.map((id) => {
      const values = elGrouped[id];
      const edges = [];
      if (values) {
        const data = first ? R.take(first, values) : values;
        const filterIds = (data || []).map((i) => i[`${opposite}Id`]);
        const filteredElements = processedTargets.filter((t) => filterIds.includes(t.internal_id));
        edges.push(...filteredElements.map((n) => ({ node: n, types: n.i_types })));
      }
      return buildPagination(0, null, edges, edges.length);
    });
  }
  const elements = ids.map((id) => {
    const values = elGrouped[id];
    const data = first ? R.take(first, values) : values;
    const filterIds = (data || []).map((i) => i[`${opposite}Id`]);
    return targets.filter((t) => filterIds.includes(t.internal_id));
  });
  if (batched) {
    return elements;
  }
  return R.flatten(elements);
};
export const batchListThroughGetFrom = async (context, user, sources, relationType, targetEntityType, opts = {}) => {
  return batchListThrough(context, user, sources, 'to', relationType, targetEntityType, opts);
};
export const listThroughGetFrom = async (context, user, sources, relationType, targetEntityType, opts = { paginate: false }) => {
  const options = { ...opts, batched: false };
  return batchListThrough(context, user, sources, 'to', relationType, targetEntityType, options);
};
export const batchListThroughGetTo = async (context, user, sources, relationType, targetEntityType, opts = {}) => {
  return batchListThrough(context, user, sources, 'from', relationType, targetEntityType, opts);
};
export const listThroughGetTo = async (context, user, sources, relationType, targetEntityType, opts = { paginate: false }) => {
  const options = { ...opts, batched: false };
  return batchListThrough(context, user, sources, 'from', relationType, targetEntityType, options);
};
// Unary handle
const loadThrough = async (context, user, sources, sourceSide, relationType, targetEntityType) => {
  const elements = await batchListThrough(context, user, sources, sourceSide, relationType, targetEntityType, {
    paginate: false,
    batched: false,
  });
  if (elements.length > 1) {
    throw DatabaseError('Expected one element only through relation', { sources, relationType, targetEntityType });
  }
  return R.head(elements);
};
export const batchLoadThroughGetFrom = async (context, user, sources, relationType, targetEntityType) => {
  const data = await batchListThroughGetFrom(context, user, sources, relationType, targetEntityType, { paginate: false });
  return data.map((b) => b && R.head(b));
};
export const loadThroughGetFrom = async (context, user, sources, relationType, targetEntityType) => {
  return loadThrough(context, user, sources, 'to', relationType, targetEntityType);
};
export const batchLoadThroughGetTo = async (context, user, sources, relationType, targetEntityType) => {
  const data = await batchListThroughGetTo(context, user, sources, relationType, targetEntityType, { paginate: false });
  return data.map((b) => b && R.head(b));
};
export const loadThroughGetTo = async (context, user, sources, relationType, targetEntityType) => {
  return loadThrough(context, user, sources, 'from', relationType, targetEntityType);
};
// Standard listing
export const listThings = async (context, user, thingsTypes, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildEntityFilters({ types: thingsTypes, ...args });
  return elPaginate(context, user, indices, paginateArgs);
};
export const listAllThings = async (context, user, thingsTypes, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildEntityFilters({ types: thingsTypes, ...args });
  return elList(context, user, indices, paginateArgs);
};
export const paginateAllThings = async (context, user, thingsTypes, args = {}) => {
  const result = await listAllThings(context, user, thingsTypes, args);
  const nodeResult = result.map((n) => ({ node: n }));
  return buildPagination(0, null, nodeResult, nodeResult.length);
};
export const loadEntity = async (context, user, entityTypes, args = {}) => {
  const opts = { ...args, connectionFormat: false };
  const entities = await listEntities(context, user, entityTypes, opts);
  if (entities.length > 1) {
    throw DatabaseError('Expect only one response', { entityTypes, args });
  }
  return R.head(entities);
};
// endregion

// region Loader element
const loadElementMetaDependencies = async (context, user, elements, args = {}) => {
  const { onlyMarking = true } = args;
  const workingElements = Array.isArray(elements) ? elements : [elements];
  const workingElementsMap = new Map(workingElements.map((i) => [i.internal_id, i]));
  const elementIds = workingElements.map((element) => element.internal_id);
  const relTypes = onlyMarking ? [RELATION_OBJECT_MARKING] : STIX_REF_RELATIONSHIP_TYPES;
  // Resolve all relations
  const refIndices = [READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS, READ_INDEX_INFERRED_RELATIONSHIPS];
  const refsRelations = await elFindByIds(context, user, elementIds, { type: relTypes, indices: refIndices, onRelationship: 'from' });
  const refsPerElements = R.groupBy((r) => r.fromId, refsRelations);
  // Parallel resolutions
  const toResolvedIds = R.uniq(refsRelations.map((rel) => rel.toId));
  const toResolvedElements = await elFindByIds(context, user, toResolvedIds, { withoutRels: true, connectionFormat: false, toMap: true });
  const refEntries = Object.entries(refsPerElements);
  const loadedElementMap = new Map();
  for (let indexRef = 0; indexRef < refEntries.length; indexRef += 1) {
    const [elementId, dependencies] = refEntries[indexRef];
    const element = workingElementsMap.get(elementId);
    // Build flatten view inside the data for stix meta
    const data = {};
    if (element) {
      const grouped = R.groupBy((a) => a.entity_type, dependencies);
      const entries = Object.entries(grouped);
      for (let index = 0; index < entries.length; index += 1) {
        const [key, values] = entries[index];
        const inputKey = schemaRelationsRefDefinition.convertDatabaseNameToInputName(element.entity_type, key);
        const resolvedElementsWithRelation = R.map((v) => {
          const resolvedElement = toResolvedElements[v.toId];
          return resolvedElement ? { ...resolvedElement, i_relation: v } : {};
        }, values).filter((d) => isNotEmptyField(d));
        const metaRefKey = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputKey);
        if (isEmptyField(metaRefKey)) {
          throw UnsupportedError('Schema validation failure when loading dependencies', { key, inputKey, type: element.entity_type });
        }
        const invalidRelations = values.filter((v) => toResolvedElements[v.toId] === undefined);
        if (invalidRelations.length > 0) {
          // Some targets can be unresolved in case of potential inconsistency between relation and target
          // This kind of situation can happen if:
          // - Access rights are asymmetric, should not happen for meta relationships.
          // - Relations is invalid, should not happen in platform data consistency.
          logApp.warn('Targets of loadElementMetaDependencies not found', { relations: values.map((v) => ({ id: v.id, target: v.toId })) });
        }
        data[key] = !metaRefKey.multiple ? R.head(resolvedElementsWithRelation)?.internal_id : resolvedElementsWithRelation.map((r) => r.internal_id);
        data[inputKey] = !metaRefKey.multiple ? R.head(resolvedElementsWithRelation) : resolvedElementsWithRelation;
      }
      loadedElementMap.set(elementId, data);
    }
  }
  return loadedElementMap;
};
const loadElementsWithDependencies = async (context, user, elements, opts = {}) => {
  const elementsToDeps = [...elements];
  let fromAndToPromise = Promise.resolve();
  const targetsToResolved = [];
  elements.forEach((e) => {
    const isRelation = e.base_type === BASE_TYPE_RELATION;
    if (isRelation) {
      elementsToDeps.push({ internal_id: e.fromId, entity_type: e.fromType });
      elementsToDeps.push({ internal_id: e.toId, entity_type: e.toType });
      targetsToResolved.push(...[e.fromId, e.toId]);
    }
  });
  const depsPromise = loadElementMetaDependencies(context, user, elementsToDeps, opts);
  if (targetsToResolved.length > 0) {
    const args = { toMap: true, connectionFormat: false };
    // Load with System user, access rights will be dynamically change after
    fromAndToPromise = elFindByIds(context, SYSTEM_USER, targetsToResolved, args);
  }
  const [fromAndToMap, depsElementsMap] = await Promise.all([fromAndToPromise, depsPromise]);
  const loadedElements = [];
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    const isRelation = element.base_type === BASE_TYPE_RELATION;
    if (isRelation) {
      const rawFrom = fromAndToMap[element.fromId];
      const rawTo = fromAndToMap[element.toId];
      const deps = depsElementsMap.get(element.id);
      // Check relations consistency
      if (isEmptyField(rawFrom) || isEmptyField(rawTo)) {
        const validFrom = isEmptyField(rawFrom) ? 'invalid' : 'valid';
        const validTo = isEmptyField(rawTo) ? 'invalid' : 'valid';
        const detail = `From ${element.fromId} is ${validFrom}, To ${element.toId} is ${validTo}`;
        logApp.warn('Auto delete of invalid relation', { id: element.id, detail });
        // Auto deletion of the invalid relation
        await elDeleteElements(context, SYSTEM_USER, [element]);
      } else {
        const from = R.mergeRight(element, { ...rawFrom, ...depsElementsMap.get(element.fromId) });
        const to = R.mergeRight(element, { ...rawTo, ...depsElementsMap.get(element.toId) });
        // Check relations marking access.
        const canAccessFrom = await isUserCanAccessStoreElement(context, user, from);
        const canAccessTo = await isUserCanAccessStoreElement(context, user, to);
        if (canAccessFrom && canAccessTo) {
          loadedElements.push(R.mergeRight(element, { from, to, ...deps }));
        }
      }
    } else {
      const deps = depsElementsMap.get(element.id);
      loadedElements.push(R.mergeRight(element, { ...deps }));
    }
  }
  return loadedElements;
};
const loadByIdsWithDependencies = async (context, user, ids, opts = {}) => {
  const elements = await elFindByIds(context, user, ids, { ...opts, withoutRels: true, connectionFormat: false });
  if (elements.length > 0) {
    return loadElementsWithDependencies(context, user, elements, opts);
  }
  return [];
};
const loadByFiltersWithDependencies = async (context, user, types, args = {}) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildEntityFilters({ types, ...args });
  const elements = await elList(context, user, indices, { ...paginateArgs, withoutRels: true, connectionFormat: false });
  if (elements.length > 0) {
    return loadElementsWithDependencies(context, user, elements, { ...args, onlyMarking: false, withoutRels: true });
  }
  return [];
};
// Get element with every elements connected element -> rel -> to
export const storeLoadByIdsWithRefs = async (context, user, ids, opts = {}) => {
  // When loading with explicit references, data must be loaded without internal rels
  // As rels are here for search and sort there is some data that conflict after references explication resolutions
  return loadByIdsWithDependencies(context, user, ids, { ...opts, onlyMarking: false, withoutRels: true });
};
export const storeLoadByIdWithRefs = async (context, user, id, opts = {}) => {
  const elements = await storeLoadByIdsWithRefs(context, user, [id], opts);
  return elements.length > 0 ? R.head(elements) : null;
};
export const stixLoadById = async (context, user, id, opts = {}) => {
  const instance = await storeLoadByIdWithRefs(context, user, id, opts);
  return instance ? convertStoreToStix(instance) : undefined;
};
export const stixLoadByIds = async (context, user, ids, opts = {}) => {
  const elements = await storeLoadByIdsWithRefs(context, user, ids, opts);
  // As stix load by ids doesn't respect the ordering we need to remap the result
  const loadedInstancesMap = new Map(elements.map((i) => ({ instance: i, ids: extractIdsFromStoreObject(i) }))
    .flat().map((o) => o.ids.map((id) => [id, o.instance])).flat());
  return ids.map((id) => loadedInstancesMap.get(id)).filter((i) => isNotEmptyField(i)).map((e) => convertStoreToStix(e));
};
export const stixLoadByIdStringify = async (context, user, id) => {
  const data = await stixLoadById(context, user, id);
  return data ? JSON.stringify(data) : '';
};
export const stixLoadByFilters = async (context, user, types, args) => {
  const elements = await loadByFiltersWithDependencies(context, user, types, args);
  return elements ? elements.map((element) => convertStoreToStix(element)) : [];
};
// endregion

// region Graphics
const convertAggregateDistributions = async (context, user, limit, orderingFunction, distribution) => {
  const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distribution));
  const resolveLabels = await elFindByIds(context, user, data.map((d) => d.label), { toMap: true });
  return data // Depending of user access, info can be empty, must be filtered
    .filter((n) => isNotEmptyField(resolveLabels[n.label.toLowerCase()]))
    .map((n) => R.assoc('entity', resolveLabels[n.label.toLowerCase()], n));
};
export const timeSeriesHistory = async (context, user, types, args) => {
  const { startDate, endDate, interval } = args;
  const histogramData = await elHistogramCount(context, user, READ_INDEX_HISTORY, args);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesEntities = async (context, user, types, args) => {
  const timeSeriesArgs = buildEntityFilters({ types, ...args });
  const { startDate, endDate, interval } = args;
  const histogramData = await elHistogramCount(context, user, args.onlyInferred ? READ_DATA_INDICES_INFERRED : READ_DATA_INDICES, timeSeriesArgs);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesRelations = async (context, user, args) => {
  const { startDate, endDate, relationship_type: relationshipTypes, interval } = args;
  const types = relationshipTypes || ['stix-core-relationship'];
  const timeSeriesArgs = buildEntityFilters({ types, ...args });
  const histogramData = await elHistogramCount(context, user, args.onlyInferred ? INDEX_INFERRED_RELATIONSHIPS : READ_RELATIONSHIPS_INDICES, timeSeriesArgs);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionHistory = async (context, user, types, args) => {
  const { limit = 10, order = 'desc', field } = args;
  if (field.includes('.') && (!field.endsWith('internal_id') && !field.includes('context_data'))) {
    throw FunctionalError('Distribution entities does not support relation aggregation field');
  }
  let finalField = field;
  if (field.includes('.' && !field.includes('context_data'))) {
    finalField = REL_INDEX_PREFIX + field;
  }
  if (field === 'name') {
    finalField = 'internal_id';
  }
  const distributionData = await elAggregationCount(context, user, READ_INDEX_HISTORY, {
    ...args,
    field: finalField,
  });
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL) || field === 'creator_id' || field === 'user_id' || field === 'group_ids' || field === 'organization_ids' || field.includes('.id') || field.includes('_id')) {
    return convertAggregateDistributions(context, user, limit, orderingFunction, distributionData);
  }
  if (field === 'name' || field === 'context_data.id') {
    let result = [];
    await convertAggregateDistributions(context, user, limit, orderingFunction, distributionData)
      .then((hits) => {
        result = hits.map((hit) => ({
          label: hit.entity.name ?? extractEntityRepresentativeName(hit.entity),
          value: hit.value,
          entity: hit.entity,
        }));
      });
    return result;
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionEntities = async (context, user, types, args) => {
  const distributionArgs = buildEntityFilters({ types, ...args });
  const { limit = 10, order = 'desc', field } = args;
  if (field.includes('.') && !field.endsWith('internal_id')) {
    throw FunctionalError('Distribution entities does not support relation aggregation field');
  }
  let finalField = field;
  if (field.includes('.')) {
    finalField = REL_INDEX_PREFIX + field;
  }
  if (field === 'name') {
    finalField = 'internal_id';
  }
  const distributionData = await elAggregationCount(context, user, args.onlyInferred ? READ_DATA_INDICES_INFERRED : READ_DATA_INDICES, {
    ...distributionArgs,
    field: finalField
  });
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL) || field === 'creator_id' || field === 'x_opencti_workflow_id') {
    return convertAggregateDistributions(context, user, limit, orderingFunction, distributionData);
  }
  if (field === 'name') {
    let result = [];
    await convertAggregateDistributions(context, user, limit, orderingFunction, distributionData)
      .then((hits) => {
        result = hits.map((hit) => ({
          label: hit.entity.name ?? extractEntityRepresentativeName(hit.entity),
          value: hit.value,
          entity: hit.entity,
        }));
      });
    return result;
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData)); // label not good
};
export const distributionRelations = async (context, user, args) => {
  const { field } = args; // Mandatory fields
  const { limit = 50, order } = args;
  const { relationship_type: relationshipTypes, dateAttribute = 'created_at' } = args;
  const types = relationshipTypes || [ABSTRACT_BASIC_RELATIONSHIP];
  const distributionDateAttribute = dateAttribute || 'created_at';
  let finalField = field;
  if (field.includes('.')) {
    finalField = REL_INDEX_PREFIX + field;
  }
  // Using elastic can only be done if the distribution is a count on types
  const opts = { ...args, dateAttribute: distributionDateAttribute, field: finalField };
  const distributionArgs = buildAggregationRelationFilter(types, opts);
  const distributionData = await elAggregationRelationsCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_RELATIONSHIPS : READ_RELATIONSHIPS_INDICES, distributionArgs);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL) || field === 'creator_id' || field === 'x_opencti_workflow_id') {
    return convertAggregateDistributions(context, user, limit, orderingFunction, distributionData);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
// endregion

// region mutation common
const depsKeys = (type) => ([
  ...depsKeysRegister.get(),
  ...[
    // Relationship
    { src: 'fromId', dst: 'from' },
    { src: 'toId', dst: 'to' },
    // Other meta refs
    ...schemaRelationsRefDefinition.getInputNames(type).map((e) => ({ src: e })),
  ],
]);

const idNormalizeDataEntity = (nameOrId, data) => (isAnId(nameOrId) ? nameOrId : generateAliasesId([nameOrId], data).at(0));

const idLabel = (label) => {
  return isAnId(label) ? label : generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(label) });
};

const inputResolveRefs = async (context, user, input, type, entitySetting) => {
  const inputResolveRefsFn = async () => {
    const fetchingIds = [];
    const expectedIds = [];
    const cleanedInput = { _index: inferIndexFromConceptType(type), ...input };
    let embeddedFromResolution;
    let forceAliases = false;
    const dependencyKeys = depsKeys(type);
    for (let index = 0; index < dependencyKeys.length; index += 1) {
      const { src, dst, types } = dependencyKeys[index];
      const depTypes = types ?? [];
      const destKey = dst || src;
      const id = input[src];
      const isValidType = depTypes.length > 0 ? depTypes.includes(type) : true;
      if (isValidType && !R.isNil(id) && !R.isEmpty(id)) {
        const isListing = Array.isArray(id);
        const hasOpenVocab = isEntityFieldAnOpenVocabulary(destKey, type);
        // Handle specific case of object label that can be directly the value instead of the key.
        if (src === INPUT_LABELS) {
          const elements = R.uniq(id.map((label) => idLabel(label)))
            .map((lid) => ({ id: lid, destKey, multiple: true }));
          fetchingIds.push(...elements);
          expectedIds.push(...elements.map((e) => e.id));
        } else if (hasOpenVocab) {
          const ids = isListing ? id : [id];
          const category = getVocabularyCategoryForField(destKey, type);
          const elements = ids.map((i) => idNormalizeDataEntity(i, { category, entity_type: ENTITY_TYPE_VOCABULARY }))
            .map((lid) => ({ id: lid, destKey, multiple: isListing }));
          fetchingIds.push(...elements);
          forceAliases = true;
        } else if (isListing) {
          const elements = R.uniq(id).map((i) => ({ id: i, destKey, multiple: true }));
          fetchingIds.push(...elements);
          expectedIds.push(...elements.map((e) => e.id));
        } else { // Single
          if (dst === INPUT_FROM && isStixRefRelationship(type)) {
            // If resolution is due to embedded ref, the from must be fully resolved
            // This will be used to generated a correct stream message
            embeddedFromResolution = id;
          } else {
            fetchingIds.push({ id, destKey, multiple: false });
          }
          if (!expectedIds.includes(id)) {
            expectedIds.push(id);
          }
        }
        cleanedInput[src] = null;
      }
    }
    const simpleResolutionsPromise = internalFindByIds(context, user, fetchingIds.map((i) => i.id), { forceAliases });
    let embeddedFromPromise = Promise.resolve();
    if (embeddedFromResolution) {
      fetchingIds.push({ id: embeddedFromResolution, destKey: 'from', multiple: false });
      embeddedFromPromise = storeLoadByIdWithRefs(context, user, embeddedFromResolution);
    }
    const [resolvedElements, embeddedFrom] = await Promise.all([simpleResolutionsPromise, embeddedFromPromise]);
    if (embeddedFrom) {
      resolvedElements.push(embeddedFrom);
    }
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
        throw UnsupportedError('Input resolve refs expect single value', { key: k, values: val });
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
    // In case of missing from / to, fail directly
    const expectedUnresolvedIds = unresolvedIds.filter((u) => u === input.fromId || u === input.toId);
    if (expectedUnresolvedIds.length > 0) {
      throw MissingReferenceError({ input, unresolvedIds: expectedUnresolvedIds });
    }
    // In case of missing reference NOT from or to, we reject twice before accepting
    // TODO this retry must be removed in favor of reworking the workers synchronization
    const retryNumber = user.origin?.call_retry_number;
    const optionalRefsUnresolvedIds = unresolvedIds.filter((u) => u !== input.fromId || u !== input.toId);
    const attributesConfiguration = getAttributesConfiguration(entitySetting);
    const defaultValues = attributesConfiguration?.map((attr) => attr.default_values).flat() ?? [];
    const expectedUnresolvedIdsNotDefault = optionalRefsUnresolvedIds.filter((id) => !defaultValues.includes(id));
    if (isNotEmptyField(retryNumber) && expectedUnresolvedIdsNotDefault.length > 0 && retryNumber <= 2) {
      throw MissingReferenceError({ input, unresolvedIds: expectedUnresolvedIdsNotDefault });
    }
    const complete = { ...cleanedInput, entity_type: type };
    const inputResolved = R.mergeRight(complete, R.mergeAll(resolved));
    // Check Open vocab in resolved to convert them back to the raw value
    const entityVocabs = Object.values(vocabularyDefinitions).filter(({ entity_types }) => entity_types.includes(type));
    entityVocabs.forEach(({ fields }) => {
      const existingFields = fields.filter(({ key }) => Boolean(input[key]));
      existingFields.forEach(({ key, required, multiple }) => {
        const resolvedData = inputResolved[key];
        if (isEmptyField(resolvedData) && required) {
          throw FunctionalError('Missing mandatory attribute for vocabulary', { key });
        }
        if (isNotEmptyField(resolvedData)) {
          const isArrayValues = Array.isArray(resolvedData);
          if (isArrayValues && !multiple) {
            throw FunctionalError('Find multiple vocabularies for single one', { key, data: resolvedData });
          }
          inputResolved[key] = isArrayValues ? resolvedData.map(({ name }) => name) : resolvedData.name;
        }
      });
    });
    // Check the marking allow for the user and asked inside the input
    if (!isBypassUser(user) && inputResolved[INPUT_MARKINGS]) {
      const inputMarkingIds = inputResolved[INPUT_MARKINGS].map((marking) => marking.internal_id);
      const userMarkingIds = user.allowed_marking.map((marking) => marking.internal_id);
      if (!inputMarkingIds.every((v) => userMarkingIds.includes(v))) {
        throw MissingReferenceError({ context: 'Missing markings', input });
      }
    }
    return inputResolved;
  };
  return telemetry(context, user, `INPUTS RESOLVE ${type}`, {
    [SemanticAttributes.DB_NAME]: 'middleware',
    [SemanticAttributes.DB_OPERATION]: 'resolver',
  }, inputResolveRefsFn);
};
const isRelationTargetGrants = (elementGrants, relation, type) => {
  const isTargetType = relation.base_type === BASE_TYPE_RELATION && relation.entity_type === RELATION_OBJECT;
  if (!isTargetType) return false;
  const isUnrestricted = [relation.to.entity_type, ...relation.to.parent_types]
    .some((r) => STIX_ORGANIZATIONS_UNRESTRICTED.includes(r));
  if (isUnrestricted) return false;
  return type === ACTION_TYPE_UNSHARE || !elementGrants.every((v) => (relation.to[RELATION_GRANTED_TO] ?? []).includes(v));
};
const createContainerSharingTask = (context, type, element, relations = []) => {
  // If object_refs relations are newly created
  // One side is a container, the other side must inherit from the granted_refs
  const targetGrantIds = [];
  let taskPromise = Promise.resolve();
  const elementGrants = (relations ?? []).filter((e) => e.entity_type === RELATION_GRANTED_TO).map((r) => r.to.internal_id);
  // If container is granted, we need to grant every new children.
  if (element.base_type === BASE_TYPE_ENTITY && isStixDomainObjectShareableContainer(element.entity_type)) {
    elementGrants.push(...(element[RELATION_GRANTED_TO] ?? []));
    if (elementGrants.length > 0) {
      // A container has created or modified (addition of some object_refs)
      // We need to compute the granted_refs on the container and apply it on new child
      // Apply will be done on a background task to not slow the main ingestion process.
      const newChildrenIds = (relations ?? [])
        .filter((e) => isRelationTargetGrants(elementGrants, e, type))
        .map((r) => r.to.internal_id);
      targetGrantIds.push(...newChildrenIds);
    }
  }
  if (element.base_type === BASE_TYPE_RELATION && isStixDomainObjectShareableContainer(element.from.entity_type)) {
    elementGrants.push(...(element.from[RELATION_GRANTED_TO] ?? []));
    // A new object_ref relation was created between a shareable container and an element
    // If this element is compatible we need to apply the granted_refs of the container on this new element
    if (elementGrants.length > 0 && isRelationTargetGrants(elementGrants, element, type)) {
      targetGrantIds.push(element.to.internal_id);
    }
  }
  // If element needs to be updated, start a SHARE background task
  if (targetGrantIds.length > 0) {
    const input = { ids: targetGrantIds, scope: 'SETTINGS', actions: [{ type, context: { values: elementGrants } }] };
    taskPromise = createListTask(context, context.user, input);
  }
  return taskPromise;
};
const indexCreatedElement = async (context, user, { element, relations }) => {
  // Continue the creation of the element and the connected relations
  const indexPromise = elIndexElements(context, user, element.entity_type, [element, ...(relations ?? [])]);
  const taskPromise = createContainerSharingTask(context, ACTION_TYPE_SHARE, element, relations);
  await Promise.all([taskPromise, indexPromise]);
};
export const updatedInputsToData = (instance, inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value } = input;
    let val = value;
    if (!isMultipleAttribute(instance.entity_type, key) && val) {
      val = R.head(value);
    }
    return { [key]: val };
  }, inputs);
  return mergeDeepRightAll(...inputPairs);
};
export const mergeInstanceWithInputs = (instance, inputs) => {
  // standard_id must be maintained
  // const inputsWithoutId = inputs.filter((i) => i.key !== ID_STANDARD);
  const data = updatedInputsToData(instance, inputs);
  const updatedInstance = R.mergeRight(instance, data);
  return R.reject(R.equals(null))(updatedInstance);
};
const partialInstanceWithInputs = (instance, inputs) => {
  const inputData = updatedInputsToData(instance, inputs);
  return {
    _index: instance._index,
    internal_id: instance.internal_id,
    entity_type: instance.entity_type,
    representative: extractRepresentative(instance),
    ...inputData,
  };
};
const rebuildAndMergeInputFromExistingData = (rawInput, instance) => {
  const { key, value, object_path, operation = UPDATE_OPERATION_REPLACE } = rawInput; // value can be multi valued
  const isMultiple = isMultipleAttribute(instance.entity_type, key);
  let finalVal;
  let finalKey = key;
  // TODO Add support for these restrictions
  // TODO Change R.head(value) limitation
  if (isDictionaryAttribute(key) && isNotEmptyField(R.head(value))) { // Only allow full cleanup
    throw UnsupportedError('Dictionary attribute cant be updated directly', { rawInput });
  }
  if (!isMultiple && isObjectAttribute(key)) {
    throw UnsupportedError('Object update only available for array attributes', { rawInput });
  }
  // region rebuild input values consistency
  if (key.includes('.')) {
    // In case of dict attributes, patching the content is possible through first level path
    const splitKey = key.split('.');
    if (splitKey.length > 2) {
      throw UnsupportedError('Multiple path follow is not supported', { rawInput });
    }
    const [baseKey, targetKey] = splitKey;
    if (!isDictionaryAttribute(baseKey)) {
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
    const currentValues = (Array.isArray(instance[key]) ? instance[key] : [instance[key]]) ?? [];
    if (operation === UPDATE_OPERATION_ADD) {
      if (isObjectAttribute(key) && object_path) {
        const pointers = JSONPath({ json: instance, resultType: 'pointer', path: `${key}${object_path}` });
        const patch = pointers.map((p) => ({ op: operation, path: p, value }));
        const patchedInstance = jsonpatch.applyPatch(structuredClone(instance), patch).newDocument;
        finalVal = patchedInstance[key];
      } else {
        finalVal = R.uniq([...currentValues, value].flat().filter((v) => isNotEmptyField(v)));
      }
    } else if (operation === UPDATE_OPERATION_REMOVE) {
      if (isObjectAttribute(key)) {
        const pointers = JSONPath({ json: instance, resultType: 'pointer', path: `${key}${object_path}` }).reverse();
        const patch = pointers.map((p) => ({ op: operation, path: p }));
        const patchedInstance = jsonpatch.applyPatch(structuredClone(instance), patch).newDocument;
        finalVal = patchedInstance[key];
      } else {
        finalVal = R.filter((n) => !R.includes(n, value), currentValues);
      }
    } else if (isObjectAttribute(key)) { // REPLACE
      const path = `${key}${object_path ?? ''}`;
      const pointers = JSONPath({ json: instance, resultType: 'pointer', path });
      if (pointers.length === 0) { // If no pointers, target the base attribute
        const base = schemaAttributesDefinition.getAttribute(instance.entity_type, key);
        finalVal = base.multiple ? value : R.head(value);
      } else {
        const targetIsMultiple = isPointersTargetMultipleAttribute(instance, pointers);
        const patch = pointers.map((p) => ({ op: operation, path: p, value: targetIsMultiple ? value : R.head(value) }));
        const patchedInstance = jsonpatch.applyPatch(structuredClone(instance), patch).newDocument;
        finalVal = patchedInstance[key];
      }
    } else { // Replace general
      finalVal = value;
    }
    if (compareUnsorted(finalVal ?? [], currentValues)) {
      return {}; // No need to update the attribute
    }
  } else {
    finalVal = value;
    const isDate = isDateAttribute(key);
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
  if (isDateAttribute(finalKey)) {
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
  const metaKeys = [...schemaRelationsRefDefinition.getStixNames(instance.entity_type), ...schemaRelationsRefDefinition.getInputNames(instance.entity_type)];
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  const mergeInput = (input) => rebuildAndMergeInputFromExistingData(input, instance);
  const remappedInputs = R.map((i) => mergeInput(i), attributes);
  const resolvedInputs = R.filter((f) => !R.isEmpty(f), remappedInputs);
  return mergeInstanceWithInputs(instance, resolvedInputs);
};
const listEntitiesByHashes = async (context, user, type, hashes) => {
  if (isEmptyField(hashes)) {
    return [];
  }
  const searchHashes = extractNotFuzzyHashValues(hashes); // Search hashes must filter the fuzzy hashes
  return listEntities(context, user, [type], {
    filters: {
      mode: 'and',
      filters: [{ key: 'hashes.*', values: searchHashes, operator: 'wildcard' }],
      filterGroups: [],
    },
    noFiltersChecking: true,
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
const ed = (date) => isEmptyField(date) || date === FROM_START_STR || date === UNTIL_END_STR;
const noDate = (e) => ed(e.first_seen) && ed(e.last_seen) && ed(e.start_time) && ed(e.stop_time);
const filterTargetByExisting = async (context, targetEntity, redirectSide, sourcesDependencies, targetDependencies) => {
  const cache = [];
  const filtered = [];
  const sources = sourcesDependencies[`i_relations_${redirectSide}`];
  const targets = targetDependencies[`i_relations_${redirectSide}`];
  const markingSources = sources.filter((r) => r.i_relation.entity_type === RELATION_OBJECT_MARKING);
  const markingTargets = targets.filter((r) => r.i_relation.entity_type === RELATION_OBJECT_MARKING);
  const markings = [...markingSources, ...markingTargets];
  const filteredMarkings = await cleanMarkings(context, markings.map((m) => m.internal_id));
  const filteredMarkingIds = filteredMarkings.map((m) => m.internal_id);
  const markingTargetDeletions = markingTargets.filter((m) => !filteredMarkingIds.includes(m.internal_id)).map((m) => m.i_relation);
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index];
    // If the relation source is already in target = filtered
    const finder = (t) => {
      const sameTarget = t.internal_id === source.internal_id;
      const sameRelationType = t.i_relation.entity_type === source.i_relation.entity_type;
      return sameRelationType && sameTarget && noDate(t.i_relation);
    };
    // In case of single meta to move, check if the target have not already this relation.
    // If yes, we keep it, if not we rewrite it
    const isSingleMeta = isSingleRelationsRef(source.i_relation.fromType, source.i_relation.entity_type);
    const relationInputName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(targetEntity.entity_type, source.i_relation.entity_type);
    const existingSingleMeta = isSingleMeta && isNotEmptyField(targetEntity[relationInputName]);
    // For single meta only rely on entity type to prevent relation duplications
    const id = isSingleMeta ? source.i_relation.entity_type : `${source.i_relation.entity_type}-${source.internal_id}`;
    // Self ref relationships is not allowed, need to compare the side that will be kept with the target
    const relationSideToKeep = redirectSide === 'from' ? 'toId' : 'fromId';
    const isSelfMeta = isStixRefRelationship(source.i_relation.entity_type) && (targetEntity.internal_id === source.i_relation[relationSideToKeep]);
    // Markings duplication definition group
    const isMarkingToKeep = source.i_relation.entity_type === RELATION_OBJECT_MARKING ? filteredMarkingIds.includes(source.internal_id) : true;
    // Check and add the relation in the processing list if needed
    if (!existingSingleMeta && !isSelfMeta && isMarkingToKeep && !R.find(finder, targets) && !cache.includes(id)) {
      filtered.push(source);
      cache.push(id);
    }
  }
  return { deletions: markingTargetDeletions, redirects: filtered };
};

const mergeEntitiesRaw = async (context, user, targetEntity, sourceEntities, targetDependencies, sourcesDependencies, opts = {}) => {
  const { chosenFields = {} } = opts;
  // 01 Check if everything is fully resolved.
  const elements = [targetEntity, ...sourceEntities];
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
    throw FunctionalError('Cannot merge entities of different types', { dest: targetType, source: sourceTypes });
  }
  // Check supported entities
  if (!isStixCoreObject(targetEntity.entity_type) && targetEntity.entity_type !== ENTITY_TYPE_VOCABULARY) {
    throw FunctionalError('Unsupported entity type for merging', { type: targetType });
  }
  // For vocabularies, extra elastic query is required
  if (targetEntity.entity_type === ENTITY_TYPE_VOCABULARY) {
    // Merge is only possible between same categories
    const categories = new Set([targetEntity.category, ...sourceEntities.map((s) => s.category)]);
    if (categories.size > 1) {
      throw FunctionalError('Cannot merge vocabularies of different category', { categories });
    }
    const completeCategory = getVocabulariesCategories().find(({ key }) => key === targetEntity.category);
    await updateElasticVocabularyValue(sourceEntities.map((s) => s.name), targetEntity.name, completeCategory);
  }
  // 2. EACH SOURCE (Ignore createdBy)
  // - EVERYTHING I TARGET (->to) ==> We change to relationship FROM -> TARGET ENTITY
  // - EVERYTHING TARGETING ME (-> from) ==> We change to relationship TO -> TARGET ENTITY
  // region CHANGING FROM
  const { deletions: fromDeletions, redirects: relationsToRedirectFrom } = await filterTargetByExisting(context, targetEntity, 'from', sourcesDependencies, targetDependencies);
  // region CHANGING TO
  const { deletions: toDeletions, redirects: relationsFromRedirectTo } = await filterTargetByExisting(context, targetEntity, 'to', sourcesDependencies, targetDependencies);
  const updateConnections = [];
  const updateEntities = [];
  // FROM (x -> MERGED TARGET) --- (from) relation (to) ---- RELATED_ELEMENT
  // noinspection DuplicatedCode
  for (let indexFrom = 0; indexFrom < relationsToRedirectFrom.length; indexFrom += 1) {
    const entity = relationsToRedirectFrom[indexFrom];
    const sideTarget = targetEntity.internal_id;
    const sideToRedirect = entity.i_relation.fromId;
    const sideToKeep = entity.i_relation.toId;
    const sideToKeepType = entity.i_relation.toType;
    const relationType = entity.i_relation.entity_type;
    // Replace relation connection fromId with the new TARGET
    const relUpdate = {
      _index: entity.i_relation._index,
      id: entity.i_relation.internal_id,
      standard_id: entity.i_relation.standard_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      side: 'source_ref',
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, ROLE_TO)) {
      updateEntities.push({
        _index: entity._index,
        id: sideToKeep,
        toReplace: sideToRedirect,
        relationType,
        entity_type: sideToKeepType,
        data: { internal_id: sideTarget },
      });
    }
    // Update the MERGED TARGET (Need to add the relation side)
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, ROLE_FROM)) {
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
    const entity = relationsFromRedirectTo[indexTo];
    const sideToRedirect = entity.i_relation.toId;
    const sideToKeep = entity.i_relation.fromId;
    const sideToKeepType = entity.i_relation.fromType;
    const sideTarget = targetEntity.internal_id;
    const relationType = entity.i_relation.entity_type;
    const relUpdate = {
      _index: entity.i_relation._index,
      id: entity.i_relation.internal_id,
      standard_id: entity.i_relation.standard_id,
      toReplace: sideToRedirect,
      entity_type: relationType,
      side: 'target_ref',
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, ROLE_FROM)) {
      updateEntities.push({
        _index: entity._index,
        id: sideToKeep,
        toReplace: sideToRedirect,
        relationType,
        entity_type: sideToKeepType,
        data: { internal_id: sideTarget },
      });
    }
    // Update the MERGED TARGET (Need to add the relation side)
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, ROLE_TO)) {
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
  const groupsOfRelsUpdate = R.splitEvery(MAX_BULK_OPERATIONS, updateConnections);
  const concurrentRelsUpdate = async (connsToUpdate) => {
    await elUpdateRelationConnections(connsToUpdate);
    currentRelsUpdateCount += connsToUpdate.length;
    logApp.info(`[OPENCTI] Merging, updating relations ${currentRelsUpdateCount} / ${updateConnections.length}`);
  };
  await Promise.map(groupsOfRelsUpdate, concurrentRelsUpdate, { concurrency: ES_MAX_CONCURRENCY });
  const updatedRelations = updateConnections.filter((u) => isStixRelationshipExceptRef(u.entity_type)).map((c) => c.standard_id);
  // Update all impacted entities
  logApp.info(`[OPENCTI] Merging impacting ${updateEntities.length} entities for ${targetEntity.internal_id}`);
  const updatesByEntity = R.groupBy((i) => i.id, updateEntities);
  const entries = Object.entries(updatesByEntity);
  let currentEntUpdateCount = 0;
  const updateBulkEntities = entries.filter(([, values]) => values.length === 1).map(([, values]) => values).flat();
  const groupsOfEntityUpdate = R.splitEvery(MAX_BULK_OPERATIONS, updateBulkEntities);
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
  // Take care of relations deletions to prevent duplicate marking definitions.
  const elementToRemoves = [...sourceEntities, ...fromDeletions, ...toDeletions];
  // All not move relations will be deleted, so we need to remove impacted rel in entities.
  const dependencyDeletions = await elDeleteElements(context, user, elementToRemoves, storeLoadByIdsWithRefs);
  // Everything if fine update remaining attributes
  const updateAttributes = [];
  // 1. Update all possible attributes
  const attributes = schemaAttributesDefinition.getAttributeNames(targetType);
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
    } else if (isMultipleAttribute(targetType, targetFieldKey)) {
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
  const data = await updateAttributeRaw(context, user, targetEntity, updateAttributes);
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

const loadMergeEntitiesDependencies = async (context, user, entityIds) => {
  const data = { [INTERNAL_FROM_FIELD]: [], [INTERNAL_TO_FIELD]: [] };
  for (let entityIndex = 0; entityIndex < entityIds.length; entityIndex += 1) {
    const entityId = entityIds[entityIndex];
    // Internal From
    const listFromCallback = async (elements) => {
      const findArgs = { toMap: true, baseData: true };
      const relTargets = await internalFindByIds(context, user, elements.map((rel) => rel.toId), findArgs);
      for (let index = 0; index < elements.length; index += 1) {
        const rel = elements[index];
        data[INTERNAL_FROM_FIELD].push({
          _index: relTargets[rel.toId]._index,
          internal_id: rel.toId,
          entity_type: rel.toType,
          name: rel.toName,
          i_relation: rel
        });
      }
    };
    const fromArgs = { baseData: true, fromId: entityId, callback: listFromCallback };
    await listAllRelations(context, user, ABSTRACT_STIX_RELATIONSHIP, fromArgs);
    // Internal to
    const listToCallback = async (elements) => {
      const findArgs = { toMap: true, baseData: true };
      const relSources = await internalFindByIds(context, user, elements.map((rel) => rel.fromId), findArgs);
      for (let index = 0; index < elements.length; index += 1) {
        const rel = elements[index];
        data[INTERNAL_TO_FIELD].push({
          _index: relSources[rel.fromId]._index,
          internal_id: rel.fromId,
          entity_type: rel.fromType,
          name: rel.fromName,
          i_relation: rel
        });
      }
    };
    const toArgs = { baseData: true, toId: entityId, callback: listToCallback };
    await listAllRelations(context, user, ABSTRACT_STIX_RELATIONSHIP, toArgs);
  }
  return data;
};

export const mergeEntities = async (context, user, targetEntityId, sourceEntityIds, opts = {}) => {
  // Pre-checks
  if (R.includes(targetEntityId, sourceEntityIds)) {
    throw FunctionalError('Cannot merge entities, same ID detected in source and destination', {
      targetEntityId,
      sourceEntityIds,
    });
  }
  logApp.info(`[OPENCTI] Merging ${sourceEntityIds} in ${targetEntityId}`);
  // targetEntity and sourceEntities must be accessible
  const mergedIds = [targetEntityId, ...sourceEntityIds];
  const mergedInstances = await internalFindByIds(context, user, mergedIds);
  if (mergedIds.length !== mergedInstances.length) {
    throw FunctionalError('Cannot access all entities for merging');
  }

  if (mergedInstances.some(({ entity_type, builtIn }) => entity_type === ENTITY_TYPE_VOCABULARY && Boolean(builtIn))) {
    throw FunctionalError('Cannot merge builtin vocabularies');
  }
  // We need to lock all elements not locked yet.
  const { locks = [] } = opts;
  const participantIds = mergedIds.filter((e) => !locks.includes(e));
  let lock;
  try {
    // Lock the participants that will be merged
    lock = await lockResource(participantIds);
    // Entities must be fully loaded with admin user to resolve/move all dependencies
    const initialInstance = await storeLoadByIdWithRefs(context, user, targetEntityId);
    const target = { ...initialInstance };
    const sources = await storeLoadByIdsWithRefs(context, SYSTEM_USER, sourceEntityIds);
    const sourcesDependencies = await loadMergeEntitiesDependencies(context, SYSTEM_USER, sources.map((s) => s.internal_id));
    const targetDependencies = await loadMergeEntitiesDependencies(context, SYSTEM_USER, [initialInstance.internal_id]);
    // - TRANSACTION PART
    lock.signal.throwIfAborted();
    const mergeImpacts = await mergeEntitiesRaw(context, user, target, sources, targetDependencies, sourcesDependencies, opts);
    const mergedInstance = await storeLoadByIdWithRefs(context, user, targetEntityId);
    await storeMergeEvent(context, user, initialInstance, mergedInstance, sources, mergeImpacts, opts);
    // Temporary stored the deleted elements to prevent concurrent problem at creation
    await redisAddDeletions(sources.map((s) => s.internal_id));
    // - END TRANSACTION
    return await storeLoadById(context, user, target.id, ABSTRACT_STIX_OBJECT).then((finalStixCoreObject) => {
      return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalStixCoreObject, user);
    });
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
  // Always ok for creator_id, need a stronger schema definition
  // Waiting for merge of https://github.com/OpenCTI-Platform/opencti/issues/1850
  if (key === 'creator_id') {
    return;
  }
  let masterKey = key;
  if (key.includes('.')) {
    const [firstPart] = key.split('.');
    masterKey = firstPart;
  }
  const entityAttributes = schemaAttributesDefinition.getAttributeNames(entityType);
  if (!R.includes(masterKey, entityAttributes)) {
    throw FunctionalError('This attribute key is not allowed, please check your registration attribute name', { key, entity_type: entityType });
  }
};
const innerUpdateAttribute = (instance, rawInput) => {
  const { key } = rawInput;
  // Check consistency
  checkAttributeConsistency(instance.entity_type, key);
  const input = rebuildAndMergeInputFromExistingData(rawInput, instance);
  if (R.isEmpty(input)) return [];
  const updatedInputs = [input];
  // Specific case for Report
  if (instance.entity_type === ENTITY_TYPE_CONTAINER_REPORT && key === 'published') {
    const createdInput = { key: 'created', value: input.value };
    updatedInputs.push(createdInput);
  }
  return updatedInputs;
};
const prepareAttributesForUpdate = (instance, elements, upsert) => {
  const instanceType = instance.entity_type;
  return elements.map((input) => {
    // Check integer
    if (isNumericAttribute(input.key)) {
      return {
        key: input.key,
        value: R.map((value) => {
          // Like at creation, we need to be sure that confidence is default to 0
          const baseValue = (input.key === confidence.name && isEmptyField(value)) ? 0 : value;
          const parsedValue = baseValue ? Number(baseValue) : baseValue;
          return Number.isNaN(parsedValue) ? null : parsedValue;
        }, input.value),
      };
    }
    // Check boolean
    if (isBooleanAttribute(input.key)) {
      return {
        key: input.key,
        value: R.map((value) => {
          return value === true || value === 'true';
        }, input.value),
      };
    }
    // Check dates for empty values
    if (dateForStartAttributes.includes(input.key)) {
      const emptyValue = isEmptyField(input.value) || isEmptyField(input.value.at(0));
      return {
        key: input.key,
        value: emptyValue ? [FROM_START_STR] : input.value,
      };
    }
    if (dateForEndAttributes.includes(input.key)) {
      const emptyValue = isEmptyField(input.value) || isEmptyField(input.value.at(0));
      return {
        key: input.key,
        value: emptyValue ? [UNTIL_END_STR] : input.value,
      };
    }
    // Specific case for Label
    if (input.key === VALUE_FIELD && instanceType === ENTITY_TYPE_LABEL) {
      return {
        key: input.key,
        value: input.value.map((v) => v.toLowerCase())
      };
    }
    // Specific case for name in aliased entities
    // If name change already inside aliases, name must be kep untouched
    if (upsert && input.key === NAME_FIELD && isStixObjectAliased(instanceType)) {
      const aliasField = resolveAliasesField(instanceType).name;
      const normalizeAliases = instance[aliasField] ? instance[aliasField].map((e) => normalizeName(e)) : [];
      const name = normalizeName(input.value.at(0));
      if ((normalizeAliases).includes(name)) {
        return null;
      }
    }
    // Aliases can't have the same name as entity name and an already existing normalized alias
    if (input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI) {
      const filteredValues = input.value.filter((e) => normalizeName(e) !== normalizeName(instance.name));
      const uniqAliases = R.uniqBy((e) => normalizeName(e), filteredValues);
      return {
        key: input.key,
        value: uniqAliases
      };
    }
    // No need to rework the input
    return input;
  }).filter((i) => isNotEmptyField(i));
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
  return isMultipleAttribute(instance.entity_type, key) ? data : [data];
};

const updateDateRangeValidation = (instance, inputs, from, to) => {
  const fromVal = R.head(R.find((e) => e.key === from, inputs)?.value || [instance[from]]);
  const toVal = R.head(R.find((e) => e.key === to, inputs)?.value || [instance[to]]);
  if (utcDate(fromVal) > utcDate(toVal)) {
    const data = { inputs, [from]: fromVal, [to]: toVal };
    throw DatabaseError(`You cant update an element with ${to} less than ${from}`, data);
  }
};
const updateAttributeRaw = async (context, user, instance, inputs, opts = {}) => {
  const today = now();
  // Upsert option is only useful to force aliases to be kept when upserting the entity
  const { impactStandardId = true, upsert = false } = opts;
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const instanceType = instance.entity_type;
  // Prepare attributes
  const preparedElements = prepareAttributesForUpdate(instance, elements, upsert);
  // region Check date range
  const inputKeys = inputs.map((i) => i.key);
  if (inputKeys.includes(START_TIME) || inputKeys.includes(STOP_TIME)) {
    updateDateRangeValidation(instance, preparedElements, START_TIME, STOP_TIME);
  }
  if (inputKeys.includes(FIRST_SEEN) || inputKeys.includes(LAST_SEEN)) {
    updateDateRangeValidation(instance, preparedElements, FIRST_SEEN, LAST_SEEN);
  }
  if (inputKeys.includes(VALID_FROM) || inputKeys.includes(VALID_UNTIL)) {
    updateDateRangeValidation(instance, preparedElements, VALID_FROM, VALID_UNTIL);
  }
  if (inputKeys.includes(FIRST_OBSERVED) || inputKeys.includes(LAST_OBSERVED)) {
    updateDateRangeValidation(instance, preparedElements, FIRST_OBSERVED, LAST_OBSERVED);
  }
  // endregion
  // region Some magic around aliases
  // If named entity name updated or alias are updated, modify the aliases ids
  if (isStixObjectAliased(instanceType)) {
    const aliasField = resolveAliasesField(instanceType).name;
    const nameInput = R.find((e) => e.key === NAME_FIELD, preparedElements);
    const aliasesInput = R.find((e) => e.key === aliasField, preparedElements);
    if (nameInput || aliasesInput) {
      const askedModificationName = nameInput ? R.head(nameInput.value) : undefined;
      // Cleanup the alias input.
      if (aliasesInput) {
        const preparedAliases = (aliasesInput.value ?? [])
          .filter((a) => isNotEmptyField(a))
          .filter((a) => normalizeName(a) !== normalizeName(instance.name)
              && normalizeName(a) !== normalizeName(askedModificationName))
          .map((a) => a.trim());
        aliasesInput.value = R.uniqBy((e) => normalizeName(e), preparedAliases);
      }
      // In case of upsert name change, old name must be pushed in aliases
      // If aliases are also ask for modification, we need to change the input
      if (askedModificationName && normalizeName(instance.name) !== normalizeName(askedModificationName)) {
        // If name change, we need to add the old name in aliases
        const aliases = [...(instance[aliasField] ?? [])];
        if (upsert) {
          // For upsert, we concatenate everything to be none destructive
          aliases.push(...(aliasesInput ? aliasesInput.value : []));
          if (!aliases.includes(instance.name)) {
            // If name changing is part of an upsert, the previous name must be copied into aliases
            aliases.push(instance.name);
          }
          const uniqAliases = R.uniqBy((e) => normalizeName(e), aliases);
          if (aliasesInput) { // If aliases input also exists
            aliasesInput.value = uniqAliases;
          } else { // We need to create an extra input getting existing aliases
            const generatedAliasesInput = { key: aliasField, value: uniqAliases };
            preparedElements.push(generatedAliasesInput);
          }
        } else if (!aliasesInput) {
          // Name change can create a duplicate with aliases
          // If it's the case aliases must be also patched.
          const currentAliases = instance[aliasField] || [];
          const targetAliases = currentAliases.filter((a) => a !== askedModificationName);
          if (currentAliases.length !== targetAliases.length) {
            const generatedAliasesInput = { key: aliasField, value: targetAliases };
            preparedElements.push(generatedAliasesInput);
          }
        }
        // Regenerated the internal ids with the instance target aliases
        const aliasesId = generateAliasesId(R.uniq([askedModificationName, ...aliases]), instance);
        const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
        preparedElements.push(aliasInput);
      } else if (aliasesInput) {
        // No name change asked but aliases addition
        if (upsert) {
          // In upsert we cumulate with current aliases
          aliasesInput.value = R.uniqBy((e) => normalizeName(e), [...aliasesInput.value, ...(instance[aliasField] || [])]);
        }
        // Internal ids alias must be generated again
        const aliasesId = generateAliasesId(R.uniq([instance.name, ...aliasesInput.value]), instance);
        const aliasIdsInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
        preparedElements.push(aliasIdsInput);
      }
    }
  }
  // endregion
  // region Artifact and file additional names
  // In case of artifact and file, we need to keep name in additional names in case of upsert
  const isNamedObservable = instanceType === ENTITY_HASHED_OBSERVABLE_ARTIFACT || instanceType === ENTITY_HASHED_OBSERVABLE_STIX_FILE;
  if (upsert && isNamedObservable) {
    const nameInput = R.find((e) => e.key === NAME_FIELD, preparedElements);
    // In Upsert mode, x_opencti_additional_names update must not be destructive, previous names must be kept
    const additionalNamesInput = R.find((e) => e.key === ATTRIBUTE_ADDITIONAL_NAMES, preparedElements);
    if (additionalNamesInput) {
      const names = [...additionalNamesInput.value, ...(instance[ATTRIBUTE_ADDITIONAL_NAMES] ?? [])];
      if (nameInput) { // If name will be replaced, add it in additional names
        names.push(instance[NAME_FIELD]);
      }
      additionalNamesInput.value = R.uniq(names);
    } else if (nameInput) { // If name will be replaced, add it in additional names
      const newAdditional = [instance[NAME_FIELD], ...(instance[ATTRIBUTE_ADDITIONAL_NAMES] ?? [])];
      const addNamesInput = { key: ATTRIBUTE_ADDITIONAL_NAMES, value: R.uniq(newAdditional) };
      preparedElements.push(addNamesInput);
    }
  }
  // endregion
  // region Standard id impact
  // If update is part of the key, update the standard_id
  const keys = R.map((t) => t.key, preparedElements);
  if (impactStandardId && isFieldContributingToStandardId(instance, keys)) {
    const updatedInstance = mergeInstanceWithUpdateInputs(instance, preparedElements);
    // const updatedInstance = mergeInstanceWithInputs(instance, preparedElements);
    const standardId = generateStandardId(instanceType, updatedInstance);
    if (instance.standard_id !== standardId) {
      // In some condition the impacted element will not generate a new standard.
      // It's the case of HASH for example. If SHA1 is added after MD5, it's an impact without actual change
      preparedElements.push({ key: ID_STANDARD, value: [standardId] });
    }
    // For stix element, looking for keeping old stix ids
    if (isStixCyberObservable(instance.entity_type)) {
      // Standard id is generated from data depending on multiple ways and multiple attributes
      if (isStandardIdUpgraded(instance, updatedInstance)) {
        // If update already contains a change of the other stix ids
        // we need to impact directly the impacted and updated related input
        const stixInput = R.find((e) => e.key === IDS_STIX, preparedElements);
        if (stixInput) {
          stixInput.value = R.uniq([...stixInput.value, instance.standard_id]);
        } else {
          // If no stix ids modification, add the standard id in the list and patch the element
          const ids = R.uniq([...(instance[IDS_STIX] ?? []), instance.standard_id]);
          preparedElements.push({ key: IDS_STIX, value: ids });
        }
      } else if (isStandardIdDowngraded(instance, updatedInstance)) {
        // If standard_id is downgraded, we need to remove the old one from the other stix ids
        const stixInput = R.find((e) => e.key === IDS_STIX, preparedElements);
        if (stixInput) {
          stixInput.operation = UPDATE_OPERATION_REPLACE;
          stixInput.value = stixInput.value.filter((i) => i !== standardId);
        } else {
          // In case of downgrade we purge the other stix ids.
          preparedElements.push({ key: IDS_STIX, value: [] });
        }
      }
    }
  }
  // endregion
  // If is valid_until modification, update also revoked if needed
  const validUntilInput = R.find((e) => e.key === VALID_UNTIL, preparedElements);
  if (validUntilInput) {
    const untilDate = R.head(validUntilInput.value);
    const untilDateTime = utcDate(untilDate).toDate();
    const nowDate = utcDate().toDate();
    const isMustBeRevoked = untilDateTime < nowDate;
    const revokedInput = R.find((e) => e.key === REVOKED, preparedElements);
    if (!revokedInput) {
      preparedElements.push({ key: REVOKED, value: [isMustBeRevoked] });
    }
    const detectionInput = R.find((e) => e.key === X_DETECTION, preparedElements);
    if (!detectionInput && instance.entity_type === ENTITY_TYPE_INDICATOR && untilDateTime <= nowDate) {
      preparedElements.push({ key: X_DETECTION, value: [false] });
    }
  }
  // Update all needed attributes with inner elements if needed
  const updatedInputs = [];
  const impactedInputs = [];
  const isWorkflowChange = inputKeys.includes(X_WORKFLOW_ID);
  const platformStatuses = isWorkflowChange ? await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS) : [];
  for (let index = 0; index < preparedElements.length; index += 1) {
    const input = preparedElements[index];
    const ins = innerUpdateAttribute(instance, input);
    if (ins.length > 0) {
      const filteredIns = ins.filter((o) => {
        if (o.key === IDS_STIX) {
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
        }
        // Updated inputs must not be internals
        return !o.key.startsWith('i_') && o.key !== 'x_opencti_graph_data';
      });
      if (filteredIns.length > 0) {
        const updatedInputsFiltered = filteredIns.map((filteredInput) => {
          // TODO JRI Rework that part
          const previous = getPreviousInstanceValue(filteredInput.key, instance);
          // Specific input resolution for workflow
          if (filteredInput.key === X_WORKFLOW_ID) {
            // workflow_id is not a relation but message must contain the name and not the internal id
            const workflowId = R.head(filteredInput.value);
            const workflowStatus = workflowId ? platformStatuses.find((p) => p.id === workflowId) : workflowId;
            return {
              operation: filteredInput.operation,
              key: filteredInput.key,
              value: [workflowStatus ? workflowStatus.name : null],
              previous,
            };
          }
          // Check symmetric difference for add and remove
          if (filteredInput.operation === UPDATE_OPERATION_ADD || filteredInput.operation === UPDATE_OPERATION_REMOVE) {
            return {
              operation: filteredInput.operation,
              key: filteredInput.key,
              value: R.symmetricDifference(previous ?? [], filteredInput.value ?? []),
              previous,
            };
          }
          // For replace, if its a complex object, do a simple diff
          if (filteredInput.operation === UPDATE_OPERATION_REPLACE && isObjectAttribute(filteredInput.key)) {
            return {
              operation: filteredInput.operation,
              key: filteredInput.key,
              value: R.difference(filteredInput.value ?? [], previous ?? []),
              previous,
            };
          }
          // For simple values, just keep everything in the replace
          return { ...filteredInput, previous };
        });
        updatedInputs.push(...updatedInputsFiltered);
      }
      impactedInputs.push(...ins);
    }
  }
  // Impact the updated_at only if stix data is impacted
  // In case of upsert, this addition will be supported by the parent function
  if (impactedInputs.length > 0 && isUpdatedAtObject(instance.entity_type)) {
    const updatedAtInput = { key: 'updated_at', value: [today] };
    impactedInputs.push(updatedAtInput);
  }
  if (impactedInputs.length > 0 && isModifiedObject(instance.entity_type)) {
    const modifiedAtInput = { key: 'modified', value: [today] };
    impactedInputs.push(modifiedAtInput);
  }
  return {
    updatedInputs, // Sourced inputs for event stream
    impactedInputs, // All inputs that need to be re-indexed. (so without meta relationships)
    updatedInstance: mergeInstanceWithInputs(instance, impactedInputs),
  };
};

export const updateAttributeMetaResolved = async (context, user, initial, inputs, opts = {}) => {
  const { locks = [], impactStandardId = true } = opts;
  const updates = Array.isArray(inputs) ? inputs : [inputs];
  // Region - Pre-Check
  const elementsByKey = R.groupBy((e) => e.key, updates);
  const multiOperationKeys = Object.values(elementsByKey).filter((n) => n.length > 1);
  if (multiOperationKeys.length > 1) {
    throw UnsupportedError('We cant update the same attribute multiple times in the same operation');
  }
  const references = opts.references ? await internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) : [];
  if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
    throw FunctionalError('Cant find element references for commit', { id: initial.internal_id, references: opts.references });
  }
  // Validate input attributes
  const entitySetting = await getEntitySettingFromCache(context, initial.entity_type);
  await validateInputUpdate(context, user, initial.entity_type, initial, updates, entitySetting);
  // Endregion
  // Individual check
  const { bypassIndividualUpdate } = opts;
  if (initial.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL && !isEmptyField(initial.contact_information) && !bypassIndividualUpdate) {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: 'user_email', values: [initial.contact_information] }],
        filterGroups: [],
      },
      noFiltersChecking: true,
      connectionFormat: false
    };
    const users = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], args);
    if (users.length > 0) {
      throw FunctionalError('Cannot update an individual corresponding to a user');
    }
  }
  if (updates.length === 0) {
    return { element: initial };
  }
  // Check user access update
  const manageAccessUpdate = updates.some((e) => e.key === 'authorized_members');
  if (!validateUserAccessOperation(user, initial, manageAccessUpdate ? 'manage-access' : 'edit')) {
    throw ForbiddenAccess();
  }
  // Split attributes and meta
  // Supports inputs meta or stix meta
  const metaKeys = [...schemaRelationsRefDefinition.getStixNames(initial.entity_type), ...schemaRelationsRefDefinition.getInputNames(initial.entity_type)];
  const meta = updates.filter((e) => metaKeys.includes(e.key));
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  const updated = mergeInstanceWithUpdateInputs(initial, inputs);
  const keys = R.map((t) => t.key, attributes);
  if (opts.bypassValidation !== true) { // Allow creation directly from the back-end
    const isAllowedToByPass = isUserHasCapability(user, BYPASS_REFERENCE);
    if (!isAllowedToByPass && entitySetting?.enforce_reference) {
      const isNoReferenceKey = noReferenceAttributes.includes(R.head(keys)) && keys.length === 1;
      if (!isNoReferenceKey && isEmptyField(opts.references)) {
        throw ValidationError('references', { message: 'You must provide at least one external reference to update' });
      }
    }
  }
  let locksIds = getInstanceIds(initial);
  // 01. Check if updating alias lead to entity conflict
  if (isStixObjectAliased(initial.entity_type)) {
    // If user ask for aliases modification, we need to check if it not already belong to another entity.
    const isInputAliases = (input) => input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI;
    const aliasedInputs = R.filter((input) => isInputAliases(input), attributes);
    if (aliasedInputs.length > 0) {
      const aliases = R.uniq(aliasedInputs.map((a) => a.value).flat().filter((a) => isNotEmptyField(a)).map((a) => a.trim()));
      const aliasesIds = generateAliasesId(aliases, initial);
      const existingEntities = await internalFindByIds(context, user, aliasesIds, { type: initial.entity_type });
      const differentEntities = R.filter((e) => e.internal_id !== initial.internal_id, existingEntities);
      if (differentEntities.length > 0) {
        throw FunctionalError('This update will produce a duplicate', {
          id: initial.internal_id,
          type: initial.entity_type,
          existingIds: existingEntities.map((e) => e.id),
        });
      }
    }
  }
  // 02. Check if this update is not resulting to an entity merging
  let eventualNewStandardId = null;
  const standardIdImpacted = impactStandardId && isFieldContributingToStandardId(initial, keys);
  if (standardIdImpacted) {
    // In this case we need to reconstruct the data like if an update already appears
    // Based on that we will be able to generate the correct standard id
    locksIds = getInstanceIds(updated); // Take lock ids on the new merged initial.
    const targetStandardId = generateStandardId(initial.entity_type, updated);
    if (targetStandardId !== initial.standard_id && !(initial[IDS_STIX] ?? []).includes(targetStandardId)) {
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
      existingEntityPromise = internalLoadById(context, user, eventualNewStandardId);
    }
    if (isStixCyberObservableHashedObservable(initial.entity_type)) {
      existingByHashedPromise = listEntitiesByHashes(context, user, initial.entity_type, updated.hashes)
        .then((entities) => entities.filter((e) => e.id !== initial.internal_id));
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
      if (isStixCyberObservable(initial.entity_type)) {
        // Everything ok, let merge
        hashMergeValidation([updated, ...existingEntities]);
        const sourceEntityIds = existingEntities.map((c) => c.internal_id);
        const merged = await mergeEntities(context, user, updated.internal_id, sourceEntityIds, { locks: participantIds });
        // Then apply initial updates on merged result
        return updateAttributeMetaResolved(context, user, merged, updates, { ...opts, locks: participantIds });
      }
      // noinspection ExceptionCaughtLocallyJS
      throw FunctionalError('This update will produce a duplicate', {
        id: initial.id,
        type: initial.entity_type,
        existingIds: existingEntities.map((e) => e.id),
      });
    }
    // noinspection UnnecessaryLocalVariableJS
    const data = await updateAttributeRaw(context, user, initial, attributes, opts);
    const { updatedInstance, impactedInputs, updatedInputs } = data;
    // Check the consistency of the observable.
    if (isStixCyberObservable(updatedInstance.entity_type)) {
      const observableSyntaxResult = checkObservableSyntax(updatedInstance.entity_type, updatedInstance);
      if (observableSyntaxResult !== true) {
        throw FunctionalError('Observable of is not correctly formatted', { id: initial.internal_id, type: initial.entity_type });
      }
    }
    lock.signal.throwIfAborted();
    if (impactedInputs.length > 0) {
      const updateAsInstance = partialInstanceWithInputs(updatedInstance, impactedInputs);
      await elUpdateElement(updateAsInstance);
    }
    // endregion
    // region metas
    const relationsToCreate = [];
    const relationsToDelete = [];
    const buildInstanceRelTo = (to, relType) => buildInnerRelation(initial, to, relType);
    for (let metaIndex = 0; metaIndex < meta.length; metaIndex += 1) {
      const { key: metaKey } = meta[metaIndex];
      const key = schemaRelationsRefDefinition.convertStixNameToInputName(updatedInstance.entity_type, metaKey) || metaKey;
      const relDef = schemaRelationsRefDefinition.getRelationRef(updatedInstance.entity_type, key);
      const relType = relDef.databaseName;
      // ref and _refs are expecting direct identifier in the value
      // We dont care about the operation here, the only thing we can do is replace
      if (!relDef.multiple) {
        const currentValue = updatedInstance[key];
        const { value: targetsCreated } = meta[metaIndex];
        const targetCreated = R.head(targetsCreated);
        // If asking for a real change
        if (currentValue?.standard_id !== targetCreated?.internal_id && currentValue?.id !== targetCreated?.internal_id) {
          // Delete the current relation
          if (currentValue?.standard_id) {
            const currentRels = await listAllRelations(context, user, relType, { fromId: initial.id });
            relationsToDelete.push(...currentRels);
          }
          // Create the new one
          if (isNotEmptyField(targetCreated)) {
            relationsToCreate.push(...buildInstanceRelTo(targetCreated, relType));
            const previous = currentValue ? [currentValue] : currentValue;
            updatedInputs.push({ key, value: [targetCreated], previous });
            updatedInstance[key] = targetCreated;
          } else if (currentValue) {
            // Just replace by nothing
            updatedInputs.push({ key, value: null, previous: [currentValue] });
            updatedInstance[key] = null;
          }
        }
      } else {
        // Special access check for RELATION_GRANTED_TO meta
        if (relType === RELATION_GRANTED_TO && !isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
          throw ForbiddenAccess();
        }
        let { value: refs, operation = UPDATE_OPERATION_REPLACE } = meta[metaIndex];
        if (relType === RELATION_OBJECT_MARKING) {
          const markingsCleaned = await handleMarkingOperations(context, initial.objectMarking, refs, operation);
          ({ operation, refs } = { operation: markingsCleaned.operation, refs: markingsCleaned.refs });
        }
        if (operation === UPDATE_OPERATION_REPLACE) {
          // Delete all relations
          const currentRels = await listAllRelations(context, user, relType, { fromId: initial.internal_id });
          const currentRelsToIds = currentRels.map((n) => n.toId);
          const newTargetsIds = refs.map((n) => n.id);
          if (R.symmetricDifference(newTargetsIds, currentRelsToIds).length > 0) {
            if (currentRels.length > 0) {
              relationsToDelete.push(...currentRels);
            }
            // 02. Create the new relations
            if (refs.length > 0) {
              const newRelations = buildInstanceRelTo(refs, relType);
              relationsToCreate.push(...newRelations);
            }
            updatedInputs.push({ key, value: refs, previous: updatedInstance[key] });
            updatedInstance[key] = refs;
          }
        }
        if (operation === UPDATE_OPERATION_ADD) {
          const currentIds = (updatedInstance[key] || []).map((o) => [o.id, o.standard_id]).flat();
          const refsToCreate = refs.filter((r) => !currentIds.includes(r.internal_id));
          if (refsToCreate.length > 0) {
            const newRelations = buildInstanceRelTo(refsToCreate, relType);
            relationsToCreate.push(...newRelations);
            updatedInputs.push({ key, value: refsToCreate, operation });
            updatedInstance[key] = [...(updatedInstance[key] || []), ...refsToCreate];
          }
        }
        if (operation === UPDATE_OPERATION_REMOVE) {
          const targetIds = refs.map((t) => t.internal_id);
          const currentRels = await listAllRelations(context, user, relType, { fromId: initial.internal_id });
          const relsToDelete = currentRels.filter((c) => targetIds.includes(c.toId));
          if (relsToDelete.length > 0) {
            relationsToDelete.push(...relsToDelete);
            updatedInputs.push({ key, value: refs, operation });
            updatedInstance[key] = (updatedInstance[key] || []).filter((c) => !targetIds.includes(c.internal_id));
          }
        }
      }
    }
    if (relationsToDelete.length > 0) {
      await elDeleteElements(context, user, relationsToDelete);
    }
    if (relationsToCreate.length > 0) {
      await elIndexElements(context, user, initial.entity_type, relationsToCreate);
    }
    // endregion
    // Post-operation to update the individual linked to a user
    if (updatedInstance.entity_type === ENTITY_TYPE_USER) {
      const args = {
        filters: {
          mode: 'and',
          filters: [{ key: 'contact_information', values: [updatedInstance.user_email] }],
          filterGroups: [],
        },
        noFiltersChecking: true,
        connectionFormat: false
      };
      const individuals = await listEntities(context, user, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], args);
      if (individuals.length > 0) {
        const individualId = R.head(individuals).id;
        const patch = {
          contact_information: updatedInstance.user_email,
          name: updatedInstance.name,
          x_opencti_firstname: updatedInstance.firstname,
          x_opencti_lastname: updatedInstance.lastname
        };
        await patchAttribute(context, user, individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL, patch, { bypassIndividualUpdate: true });
      }
    }
    // Only push event in stream if modifications really happens
    if (updatedInputs.length > 0) {
      const message = await generateUpdateMessage(context, updatedInstance.entity_type, updatedInputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage,
        external_references: references.map((ref) => convertExternalReferenceToStix(ref))
      } : undefined;
      const event = await storeUpdateEvent(context, user, initial, updatedInstance, message, { ...opts, commit });
      return { element: updatedInstance, event, isCreation: false };
    }
    // Return updated element after waiting for it.
    return { element: updatedInstance, event: null, isCreation: false };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const updateAttributeFromLoadedWithRefs = async (context, user, initial, inputs, opts = {}) => {
  if (!initial) {
    throw FunctionalError('Cant update undefined element');
  }
  const updates = Array.isArray(inputs) ? inputs : [inputs];
  const metaKeys = [...schemaRelationsRefDefinition.getStixNames(initial.entity_type), ...schemaRelationsRefDefinition.getInputNames(initial.entity_type)];
  const meta = updates.filter((e) => metaKeys.includes(e.key));
  const metaIds = R.uniq(meta.map((i) => i.value ?? []).flat());
  const metaDependencies = await elFindByIds(context, user, metaIds, { toMap: true, mapWithAllIds: true });
  const revolvedInputs = updates.map((input) => {
    if (metaKeys.includes(input.key)) {
      const resolvedValues = (input.value ?? []).map((refId) => metaDependencies[refId]).filter((o) => isNotEmptyField(o));
      return { ...input, value: resolvedValues };
    }
    return input;
  });
  return updateAttributeMetaResolved(context, user, initial, revolvedInputs, opts);
};

export const updateAttribute = async (context, user, id, type, inputs, opts = {}) => {
  const initial = await storeLoadByIdWithRefs(context, user, id, { type });
  if (!initial) {
    throw FunctionalError('Cant find element to update', { id, type });
  }
  return updateAttributeFromLoadedWithRefs(context, user, initial, inputs, opts);
};

export const patchAttribute = async (context, user, id, type, patch, opts = {}) => {
  const inputs = transformPatchToInput(patch, opts.operations);
  return updateAttribute(context, user, id, type, inputs, opts);
};
// endregion

// region rules
const getAllRulesField = (instance, field) => {
  return Object.keys(instance)
    .filter((key) => key.startsWith(RULE_PREFIX))
    .map((key) => instance[key])
    .filter((rule) => isNotEmptyField(rule)) // Rule can have been already reset
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
  // list supported attributes [{name: string, operation: string}] by entity type
  const supportedAttributes = RULES_ATTRIBUTES_BEHAVIOR.supportedAttributes(instance.entity_type);
  for (let index = 0; index < supportedAttributes.length; index += 1) {
    const supportedAttribute = supportedAttributes[index];
    const attribute = supportedAttribute.name;
    const values = getAllRulesField(instance, attribute);
    if (values.length > 0) {
      const { operation } = supportedAttribute;
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
const upsertEntityRule = async (context, instance, input, opts = {}) => {
  logApp.info('Upsert inferred entity', { input });
  const { fromRule } = opts;
  const updatedRule = input[fromRule];
  const rulePatch = { [fromRule]: updatedRule };
  const ruleInstance = R.mergeRight(instance, rulePatch);
  const innerPatch = createRuleDataPatch(ruleInstance);
  const patch = { ...rulePatch, ...innerPatch };
  return patchAttribute(context, RULE_MANAGER_USER, instance.id, instance.entity_type, patch, opts);
};
const upsertRelationRule = async (context, instance, input, opts = {}) => {
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
  logApp.info('Upsert inferred relation', { id: instance.id, relation: patch });
  return await patchAttribute(context, RULE_MANAGER_USER, instance.id, instance.entity_type, patch, opts);
};
// endregion

export const fillDefaultValues = (user, input, entitySetting) => {
  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (!attributesConfiguration) {
    return input;
  }
  const filledValues = new Map();
  attributesConfiguration.filter((attr) => attr.default_values)
    .filter((attr) => INPUT_MARKINGS !== attr.name)
    .forEach((attr) => {
      if (input[attr.name] === undefined || input[attr.name] === null) { // empty is a valid value
        const defaultValue = getDefaultValues(attr, schemaAttributesDefinition.isMultipleAttribute(entitySetting.target_type, attr.name));

        if (attr.name === INPUT_AUTHORIZED_MEMBERS && defaultValue) {
          const defaultAuthorizedMembers = defaultValue.map((v) => JSON.parse(v));
          // Replace dynamic creator rule with the id of the user making the query.
          const creatorRule = defaultAuthorizedMembers.find((v) => v.id === MEMBER_ACCESS_CREATOR);
          if (creatorRule) {
            creatorRule.id = user.id;
          }
          filledValues.set(attr.name, defaultAuthorizedMembers);
        } else {
          filledValues.set(attr.name, defaultValue);
        }
      }
    });

  // Marking management
  if (input[INPUT_MARKINGS] === undefined || input[INPUT_MARKINGS] === null) { // empty is a valid value
    const defaultMarkings = user.default_marking ?? [];
    const globalDefaultMarking = (defaultMarkings.find((entry) => entry.entity_type === 'GLOBAL')?.values ?? []).map((m) => m.id);
    if (!isEmptyField(globalDefaultMarking)) {
      filledValues.set(INPUT_MARKINGS, globalDefaultMarking);
    }
  }
  return { ...input, ...Object.fromEntries(filledValues) };
};

const validateEntityAndRelationCreation = async (context, user, input, type, entitySetting, opts = {}) => {
  if (opts.bypassValidation !== true) { // Allow creation directly from the back-end
    const isAllowedToByPass = isUserHasCapability(user, BYPASS_REFERENCE);
    if (!isAllowedToByPass && entitySetting?.enforce_reference) {
      if (isEmptyField(input.externalReferences)) {
        throw ValidationError('externalReferences', {
          message: 'You must provide at least one external reference for this type of entity/relationship',
        });
      }
    }
    await validateInputCreation(context, user, type, input, entitySetting);
  }
};

// region mutation relation
const buildRelationInput = (input) => {
  const { from, relationship_type: relationshipType } = input;
  // 03. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(relationshipType, input);
  // 05. Prepare the relation to be created
  const today = now();
  const relationAttributes = {};
  relationAttributes._index = inferIndexFromConceptType(relationshipType);
  // basic-relationship
  relationAttributes.internal_id = internalId;
  relationAttributes.standard_id = standardId;
  relationAttributes.entity_type = relationshipType;
  relationAttributes.relationship_type = relationshipType;
  relationAttributes.created_at = today;
  relationAttributes.updated_at = today;
  // stix-relationship
  if (isStixRelationshipExceptRef(relationshipType)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    relationAttributes.x_opencti_stix_ids = stixIds;
    relationAttributes.revoked = R.isNil(input.revoked) ? false : input.revoked;
    relationAttributes.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
    relationAttributes.lang = R.isNil(input.lang) ? 'en' : input.lang;
    relationAttributes.created = R.isNil(input.created) ? today : input.created;
    relationAttributes.modified = R.isNil(input.modified) ? today : input.modified;
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    relationAttributes.description = R.isNil(input.description) ? null : input.description;
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    //* v8 ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with stop_time less than start_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-ref-relationship
  if (isStixRefRelationship(relationshipType) && schemaRelationsRefDefinition.isDatable(from.entity_type, relationshipType)) {
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    relationAttributes.created = R.isNil(input.created) ? today : input.created;
    relationAttributes.modified = R.isNil(input.modified) ? today : input.modified;
    //* v8 ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with stop_time less than start_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-sighting-relationship
  if (isStixSightingRelationship(relationshipType)) {
    relationAttributes.description = R.isNil(input.description) ? null : input.description;
    relationAttributes.attribute_count = R.isNil(input.attribute_count) ? 1 : input.attribute_count;
    relationAttributes.x_opencti_negative = R.isNil(input.x_opencti_negative) ? false : input.x_opencti_negative;
    relationAttributes.first_seen = R.isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen;
    relationAttributes.last_seen = R.isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen;
    //* v8 ignore if */
    if (relationAttributes.first_seen > relationAttributes.last_seen) {
      throw DatabaseError('You cant create a relation with a first_seen greater than the last_seen', {
        from: input.fromId,
        input,
      });
    }
  }
  return { relation: relationAttributes };
};
const buildInnerRelation = (from, to, type) => {
  const targets = Array.isArray(to) ? to : [to];
  if (!to || R.isEmpty(targets)) {
    return [];
  }
  const relations = [];
  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i];
    const input = { from, to: target, relationship_type: type };
    const { relation } = buildRelationInput(input);
    // Ignore self relationships
    if (from.internal_id !== target.internal_id) {
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
      relations.push(basicRelation);
    }
  }
  return relations;
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
const buildAttributeUpdate = (isFullSync, attribute, currentData, inputData) => {
  const inputs = [];
  const fieldKey = attribute.name;
  if (isDictionaryAttribute(fieldKey)) {
    if (isNotEmptyField(inputData)) {
      // In standard mode, just patch inner dictionary keys
      const inputEntries = Object.entries(inputData);
      inputEntries.forEach(([k, v]) => {
        inputs.push({ key: `${fieldKey}.${k}`, value: [v] });
      });
      if (isFullSync && isNotEmptyField(currentData)) {
        const inputDictMap = new Map(inputEntries);
        Object.entries(currentData).forEach(([k]) => {
          if (!inputDictMap.has(k)) { // If known, replace
            inputs.push({ key: `${fieldKey}.${k}`, value: [null] });
          }
        });
      }
    } else if (isFullSync) { // We only allowed removal for full synchronization
      inputs.push({ key: fieldKey, value: [inputData] });
    }
  } else if (attribute.multiple) {
    const operation = isFullSync ? UPDATE_OPERATION_REPLACE : UPDATE_OPERATION_ADD;
    // Only add input in case of replace or when we really need to add something
    if (operation === UPDATE_OPERATION_REPLACE || (operation === UPDATE_OPERATION_ADD && isNotEmptyField(inputData))) {
      inputs.push({ key: fieldKey, value: inputData, operation });
    }
  } else {
    inputs.push({ key: fieldKey, value: [inputData] });
  }
  return inputs;
};
const buildTimeUpdate = (input, instance, startField, stopField) => {
  const inputs = [];
  // If not coming from a rule, compute extended time.
  if (input[startField]) {
    const extendedStart = computeExtendedDateValues(input[startField], instance[startField], ALIGN_OLDEST);
    if (extendedStart) {
      inputs.push({ key: startField, value: [extendedStart] });
    }
  }
  if (input[stopField]) {
    const extendedStop = computeExtendedDateValues(input[stopField], instance[stopField], ALIGN_NEWEST);
    if (extendedStop) {
      inputs.push({ key: stopField, value: [extendedStop] });
    }
  }
  return inputs;
};
const buildRelationDeduplicationFilter = (input) => {
  const args = {};
  const { from, relationship_type: relationshipType, createdBy } = input;
  const deduplicationConfig = conf.get('relations_deduplication') ?? {
    past_days: 30,
    next_days: 30,
    created_by_based: false,
    types_overrides: {}
  };
  const config = deduplicationConfig.types_overrides?.[relationshipType] ?? deduplicationConfig;
  if (config.created_by_based && createdBy) {
    args.relationFilter = { relation: RELATION_CREATED_BY, id: createdBy.id };
  }
  const prepareBeginning = (key) => prepareDate(moment(input[key]).subtract(config.past_days, 'days').utc());
  const prepareStopping = (key) => prepareDate(moment(input[key]).add(config.next_days, 'days').utc());
  // Prepare for stix core
  if (isStixCoreRelationship(relationshipType)) {
    if (!R.isNil(input.start_time)) {
      args.startTimeStart = prepareBeginning('start_time');
      args.startTimeStop = prepareStopping('start_time');
    }
    if (!R.isNil(input.stop_time)) {
      args.stopTimeStart = prepareBeginning('stop_time');
      args.stopTimeStop = prepareStopping('stop_time');
    }
  }
  // Prepare for stix ref
  if (isStixRefRelationship(relationshipType) && schemaRelationsRefDefinition.isDatable(from.entity_type, relationshipType)) {
    if (!R.isNil(input.start_time)) {
      args.startTimeStart = prepareBeginning('start_time');
      args.startTimeStop = prepareStopping('start_time');
    }
    if (!R.isNil(input.stop_time)) {
      args.stopTimeStart = prepareBeginning('stop_time');
      args.stopTimeStop = prepareStopping('stop_time');
    }
  }
  // Prepare for stix sighting
  if (isStixSightingRelationship(relationshipType)) {
    if (!R.isNil(input.first_seen)) {
      args.firstSeenStart = prepareBeginning('first_seen');
      args.firstSeenStop = prepareStopping('first_seen');
    }
    if (!R.isNil(input.last_seen)) {
      args.lastSeenStart = prepareBeginning('last_seen');
      args.lastSeenStop = prepareStopping('last_seen');
    }
  }
  return args;
};

export const buildDynamicFilterArgsContent = (inputFilters) => {
  const { filters = [], filterGroups = [] } = inputFilters;
  // 01. Handle filterGroups
  const dynamicFilterGroups = [];
  for (let index = 0; index < filterGroups.length; index += 1) {
    const group = filterGroups[index];
    const dynamicGroup = buildDynamicFilterArgsContent(group);
    dynamicFilterGroups.push(dynamicGroup);
  }
  // 02. Handle filters
  // Currently, filters are not supported the way we handle elementId and relationship_type in domain/stixCoreObject/findAll
  // We need to rebuild the filters
  // Extract elementId and relationship_type
  const elementId = R.head(filters
    .filter((n) => (Array.isArray(n.key)
      ? R.head(n.key) === 'rel_*.internal_id'
      : n.key === 'rel_*.internal_id')))?.values || null;
  const relationship_type = R.head(filters.filter((n) => (Array.isArray(n.key) ? R.head(n.key) === 'relationship_type' : n.key === 'relationship_type')))?.values || null;
  // Build filter without it
  let dynamicFilters = filters.filter((n) => !['rel_*.internal_id', 'relationship_type'].includes(Array.isArray(n.key) ? R.head(n.key) : n.key));
  if (isNotEmptyField(elementId)) {
    // In case of element id, we look for a specific entity used by relationships independent of the direction
    // To do that we need to lookup the element inside the rel_ fields that represent the relationships connections
    // that are denormalized at relation creation.
    // If relation types are also in the query, we filter on specific rel_[TYPE], if not, using a wilcard.
    if (isNotEmptyField(relationship_type)) {
      const relationshipFilterKeys = relationship_type.map((n) => buildRefRelationKey(n));
      dynamicFilters = [...dynamicFilters, {
        key: relationshipFilterKeys,
        values: Array.isArray(elementId) ? elementId : [elementId]
      }];
    } else {
      dynamicFilters = [...dynamicFilters, {
        key: buildRefRelationKey('*'),
        values: Array.isArray(elementId) ? elementId : [elementId]
      }];
    }
  }
  return {
    mode: inputFilters.mode ?? 'and',
    filters: dynamicFilters,
    filterGroups: dynamicFilterGroups,
  };
};
export const buildDynamicFilterArgs = (inputFilters) => {
  const filters = buildDynamicFilterArgsContent(inputFilters);
  return { connectionFormat: false, first: 500, filters };
};

const upsertElement = async (context, user, element, type, updatePatch, opts = {}) => {
  const inputs = []; // All inputs impacted by modifications (+inner)
  // -- Independent update
  // Handle attributes updates
  if (isNotEmptyField(updatePatch.stix_id) || isNotEmptyField(updatePatch.x_opencti_stix_ids)) {
    const ids = [...(updatePatch.x_opencti_stix_ids || [])];
    if (isNotEmptyField(updatePatch.stix_id) && updatePatch.stix_id !== element.standard_id) {
      ids.push(updatePatch.stix_id);
    }
    if (ids.length > 0) {
      inputs.push({ key: 'x_opencti_stix_ids', value: ids, operation: UPDATE_OPERATION_ADD });
    }
  }
  // Add support for existing creator_id that can be a simple string except of an array
  const creatorIds = [];
  if (isNotEmptyField(element.creator_id)) {
    const idCreators = Array.isArray(element.creator_id) ? element.creator_id : [element.creator_id];
    creatorIds.push(...idCreators);
  }
  // Cumulate creator id
  if (!INTERNAL_USERS[user.id] && !creatorIds.includes(user.id)) {
    inputs.push({ key: 'creator_id', value: [...creatorIds, user.id], operation: UPDATE_OPERATION_ADD });
  }
  // Upsert observed data count and times extensions
  if (type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    // Upsert the count only if a time patch is applied.
    const timePatchInputs = buildTimeUpdate(updatePatch, element, 'first_observed', 'last_observed');
    if (timePatchInputs.length > 0) {
      inputs.push(...timePatchInputs);
      inputs.push({ key: 'number_observed', value: [element.number_observed + updatePatch.number_observed] });
    }
  }
  // If file directly attached
  if (!isEmptyField(updatePatch.file)) {
    const path = `import/${element.entity_type}/${element.internal_id}`;
    const file = await upload(context, user, path, updatePatch.file, { entity: element });
    const convertedFile = storeFileConverter(user, file);
    // The impact in the database is the completion of the files
    const fileImpact = { key: 'x_opencti_files', value: [...(element.x_opencti_files ?? []), convertedFile] };
    inputs.push(fileImpact);
  }
  // Upsert relations with times extensions
  if (isStixCoreRelationship(type)) {
    const timePatchInputs = buildTimeUpdate(updatePatch, element, 'start_time', 'stop_time');
    inputs.push(...timePatchInputs);
  }
  if (isStixSightingRelationship(type)) {
    const timePatchInputs = buildTimeUpdate(updatePatch, element, 'first_seen', 'last_seen');
    if (timePatchInputs.length > 0) {
      inputs.push(...timePatchInputs);
      inputs.push({ key: 'attribute_count', value: [element.attribute_count + updatePatch.attribute_count] });
    }
  }
  // If confidence is passed at creation, just compare confidence
  const isPatchUpdateOption = updatePatch.update === true;
  const isConfidenceMatch = isNotEmptyField(updatePatch.confidence) ? (updatePatch.confidence >= element.confidence) : isPatchUpdateOption;
  // -- Upsert attributes
  const attributes = Array.from(schemaAttributesDefinition.getAttributes(type).values());
  for (let attrIndex = 0; attrIndex < attributes.length; attrIndex += 1) {
    const attribute = attributes[attrIndex];
    const attributeKey = attribute.name;
    const isInputAvailable = attributeKey in updatePatch;
    if (isInputAvailable) { // The attribute is explicitly available in the patch
      const inputData = updatePatch[attributeKey];
      const isFullSync = context.synchronizedUpsert; // In case of full synchronization, just update the data
      const isInputWithData = isNotEmptyField(inputData);
      const isCurrentlyEmpty = isEmptyField(element[attributeKey]) && isInputWithData; // If the element current data is empty, we always expect to put the value
      // Field can be upsert if:
      // 1. Confidence is correct
      // 2. Attribute is declared upsert=true in the schema
      // 3. Data from the inputs is not empty to prevent any data cleaning
      const canBeUpsert = isConfidenceMatch && attribute.upsert && isInputWithData;
      // Upsert will be done if upsert is well-defined but also in full synchro mode or if the current value is empty
      if (canBeUpsert || isFullSync || isCurrentlyEmpty) {
        inputs.push(...buildAttributeUpdate(isFullSync, attribute, element[attributeKey], inputData));
      }
    }
  }
  // -- Upsert refs
  const metaInputFields = schemaRelationsRefDefinition.getRelationsRef(element.entity_type).map((ref) => ref.inputName);
  for (let fieldIndex = 0; fieldIndex < metaInputFields.length; fieldIndex += 1) {
    const inputField = metaInputFields[fieldIndex];
    const relDef = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputField);
    const isInputAvailable = inputField in updatePatch;
    if (isInputAvailable) {
      const patchInputData = updatePatch[inputField];
      const isInputWithData = isNotEmptyField(patchInputData);
      const isUpsertSynchro = (context.synchronizedUpsert || inputField === INPUT_GRANTED_REFS); // Granted Refs are always fully sync
      if (relDef.multiple) {
        const currentData = element[relDef.databaseName] ?? [];
        const targetData = (patchInputData ?? []).map((n) => n.internal_id);
        // If expected data is different from current data
        if (R.symmetricDifference(currentData, targetData).length > 0) {
          const diffTargets = (patchInputData ?? []).filter((target) => !currentData.includes(target.internal_id));
          // In full synchro, just replace everything
          if (isUpsertSynchro) {
            inputs.push({ key: inputField, value: patchInputData ?? [], operation: UPDATE_OPERATION_REPLACE });
          } else if (isInputWithData && diffTargets.length > 0) {
            // If data is provided and different from existing data, apply an add operation
            inputs.push({ key: inputField, value: diffTargets, operation: UPDATE_OPERATION_ADD });
          }
        }
      } else {
        const currentData = element[relDef.databaseName];
        const updatable = isUpsertSynchro || (isInputWithData && isEmptyField(currentData));
        // If expected data is different from current data
        // And data can be updated (complete a null value or forced through synchro upsert option
        if (!R.equals(currentData, patchInputData) && updatable) {
          inputs.push({ key: inputField, value: [patchInputData] });
        }
      }
    }
  }
  // -- If modifications need to be done, add updated_at and modified
  if (inputs.length > 0) {
    // Update the attribute and return the result
    const updateOpts = { ...opts, upsert: context.synchronizedUpsert !== true };
    const update = await updateAttributeMetaResolved(context, user, element, inputs, updateOpts);
    await createContainerSharingTask(context, ACTION_TYPE_SHARE, update.element);
    return update;
  }
  // -- No modification applied
  return { element, event: null, isCreation: false };
};

export const buildRelationData = async (context, user, input, opts = {}) => {
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
    data.i_inference_weight = input.i_inference_weight;
  }
  data.internal_id = internalId;
  data.standard_id = standardId;
  data.entity_type = relationshipType;
  data.relationship_type = relationshipType;
  data.creator_id = [user.internal_id];
  data.created_at = today;
  data.updated_at = today;
  // region re-work data
  // stix-relationship
  if (isStixRelationshipExceptRef(relationshipType)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    data.x_opencti_stix_ids = stixIds;
    data.revoked = R.isNil(input.revoked) ? false : input.revoked;
    data.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
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
      // Get statuses
      const platformStatuses = await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS);
      const statusesForType = platformStatuses.filter((p) => p.type === type);
      if (statusesForType.length > 0) {
        // Check, if status is not set or not valid
        if (R.isNil(input[X_WORKFLOW_ID]) || statusesForType.filter((n) => n.id === input[X_WORKFLOW_ID]).length === 0) {
          data[X_WORKFLOW_ID] = R.head(statusesForType).id;
        }
      }
    }
  }
  // stix-ref-relationship
  if (isStixRefRelationship(relationshipType) && schemaRelationsRefDefinition.isDatable(from.entity_type, relationshipType)) {
    // because spec is only put in all stix except meta, and stix cyber observable is a meta but requires this
    data.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    data.created = R.isNil(input.created) ? today : input.created;
    data.modified = R.isNil(input.modified) ? today : input.modified;
    //* v8 ignore if */
    if (data.start_time > data.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    data.description = input.description ? input.description : '';
    data.start_time = isEmptyField(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = isEmptyField(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    //* v8 ignore if */
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
    //* v8 ignore if */
    if (data.first_seen > data.last_seen) {
      throw DatabaseError('You cant create a relation with last_seen less than first_seen', {
        from: input.fromId,
        input,
      });
    }
  }
  // endregion
  // 04. Create the relation
  const fromRole = `${relationshipType}_from`;
  const toRole = `${relationshipType}_to`;
  // Build final query
  const relToCreate = [];
  if (isStixRelationshipExceptRef(relationshipType)) {
    // We need to link the data to organization sharing, only for core and sightings.
    if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
      relToCreate.push(...buildInnerRelation(data, input[INPUT_GRANTED_REFS], RELATION_GRANTED_TO));
    } else if (!user.inside_platform_organization) {
      // If user is not part of the platform organization, put its own organizations
      relToCreate.push(...buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
    }
    const markingsFiltered = await cleanMarkings(context, input.objectMarking);
    relToCreate.push(...buildInnerRelation(data, markingsFiltered, RELATION_OBJECT_MARKING));
  }
  if (isStixCoreRelationship(relationshipType)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
    relToCreate.push(...buildInnerRelation(data, input.killChainPhases, RELATION_KILL_CHAIN_PHASE));
    relToCreate.push(...buildInnerRelation(data, input.externalReferences, RELATION_EXTERNAL_REFERENCE));
  }
  if (isStixSightingRelationship(relationshipType)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
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
  return {
    element: created,
    isCreation: true,
    previous: null,
    relations: relToCreate
  };
};

export const createRelationRaw = async (context, user, input, opts = {}) => {
  let lock;
  const { fromRule, locks = [] } = opts;
  const { fromId, toId, relationship_type: relationshipType } = input;
  // Pre-check before inputs resolution
  if (fromId === toId) {
    /* v8 ignore next */
    const errorData = { from: input.fromId, relationshipType };
    throw UnsupportedError('Relation cant be created with the same source and target', errorData);
  }
  const entitySetting = await getEntitySettingFromCache(context, relationshipType);
  const filledInput = fillDefaultValues(user, input, entitySetting);
  await validateEntityAndRelationCreation(context, user, filledInput, relationshipType, entitySetting, opts);
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(context, user, filledInput, relationshipType, entitySetting);
  const { from, to } = resolvedInput;
  // check if user has "edit" access on from and to
  if (!validateUserAccessOperation(user, from, 'edit') || !validateUserAccessOperation(user, to, 'edit')) {
    throw ForbiddenAccess();
  }
  // Check consistency
  await checkRelationConsistency(context, user, relationshipType, from, to);
  // In some case from and to can be resolved to the same element (because of automatic merging)
  if (from.internal_id === to.internal_id) {
    /* v8 ignore next */
    if (relationshipType === RELATION_REVOKED_BY) {
      // Because of entity merging, we can receive some revoked-by on the same internal id element
      // In this case we need to revoke the fromId stixId of the relation
      // TODO Handle RELATION_REVOKED_BY special case
    }
    const errorData = { from: input.fromId, to: input.toId, relationshipType };
    throw UnsupportedError('Relation cant be created with the same source and target', errorData);
  }
  // It's not possible to create a single ref relationship if one already exists
  if (isSingleRelationsRef(resolvedInput.from.entity_type, relationshipType)) {
    const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(resolvedInput.from.entity_type, relationshipType);
    if (isNotEmptyField(resolvedInput.from[key])) {
      const errorData = { from: input.fromId, to: input.toId, relationshipType };
      throw UnsupportedError('Cant add another relation on single ref', errorData);
    }
  }
  // Build lock ids
  const inputIds = getInputIds(relationshipType, resolvedInput, fromRule);
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
      const inferredRelationships = await listRelations(context, SYSTEM_USER, relationshipType, fromRuleArgs);
      existingRelationships.push(...inferredRelationships);
    } else {
      // In case of direct relation, try to find the relation with time filters
      // Only in standard indices.
      const timeFilters = buildRelationDeduplicationFilter(resolvedInput);
      const manualArgs = { ...listingArgs, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, ...timeFilters };
      const manualRelationships = await listRelations(context, SYSTEM_USER, relationshipType, manualArgs);
      existingRelationships.push(...manualRelationships);
    }
    let existingRelationship = null;
    if (existingRelationships.length > 0) {
      // We need to filter what we found with the user rights
      const filteredRelations = await userFilterStoreElements(context, user, existingRelationships);
      // If nothing accessible for this user, throw ForbiddenAccess
      if (filteredRelations.length === 0) {
        throw UnsupportedError('Restricted relation already exists');
      }
      // Meta single relation check
      if (isSingleRelationsRef(resolvedInput.from.entity_type, relationshipType)) {
        // If relation already exist, we fail
        throw UnsupportedError('Relation cant be created (single cardinality)', {
          relationshipType,
          fromId: from.internal_id,
        });
      }
      // TODO Handling merging relation when updating to prevent multiple relations finding
      existingRelationship = R.head(filteredRelations);
      // We can use the resolved input from/to to complete the element
      existingRelationship.from = from;
      existingRelationship.to = to;
    }
    // endregion
    if (existingRelationship) {
      // If upsert come from a rule, do a specific upsert.
      if (fromRule) {
        return await upsertRelationRule(context, existingRelationship, input, { ...opts, locks: participantIds });
      }
      // If not upsert the element
      return upsertElement(context, user, existingRelationship, relationshipType, resolvedInput, { ...opts, locks: participantIds });
    }
    // Check cyclic reference consistency for embedded relationships before creation
    if (isStixRefRelationship(relationshipType)) {
      const toRefs = instanceMetaRefsExtractor(relationshipType, fromRule !== undefined, to);
      // We are using rel_ to resolve STIX embedded refs, but in some cases it's not a cyclic relationships
      // Checking the direction of the relation to allow relationships
      const isReverseRelationConsistent = await isRelationConsistent(context, user, relationshipType, to, from);
      if (toRefs.includes(from.internal_id) && isReverseRelationConsistent) {
        throw FunctionalError('You cant create a cyclic relation', { from: from.standard_id, to: to.standard_id });
      }
    }
    // Just build a standard relationship
    const dataRel = await buildRelationData(context, user, resolvedInput, opts);
    // Index the created element
    lock.signal.throwIfAborted();
    await indexCreatedElement(context, user, dataRel);
    // Push the input in the stream
    let event;
    // In case on embedded relationship creation, we need to dispatch
    // an update of the from entity that host this embedded ref.
    if (isStixRefRelationship(relationshipType)) {
      const referencesPromises = opts.references ? internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) : Promise.resolve([]);
      const references = await Promise.all(referencesPromises);
      if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
        throw FunctionalError('Cant find element references for commit', {
          id: input.fromId,
          references: opts.references
        });
      }
      const previous = resolvedInput.from; // Complete resolution done by the input resolver
      const targetElement = { ...resolvedInput.to, i_relation: resolvedInput };
      const instance = { ...previous };
      const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(instance.entity_type, relationshipType);
      let inputs;
      if (isSingleRelationsRef(instance.entity_type, relationshipType)) {
        inputs = [{ key, value: [targetElement] }];
        // Generate the new version of the from
        instance[key] = targetElement;
      } else {
        inputs = [{ key, value: [targetElement], operation: UPDATE_OPERATION_ADD }];
        // Generate the new version of the from
        instance[key] = [...(instance[key] ?? []), targetElement];
      }
      const message = await generateUpdateMessage(context, instance.entity_type, inputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage,
        external_references: references.map((ref) => convertExternalReferenceToStix(ref))
      } : undefined;
      event = await storeUpdateEvent(context, user, previous, instance, message, { ...opts, commit });
      dataRel.element.from = instance; // dynamically update the from to have an up to date relation
    } else {
      const createdRelation = { ...resolvedInput, ...dataRel.element };
      event = await storeCreateRelationEvent(context, user, createdRelation, opts);
    }
    // - TRANSACTION END
    return { element: dataRel.element, event, isCreation: true };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
export const createRelation = async (context, user, input, opts = {}) => {
  const data = await createRelationRaw(context, user, input, opts);
  return data.element;
};
export const createInferredRelation = async (context, input, ruleContent, opts = {}) => {
  const args = {
    ...opts,
    fromRule: ruleContent.field,
    bypassValidation: true, // We need to bypass validation here has we maybe not setup all require fields
  };
  // eslint-disable-next-line camelcase
  const { fromId, toId, relationship_type } = input;
  // In some cases, we can try to create with the same from and to, ignore
  if (fromId === toId) {
    return undefined;
  }
  // Build the instance
  const instance = {
    fromId,
    toId,
    entity_type: relationship_type,
    relationship_type,
    [ruleContent.field]: [ruleContent.content]
  };
  const patch = createRuleDataPatch(instance);
  const inputRelation = { ...instance, ...patch };
  logApp.info('Create inferred relation', inputRelation);
  return createRelationRaw(context, RULE_MANAGER_USER, inputRelation, args);
};
/* v8 ignore next */
export const createRelations = async (context, user, inputs, opts = {}) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improved by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    const relation = await createRelation(context, user, inputs[i], opts);
    createdRelations.push(relation);
  }
  return createdRelations;
};
// endregion

// region mutation entity
const buildEntityData = async (context, user, input, type, opts = {}) => {
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
    R.assoc('creator_id', [user.internal_id]),
    R.dissoc('update'),
    R.dissoc('file'),
    R.omit(schemaRelationsRefDefinition.getInputNames(input.entity_type)),
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
      R.assoc('revoked', R.isNil(input.revoked) ? false : input.revoked),
      R.assoc('confidence', R.isNil(input.confidence) ? 0 : input.confidence),
      R.assoc('lang', R.isNil(input.lang) ? 'en' : input.lang),
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
    // Get statuses
    const platformStatuses = await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS);
    const statusesForType = platformStatuses.filter((p) => p.type === type);
    if (statusesForType.length > 0) {
      // Check, if status is not set or not valid
      if (R.isNil(input[X_WORKFLOW_ID]) || statusesForType.filter((n) => n.id === input[X_WORKFLOW_ID]).length === 0) {
        data = R.assoc(X_WORKFLOW_ID, R.head(statusesForType).id, data);
      }
    }
  }
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    const aliasField = resolveAliasesField(type).name;
    if (input[aliasField]) {
      const preparedAliases = input[aliasField].filter((a) => isNotEmptyField(a)).map((a) => a.trim());
      const uniqAliases = R.uniqBy((e) => normalizeName(e), preparedAliases);
      data[aliasField] = uniqAliases.filter((e) => normalizeName(e) !== normalizeName(input.name));
    }
    data = R.assoc(INTERNAL_IDS_ALIASES, generateAliasesIdsForInstance(data), data);
  }
  // Create the meta relationships (ref, refs)
  const relToCreate = [];
  const isSegregationEntity = !STIX_ORGANIZATIONS_UNRESTRICTED.some((o) => getParentTypes(data.entity_type).includes(o));
  const appendMetaRelationships = async (inputField, relType) => {
    if (input[inputField] || relType === RELATION_GRANTED_TO) {
      // For organizations management
      if (relType === RELATION_GRANTED_TO && isSegregationEntity) {
        if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && input[inputField]) {
          relToCreate.push(...buildInnerRelation(data, input[inputField], RELATION_GRANTED_TO));
        } else if (!user.inside_platform_organization) {
          // If user is not part of the platform organization, put its own organizations
          relToCreate.push(...buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
        }
      } else if (relType === RELATION_OBJECT_MARKING) {
        const markingsFiltered = await cleanMarkings(context, input[inputField]);
        relToCreate.push(...buildInnerRelation(data, markingsFiltered, relType));
      } else if (input[inputField]) {
        const instancesToCreate = Array.isArray(input[inputField]) ? input[inputField] : [input[inputField]];
        relToCreate.push(...buildInnerRelation(data, instancesToCreate, relType));
      }
    }
  };
  // If file directly attached
  if (!isEmptyField(input.file)) {
    const path = `import/${type}/${internalId}`;
    const file = await upload(context, user, path, input.file, { entity: { internal_id: internalId } });
    data.x_opencti_files = [storeFileConverter(user, file)];
    // Add external references from files if necessary
    const entitySetting = await getEntitySettingFromCache(context, type);
    if (entitySetting?.platform_entity_files_ref) {
      // Create external ref + link to current entity
      const createExternal = { source_name: file.name, url: `/storage/get/${file.id}`, fileId: file.id };
      const externalRef = await createEntity(context, user, createExternal, ENTITY_TYPE_EXTERNAL_REFERENCE);
      const newExternalRefs = [...(input[INPUT_EXTERNAL_REFS] ?? []), externalRef];
      data = { ...data, [INPUT_EXTERNAL_REFS]: newExternalRefs };
    }
  }
  // For meta stix core && meta observables
  const inputFields = schemaRelationsRefDefinition.getRelationsRef(input.entity_type);
  for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
    const inputField = inputFields[fieldIndex];
    await appendMetaRelationships(inputField.inputName, inputField.databaseName);
  }

  // Transaction succeed, complete the result to send it back
  const entity = R.pipe(
    R.assoc('id', internalId),
    R.assoc('base_type', BASE_TYPE_ENTITY),
    R.assoc('parent_types', getParentTypes(type))
  )(data);

  // Simply return the data
  return {
    isCreation: true,
    element: entity,
    message: generateCreateMessage(entity),
    previous: null,
    relations: relToCreate, // Added meta relationships
  };
};

const createEntityRaw = async (context, user, input, type, opts = {}) => {
  // Region - Pre-Check
  const entitySetting = await getEntitySettingFromCache(context, type);
  const filledInput = fillDefaultValues(user, input, entitySetting);
  await validateEntityAndRelationCreation(context, user, filledInput, type, entitySetting, opts);
  // Endregion
  const { fromRule } = opts;
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(context, user, filledInput, type, entitySetting);
  // Generate all the possibles ids
  // For marking def, we need to force the standard_id
  const participantIds = getInputIds(type, resolvedInput, fromRule);
  // Create the element
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    // Generate the internal id if needed
    const standardId = resolvedInput.standard_id || generateStandardId(type, resolvedInput);
    // Check if the entity exists, must be done with SYSTEM USER to really find it.
    const existingEntities = [];
    const existingByIdsPromise = internalFindByIds(context, SYSTEM_USER, participantIds, { type });
    // Hash are per definition keys.
    // When creating a hash, we can check all hashes to update or merge the result
    // Generating multiple standard ids could be a solution but to complex to implements
    // For now, we will look for any observables that have any hashes of this input.
    let existingByHashedPromise = Promise.resolve([]);
    if (isStixCyberObservableHashedObservable(type)) {
      existingByHashedPromise = listEntitiesByHashes(context, user, type, input.hashes);
      resolvedInput.update = true;
    }
    // Resolve the existing entity
    const [existingByIds, existingByHashed] = await Promise.all([existingByIdsPromise, existingByHashedPromise]);
    existingEntities.push(...R.uniqBy((e) => e.internal_id, [...existingByIds, ...existingByHashed]));
    // If existing entities have been found and type is a STIX Core Object
    let dataEntity;
    if (existingEntities.length > 0) {
      // We need to filter what we found with the user rights
      const filteredEntities = await userFilterStoreElements(context, user, existingEntities);
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
        return await upsertEntityRule(context, R.head(filteredEntities), input, { ...opts, locks: participantIds });
      }
      if (filteredEntities.length === 1) {
        const upsertEntityOpts = { ...opts, locks: participantIds, bypassIndividualUpdate: true };
        const element = await storeLoadByIdWithRefs(context, user, R.head(filteredEntities).internal_id);
        return upsertElement(context, user, element, type, resolvedInput, upsertEntityOpts);
      }
      // If creation is not by a reference
      // We can in best effort try to merge a common stix_id
      const existingByStandard = R.find((e) => e.standard_id === standardId, filteredEntities);
      if (existingByStandard) {
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
            // Deciding the target
            let mergeTarget = existingByStandard.internal_id;
            let mergeSource = existingByGivenStixId.internal_id;
            // If confidence level is bigger, pickup as the target
            if (existingByGivenStixId.confidence > existingByStandard.confidence) {
              mergeTarget = existingByGivenStixId.internal_id;
              mergeSource = existingByStandard.internal_id;
            }
            logApp.info('[OPENCTI] Merge during creation detected');
            await mergeEntities(context, user, mergeTarget, [mergeSource], { locks: participantIds });
          }
        }
        // In this mode we can safely consider this entity like the existing one.
        // We can upsert element except the aliases that are part of other entities
        const concurrentEntities = R.filter((e) => e.standard_id !== standardId, filteredEntities);
        const key = resolveAliasesField(type).name;
        const concurrentAliases = R.flatten(R.map((c) => [c[key], c.name], concurrentEntities));
        const normedAliases = R.uniq(concurrentAliases.map((c) => normalizeName(c)));
        const filteredAliases = R.filter((i) => !normedAliases.includes(normalizeName(i)), resolvedInput[key] || []);
        const inputAliases = { ...resolvedInput, [key]: filteredAliases };
        return upsertElement(context, user, existingByStandard, type, inputAliases, { ...opts, locks: participantIds });
      }
      if (resolvedInput.update === true) {
        // The new one is new reference, merge all found entities
        // Target entity is existingByStandard by default or any other
        const target = R.find((e) => e.standard_id === standardId, filteredEntities) || R.head(filteredEntities);
        const sources = R.filter((e) => e.internal_id !== target.internal_id, filteredEntities);
        hashMergeValidation([target, ...sources]);
        await mergeEntities(context, user, target.internal_id, sources.map((s) => s.internal_id), { locks: participantIds });
        return upsertElement(context, user, target, type, resolvedInput, { ...opts, locks: participantIds });
      }
      if (resolvedInput.stix_id && !existingEntities.map((n) => getInstanceIds(n)).flat().includes(resolvedInput.stix_id)) {
        const target = R.head(filteredEntities);
        return upsertElement(context, user, target, type, { x_opencti_stix_ids: [...target.x_opencti_stix_ids, resolvedInput.stix_id] }, { ...opts, locks: participantIds });
      }
      // If not we dont know what to do, just throw an exception.
      throw UnsupportedError('Cant upsert entity. Too many entities resolved', { input, entityIds });
    } else {
      // Create the object
      dataEntity = await buildEntityData(context, user, resolvedInput, type, opts);
    }
    // Index the created element
    lock.signal.throwIfAborted();
    await indexCreatedElement(context, user, dataEntity);
    // Push the input in the stream
    const createdElement = { ...resolvedInput, ...dataEntity.element };
    const event = await storeCreateEntityEvent(context, user, createdElement, dataEntity.message, opts);
    // Return created element after waiting for it.
    return { element: dataEntity.element, event, isCreation: true };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const createEntity = async (context, user, input, type, opts = {}) => {
  const isCompleteResult = opts.complete === true;
  // volumes of objects relationships must be controlled
  const data = await createEntityRaw(context, user, input, type, opts);
  // In case of creation, start an enrichment
  if (data.isCreation) {
    await createEntityAutoEnrichment(context, user, data.element.standard_id, type);
  }
  return isCompleteResult ? data : data.element;
};
export const createInferredEntity = async (context, input, ruleContent, type) => {
  const opts = {
    fromRule: ruleContent.field,
    impactStandardId: false,
    bypassValidation: true, // We need to bypass validation here has we maybe not setup all require fields
  };
  // Inferred entity have a specific standardId generated from dependencies data.
  const standardId = idGenFromData(type, ruleContent.content.dependencies.sort());
  const instance = { standard_id: standardId, entity_type: type, ...input, [ruleContent.field]: [ruleContent.content] };
  const patch = createRuleDataPatch(instance);
  const inputEntity = { ...instance, ...patch };
  logApp.info('Create inferred entity', { entity: inputEntity });
  return await createEntityRaw(context, RULE_MANAGER_USER, inputEntity, type, opts);
};
// endregion

// region mutation deletion
export const internalDeleteElementById = async (context, user, id, opts = {}) => {
  let lock;
  let event;
  const element = await storeLoadByIdWithRefs(context, user, id);
  if (!element) {
    throw AlreadyDeletedError({ id });
  }
  // Prevent individual deletion if linked to a user
  if (element.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL && !isEmptyField(element.contact_information)) {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: 'user_email', values: [element.contact_information] }],
        filterGroups: [],
      },
      noFiltersChecking: true,
      connectionFormat: false
    };
    const users = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], args);
    if (users.length > 0) {
      throw FunctionalError('Cannot delete an individual corresponding to a user');
    }
  }
  if (!validateUserAccessOperation(user, element, 'delete')) {
    throw ForbiddenAccess();
  }
  // Check inference operation
  checkIfInferenceOperationIsValid(user, element);
  // Apply deletion
  const participantIds = [element.internal_id];
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    if (isStixRefRelationship(element.entity_type)) {
      const referencesPromises = opts.references ? internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) : Promise.resolve([]);
      const references = await Promise.all(referencesPromises);
      if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
        throw FunctionalError('Cant find element references for commit', {
          id: element.fromId,
          references: opts.references
        });
      }
      const targetElement = { ...element.to, i_relation: element };
      const previous = await storeLoadByIdWithRefs(context, user, element.fromId);
      const instance = structuredClone(previous);
      const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(instance.entity_type, element.entity_type);
      let inputs;
      if (isSingleRelationsRef(instance.entity_type, element.entity_type)) {
        inputs = [{ key, value: [] }];
        instance[key] = undefined; // Generate the new version of the from
      } else {
        inputs = [{ key, value: [targetElement], operation: UPDATE_OPERATION_REMOVE }];
        // To prevent to many patch operations, removed key must be put at the end
        const withoutElementDeleted = (previous[key] ?? []).filter((e) => e.internal_id !== targetElement.internal_id);
        previous[key] = [...withoutElementDeleted, targetElement];
        // Generate the new version of the from
        instance[key] = withoutElementDeleted;
      }
      const message = await generateUpdateMessage(context, instance.entity_type, inputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage,
        external_references: references.map((ref) => convertExternalReferenceToStix(ref))
      } : undefined;
      const eventPromise = storeUpdateEvent(context, user, previous, instance, message, { ...opts, commit });
      const taskPromise = createContainerSharingTask(context, ACTION_TYPE_UNSHARE, element);
      const deletePromise = elDeleteElements(context, user, [element]);
      const [, , updateEvent] = await Promise.all([taskPromise, deletePromise, eventPromise]);
      event = updateEvent;
      element.from = instance; // dynamically update the from to have an up to date relation
    } else {
      // Start by deleting external files
      await deleteAllObjectFiles(context, user, element);
      // Delete all linked elements
      const dependencyDeletions = await elDeleteElements(context, user, [element], storeLoadByIdsWithRefs);
      // Publish event in the stream
      event = await storeDeleteEvent(context, user, element, dependencyDeletions, opts);
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
  // - TRANSACTION END
  return { element, event };
};
export const deleteElementById = async (context, user, elementId, type, opts = {}) => {
  if (R.isNil(type)) {
    /* v8 ignore next */
    throw FunctionalError('You need to specify a type when deleting an entity');
  }
  const { element: deleted } = await internalDeleteElementById(context, user, elementId, opts);
  return deleted;
};
export const deleteInferredRuleElement = async (rule, instance, deletedDependencies, opts = {}) => {
  const context = executionContext(rule.name, RULE_MANAGER_USER);
  // Check if deletion is really targeting an inference
  const isInferred = isInferredIndex(instance._index);
  if (!isInferred) {
    throw UnsupportedError('Instance is not inferred, cant be deleted', { id: instance.id });
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
        await internalDeleteElementById(context, RULE_MANAGER_USER, instance.id, opts);
        return true;
      }
      // If not we need to clean the rule and keep the element for other rules.
      logApp.info('Cleanup inferred element', { rule, id: instance.id });
      const input = { [completeRuleName]: null };
      const upsertOpts = { fromRule, ruleOverride: true };
      await upsertRelationRule(context, instance, input, upsertOpts);
    } else {
      logApp.info('Upsert inferred element', { rule, id: instance.id });
      // Rule still have other explanation, update the rule
      const input = { [completeRuleName]: rebuildRuleContent };
      const ruleOpts = { fromRule, ruleOverride: true };
      await upsertRelationRule(context, instance, input, ruleOpts);
    }
  } catch (err) {
    if (err.name === ALREADY_DELETED_ERROR) {
      logApp.warn(err);
    } else {
      logApp.error(err);
    }
  }
  return false;
};
export const deleteRelationsByFromAndTo = async (context, user, fromId, toId, relationshipType, scopeType, opts = {}) => {
  //* v8 ignore if */
  if (R.isNil(scopeType) || R.isNil(fromId) || R.isNil(toId)) {
    throw FunctionalError('You need to specify a scope type when deleting a relation with from and to');
  }
  const fromThing = await internalLoadById(context, user, fromId, opts);
  // Check mandatory attribute
  const entitySetting = await getEntitySettingFromCache(context, fromThing.entity_type);
  const attributesMandatory = await getMandatoryAttributesForSetting(context, user, entitySetting);
  if (attributesMandatory.length > 0) {
    const attribute = attributesMandatory.find((attr) => attr === schemaRelationsRefDefinition.convertDatabaseNameToInputName(fromThing.entity_type, relationshipType));
    if (attribute && fromThing[buildRefRelationKey(relationshipType)].length === 1) {
      throw ValidationError(attribute, { validation: 'This attribute is mandatory', attribute });
    }
  }
  const toThing = await internalLoadById(context, user, toId, opts);// check if user has "edit" access on from and to
  if (!validateUserAccessOperation(user, fromThing, 'edit') || !validateUserAccessOperation(user, toThing, 'edit')) {
    throw ForbiddenAccess();
  }
  // Looks like the caller doesnt give the correct from, to currently
  const relationsToDelete = await elFindByFromAndTo(context, user, fromThing.internal_id, toThing.internal_id, relationshipType);
  for (let i = 0; i < relationsToDelete.length; i += 1) {
    const r = relationsToDelete[i];
    await deleteElementById(context, user, r.internal_id, r.entity_type, opts);
  }
  return { from: fromThing, to: toThing, deletions: relationsToDelete };
};
// endregion
