import moment from 'moment';
import * as R from 'ramda';
import DataLoader from 'dataloader';
import { Promise } from 'bluebird';
import {
  DatabaseError,
  ForbiddenAccess,
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
  generateCreateMessage,
  generateUpdateMessage,
  INDEX_INFERRED_RELATIONSHIPS,
  inferIndexFromConceptType,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  READ_DATA_INDICES,
  READ_DATA_INDICES_INFERRED,
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
import {
  lockResource,
  notify,
  redisAddDeletions,
  storeCreateEntityEvent,
  storeCreateRelationEvent,
  storeDeleteEvent,
  storeMergeEvent,
  storeUpdateEvent,
} from './redis';
import { cleanStixIds, STIX_SPEC_VERSION, stixCyberObservableFieldsForType, } from './stix';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ABSTRACT_STIX_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  DEPS_KEYS,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INPUT_GRANTED_REFS,
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
  CYBER_OBSERVABLE_FIELD_TO_META_RELATION,
  INPUT_FROM,
  isStixCyberObservableRelationship,
  MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
  STIX_ATTRIBUTE_TO_CYBER_RELATIONS,
  STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE,
  STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
} from '../schema/stixCyberObservableRelationship';
import {
  fieldToMetaRelation,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_USER,
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
  extractNotFuzzyHashValues,
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
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_INDICATOR,
  isStixDomainObject,
  isStixDomainObjectShareableContainer,
  isStixObjectAliased,
  resolveAliasesField,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_LABEL, isStixMetaObject } from '../schema/stixMetaObject';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import {
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  isStixCyberObservable,
  isStixCyberObservableHashedObservable,
} from '../schema/stixCyberObservable';
import { BUS_TOPICS, logApp } from '../config/conf';
import {
  dayFormat,
  FROM_START,
  FROM_START_STR,
  mergeDeepRightAll,
  monthFormat,
  now,
  prepareDate,
  UNTIL_END,
  UNTIL_END_STR,
  utcDate,
  yearFormat,
} from '../utils/format';
import { checkObservableSyntax } from '../utils/syntax';
import { deleteAllFiles, storeFileConverter, upload } from './file-storage';
import {
  BYPASS,
  BYPASS_REFERENCE,
  executionContext,
  isBypassUser,
  isUserCanAccessStoreElement,
  KNOWLEDGE_ORGANIZATION_RESTRICT,
  RULE_MANAGER_USER,
  SYSTEM_USER,
  userFilterStoreElements
} from '../utils/access';
import { isRuleUser, RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules';
import {
  fieldAttributeToEmbeddedRelation,
  instanceMetaRefsExtractor,
  isSingleStixEmbeddedRelationship,
  isSingleStixEmbeddedRelationshipInput,
  isStixEmbeddedRelationship,
  META_STIX_ATTRIBUTES,
  metaFieldAttributes,
  STIX_ATTRIBUTE_TO_META_FIELD,
  stixEmbeddedRelationToField,
} from '../schema/stixEmbeddedRelationship';
import { createEntityAutoEnrichment } from '../domain/enrichment';
import { convertExternalReferenceToStix, convertStoreToStix, isTrustedStixId } from './stix-converter';
import {
  buildEntityFilters,
  internalFindByIds,
  internalLoadById,
  listAllRelations,
  listEntities,
  listRelations,
  storeLoadById
} from './middleware-loader';
import { checkRelationConsistency, isRelationConsistent } from '../utils/modelConsistency';
import { getEntitiesFromCache, getEntitiesMapFromCache } from './cache';
import { ACTION_TYPE_SHARE, ACTION_TYPE_UNSHARE, createListTask } from '../domain/task-common';
import { ENTITY_TYPE_VOCABULARY, vocabularyDefinitions } from '../modules/vocabulary/vocabulary-types';
import {
  getVocabulariesCategories,
  getVocabularyCategoryForField,
  isEntityFieldAnOpenVocabulary,
  updateElasticVocabularyValue
} from '../modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

// region global variables
export const MAX_BATCH_SIZE = 300;
// endregion

// region Loader common
export const batchLoader = (loader) => {
  const dataLoader = new DataLoader(
    (objects) => {
      const { context, user, args } = R.head(objects);
      const ids = objects.map((i) => i.id);
      return loader(context, user, ids, args);
    },
    { maxBatchSize: MAX_BATCH_SIZE }
  );
  return {
    load: (id, context, user, args = {}) => {
      return dataLoader.load({ id, context, user, args });
    },
  };
};
export const queryAttributes = async (types) => {
  const attributes = R.uniq(types.map((type) => schemaTypes.getAttributes(type)).flat());
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: types[0], value: n } }))
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
const batchListThrough = async (context, user, sources, sourceSide, relationType, targetEntityType, opts = {}) => {
  const { paginate = true, withInferences = true, batched = true, first = null } = opts;
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
  const indices = withInferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
  const relations = await elList(context, user, indices, {
    filters,
    types: [relationType],
    connectionFormat: false,
  });
  // For each relation resolved the target entity
  const targets = await elFindByIds(context, user, R.uniq(relations.map((s) => s[`${opposite}Id`])));
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
const loadElementMetaDependencies = async (context, user, element, args = {}) => {
  const { onlyMarking = true } = args;
  const elementId = element.internal_id;
  const relTypes = onlyMarking ? [RELATION_OBJECT_MARKING] : [ABSTRACT_STIX_META_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP];
  // Resolve all relations
  const refsRelations = await listAllRelations(context, user, relTypes, { fromId: elementId });
  const data = {};
  // Parallel resolutions
  const toResolvedIds = R.uniq(refsRelations.map((rel) => rel.toId));
  const toResolved = await elFindByIds(context, user, toResolvedIds, { toMap: true });
  const attributeToEmbeddedRelation = fieldAttributeToEmbeddedRelation();
  const embeddedRelationToField = stixEmbeddedRelationToField();
  if (refsRelations.length > 0) {
    // Build flatten view inside the data for stix meta
    const grouped = R.groupBy((a) => embeddedRelationToField[a.entity_type], refsRelations);
    const entries = Object.entries(grouped);
    for (let index = 0; index < entries.length; index += 1) {
      const [key, values] = entries[index];
      const resolvedElementsWithRelation = R.map((v) => {
        const resolvedElement = toResolved[v.toId];
        return resolvedElement ? { ...resolvedElement, i_relation: v } : {};
      }, values).filter((d) => isNotEmptyField(d));
      const metaRefKey = attributeToEmbeddedRelation[key];
      data[key] = isSingleStixEmbeddedRelationship(metaRefKey)
        ? R.head(resolvedElementsWithRelation) : resolvedElementsWithRelation;
    }
  }
  return data;
};
const loadElementWithDependencies = async (context, user, element, args = {}) => {
  const depsPromise = loadElementMetaDependencies(context, user, element, args);
  const isRelation = element.base_type === BASE_TYPE_RELATION;
  if (isRelation) {
    // Load the relation from and to directly with the system user
    // Access right must be checked by hand in this case.
    // eslint-disable-next-line no-use-before-define
    const fromPromise = loadByIdWithDependencies(context, SYSTEM_USER, element.fromId, element.fromType, { onlyMarking: true });
    // eslint-disable-next-line no-use-before-define
    const toPromise = loadByIdWithDependencies(context, SYSTEM_USER, element.toId, element.toType, { onlyMarking: true });
    const [from, to, deps] = await Promise.all([fromPromise, toPromise, depsPromise]);
    // Check relations consistency
    if (isEmptyField(from) || isEmptyField(to)) {
      const validFrom = isEmptyField(from) ? 'invalid' : 'valid';
      const validTo = isEmptyField(to) ? 'invalid' : 'valid';
      const message = `From ${element.fromId} is ${validFrom}, To ${element.toId} is ${validTo}`;
      logApp.warn(`Auto delete of invalid relation ${element.id}. ${message}`);
      // Auto deletion of the invalid relation
      await elDeleteElements(context, SYSTEM_USER, [element], storeLoadByIdWithRefs);
      return null;
    }
    // Check relations marking access.
    const canAccessFrom = await isUserCanAccessStoreElement(context, user, from);
    const canAccessTo = await isUserCanAccessStoreElement(context, user, to);
    if (canAccessFrom && canAccessTo) {
      return R.mergeRight(element, { from, to, ...deps });
    }
    // Relation is accessible but access rights is not align with the user asking for the information
    // In this case the element is considered as not existing
    return null;
  }
  const deps = await depsPromise;
  return R.mergeRight(element, { ...deps });
};
const loadByIdWithDependencies = async (context, user, id, type, args = {}) => {
  const element = await internalLoadById(context, user, id, { type });
  if (!element) return null;
  return loadElementWithDependencies(context, user, element, args);
};
// Get element with every elements connected element -> rel -> to
export const storeLoadByIdWithRefs = async (context, user, id, opts = {}) => {
  const { type = null } = opts;
  return loadByIdWithDependencies(context, user, id, type, { onlyMarking: false });
};
export const stixLoadById = async (context, user, id, opts = {}) => {
  const instance = await storeLoadByIdWithRefs(context, user, id, opts);
  if (instance) {
    return convertStoreToStix(instance);
  }
  return undefined;
};
export const stixLoadByIds = async (context, user, ids, opts = {}) => {
  const instances = await Promise.map(ids, (id) => stixLoadById(context, user, id, opts), {
    concurrency: ES_MAX_CONCURRENCY,
  });
  return instances.filter((i) => isNotEmptyField(i));
};
export const stixLoadByIdStringify = async (context, user, id) => {
  const data = await stixLoadById(context, user, id);
  return data ? JSON.stringify(data) : '';
};
// endregion

// region Graphics
const convertAggregateDistributions = async (context, user, limit, orderingFunction, distribution) => {
  const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distribution));
  const resolveLabels = await elFindByIds(context, user, data.map((d) => d.label), { toMap: true });
  return data // Depending of user access, info can be empty, must be filtered
    .filter((n) => isNotEmptyField(resolveLabels[n.label]))
    .map((n) => R.assoc('entity', resolveLabels[n.label], n));
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
  const distributionData = await elAggregationCount(context, user, args.onlyInferred ? READ_DATA_INDICES_INFERRED : READ_DATA_INDICES, {
    ...distributionArgs,
    field: finalField
  });
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL)) {
    return convertAggregateDistributions(context, user, limit, orderingFunction, distributionData);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionRelations = async (context, user, args) => {
  const { field } = args; // Mandatory fields
  const { limit = 50, order } = args;
  const { relationship_type: relationshipTypes, dateAttribute = 'created_at' } = args;
  const types = relationshipTypes || [ABSTRACT_STIX_CORE_RELATIONSHIP];
  const distributionDateAttribute = dateAttribute || 'created_at';
  // Using elastic can only be done if the distribution is a count on types
  const opts = { ...args, dateAttribute: distributionDateAttribute };
  const distributionArgs = buildEntityFilters({ types, ...opts });
  const distributionData = await elAggregationRelationsCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_RELATIONSHIPS : READ_RELATIONSHIPS_INDICES, distributionArgs);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field === ID_INTERNAL) {
    return convertAggregateDistributions(context, user, limit, orderingFunction, distributionData);
  }
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
// endregion

// region mutation common
const TRX_CREATION = 'creation';
const TRX_UPDATE = 'update';
const TRX_IDLE = 'idle';
const depsKeys = () => ([
  ...schemaTypes.get(DEPS_KEYS),
  ...[
    // Relationship
    { src: 'fromId', dst: 'from' },
    { src: 'toId', dst: 'to' },
    // Other meta refs
    ...STIX_META_RELATIONSHIPS_INPUTS.map((e) => ({ src: e })),
    ...STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS.map((e) => ({ src: e })),
  ],
]);

const idNormalizeDataEntity = (nameOrId, data) => (isAnId(nameOrId) ? nameOrId : generateAliasesId([nameOrId], data).at(0));

const idLabel = (label) => {
  return isAnId(label) ? label : generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(label) });
};

const inputResolveRefs = async (context, user, input, type) => {
  const fetchingIds = [];
  const expectedIds = [];
  const cleanedInput = { _index: inferIndexFromConceptType(type), ...input };
  let embeddedFromResolution;
  let forceAliases = false;
  const dependencyKeys = depsKeys();
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
      } else if (!expectedIds.includes(id)) {
        // If resolution is due to embedded ref, the from must be fully resolved
        // This will be used to generated a correct stream message
        if (dst === INPUT_FROM && isStixEmbeddedRelationship(type)) {
          embeddedFromResolution = id;
        } else {
          fetchingIds.push({ id, destKey, multiple: false });
        }
        expectedIds.push(id);
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
  // We only accept missing objects_refs (Report, Opinion, Note, Observed-data)
  const expectedUnresolvedIds = unresolvedIds.filter((u) => !(input[INPUT_OBJECTS] || []).includes(u));
  if (expectedUnresolvedIds.length > 0) {
    throw MissingReferenceError({ input, unresolvedIds: expectedUnresolvedIds });
  }
  // In case of objects missing reference, we reject twice before accepting
  const retryNumber = user.origin?.call_retry_number;
  const objectRefsUnresolvedIds = unresolvedIds.filter((u) => (input[INPUT_OBJECTS] ?? []).includes(u));
  if (isNotEmptyField(retryNumber) && objectRefsUnresolvedIds.length > 0 && retryNumber <= 2) {
    throw MissingReferenceError({ input, unresolvedIds });
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
        throw FunctionalError('Vocabulary value is mandatory', { key });
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
      throw ForbiddenAccess({ input });
    }
  }
  return inputResolved;
};
const isRelationTargetGrants = (elementGrants, relation, type) => {
  const isTargetType = relation.base_type === BASE_TYPE_RELATION && relation.entity_type === RELATION_OBJECT;
  if (!isTargetType) return false;
  const isUnrestricted = [relation.to.entity_type, ...relation.to.parent_types]
    .some((r) => STIX_ORGANIZATIONS_UNRESTRICTED.includes(r));
  if (isUnrestricted) return false;
  return type === ACTION_TYPE_UNSHARE || !elementGrants.every((v) => (relation.to[RELATION_GRANTED_TO] ?? []).includes(v));
};
const createContainerSharingTask = (context, type, element, relations) => {
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
    const input = { ids: targetGrantIds, actions: [{ type, context: { values: elementGrants } }] };
    taskPromise = createListTask(context.user, input);
  }
  return taskPromise;
};
const indexCreatedElement = async (context, user, { type, element, update, relations }) => {
  // Continue the creation of the element and the connected relations
  if (type === TRX_CREATION) {
    const taskPromise = createContainerSharingTask(context, ACTION_TYPE_SHARE, element, relations);
    const indexPromise = elIndexElements(context, user, element.entity_type, [element, ...(relations ?? [])]);
    await Promise.all([taskPromise, indexPromise]);
  }
  if (type === TRX_UPDATE) {
    const taskPromise = createContainerSharingTask(context, ACTION_TYPE_SHARE, element, relations);
    // update can be undefined in case of unneeded update on upsert on the element
    // noinspection ES6MissingAwait
    const updatePromise = update ? elUpdateElement(update) : Promise.resolve();
    await Promise.all([taskPromise, updatePromise]);
    if (relations.length > 0) {
      const message = `${relations.length} Relation${relations.length > 1 ? 's' : ''}`;
      await elIndexElements(context, user, message, relations);
    }
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
export const mergeInstanceWithInputs = (instance, inputs) => {
  // standard_id must be maintained
  // const inputsWithoutId = inputs.filter((i) => i.key !== ID_STANDARD);
  const data = updatedInputsToData(inputs);
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
  if (isDictionaryAttribute(key)) {
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
  const metaKeys = [...META_STIX_ATTRIBUTES, ...metaFieldAttributes()];
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
const ed = (date) => isEmptyField(date) || date === FROM_START_STR || date === UNTIL_END_STR;
const noDate = (e) => ed(e.first_seen) && ed(e.last_seen) && ed(e.start_time) && ed(e.stop_time);
const filterTargetByExisting = (sources, targets) => {
  const filtered = [];
  const cache = [];
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index];
    // If the relation source is already in target = filtered
    const finder = (t) => {
      const sameTarget = t.internal_id === source.internal_id;
      const sameRelationType = t.i_relation.entity_type === source.i_relation.entity_type;
      return sameRelationType && sameTarget && noDate(t.i_relation);
    };
    const id = `${source.entity_type}-${source.internal_id}`;
    const isSingleMeta = isSingleStixEmbeddedRelationship(source.i_relation.entity_type);
    if (!isSingleMeta && !R.find(finder, targets) && !cache.includes(id)) {
      filtered.push(source);
      cache.push(id);
    }
  }
  return filtered;
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
  const relationsToRedirectFrom = filterTargetByExisting(sourcesDependencies[INTERNAL_FROM_FIELD], targetDependencies[INTERNAL_FROM_FIELD]);
  // region CHANGING TO
  const relationsFromRedirectTo = filterTargetByExisting(sourcesDependencies[INTERNAL_TO_FIELD], targetDependencies[INTERNAL_TO_FIELD]);
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
  const groupsOfRelsUpdate = R.splitEvery(MAX_SPLIT, updateConnections);
  const concurrentRelsUpdate = async (connsToUpdate) => {
    await elUpdateRelationConnections(connsToUpdate);
    currentRelsUpdateCount += connsToUpdate.length;
    logApp.info(`[OPENCTI] Merging, updating relations ${currentRelsUpdateCount} / ${updateConnections.length}`);
  };
  await Promise.map(groupsOfRelsUpdate, concurrentRelsUpdate, { concurrency: ES_MAX_CONCURRENCY });
  const updatedRelations = updateConnections
    .filter((u) => isStixRelationShipExceptMeta(u.entity_type))
    .map((c) => c.standard_id);
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
  const dependencyDeletions = await elDeleteElements(context, user, sourceEntities, storeLoadByIdWithRefs);
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
    const listFromCallback = (elements) => {
      for (let index = 0; index < elements.length; index += 1) {
        const rel = elements[index];
        data[INTERNAL_FROM_FIELD].push({
          _index: inferIndexFromConceptType(rel.toType),
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
    const listToCallback = (elements) => {
      for (let index = 0; index < elements.length; index += 1) {
        const rel = elements[index];
        data[INTERNAL_TO_FIELD].push({
          _index: inferIndexFromConceptType(rel.fromType),
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
    const sources = await Promise.all(sourceEntityIds.map((sourceId) => storeLoadByIdWithRefs(context, SYSTEM_USER, sourceId)));
    const sourcesDependencies = await loadMergeEntitiesDependencies(context, SYSTEM_USER, sources.map((s) => s.internal_id));
    const targetDependencies = await loadMergeEntitiesDependencies(context, SYSTEM_USER, [initialInstance.internal_id]);
    // - TRANSACTION PART
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
  let masterKey = key;
  if (key.includes('.')) {
    const [firstPart] = key.split('.');
    masterKey = firstPart;
  }
  const entityAttributes = schemaTypes.getAttributes(entityType);
  if (!R.includes(masterKey, entityAttributes)) {
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
  // Specific case for Report
  if (instance.entity_type === ENTITY_TYPE_CONTAINER_REPORT && key === 'published') {
    const createdInput = { key: 'created', value: input.value };
    updatedInputs.push(createdInput);
  }
  return updatedInputs;
};
const prepareAttributes = (instance, elements) => {
  const instanceType = instance.entity_type;
  return elements.map((input) => {
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
    // Specific case for Label
    if (input.key === VALUE_FIELD && instanceType === ENTITY_TYPE_LABEL) {
      return {
        key: input.key,
        value: input.value.map((v) => v.toLowerCase())
      };
    }
    // Specific case for name in aliased entities
    // If name change already inside aliases, name must be kep untouched
    if (input.key === NAME_FIELD && isStixObjectAliased(instanceType)) {
      const aliasField = resolveAliasesField(instanceType);
      const name = normalizeName(input.value.at(0));
      if ((instance[aliasField] ?? []).includes(name)) {
        return null;
      }
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
const updateAttributeRaw = async (context, user, instance, inputs, opts = {}) => {
  // Upsert option is only useful to force aliases to be kept when upserting the entity
  const { impactStandardId = true, upsert = false } = opts;
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const instanceType = instance.entity_type;
  // Prepare attributes
  const preparedElements = prepareAttributes(instance, elements);
  // region Check date range
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
  // endregion
  // region Some magic around aliases
  // If named entity name updated or alias are updated, modify the aliases ids
  if (isStixObjectAliased(instanceType)) {
    const aliasField = resolveAliasesField(instanceType);
    const nameInput = R.find((e) => e.key === NAME_FIELD, preparedElements);
    const aliasesInput = R.find((e) => e.key === aliasField, preparedElements);
    if (nameInput || aliasesInput) {
      const name = nameInput ? R.head(nameInput.value) : undefined;
      // Cleanup the alias input
      if (aliasesInput) {
        aliasesInput.value = R.uniq(aliasesInput.value.map((a) => a.trim()).filter((a) => isNotEmptyField(a)));
      }
      // In case of upsert name change, old name must be pushed in aliases
      // If aliases are also ask for modification, we need to change the input
      if (name && normalizeName(instance.name) !== normalizeName(name)) {
        // If name change, we need to do some specific actions
        const aliases = [...(instance[aliasField] ?? [])];
        if (upsert) {
          // For upsert, we concatenate everything to be none destructive
          aliases.push(instance.name);
          // If name changing is part of an upsert, the previous name must be copied into aliases
          if (aliasesInput) { // If aliases input also exists
            aliases.push(...aliasesInput.value);
            aliasesInput.value = R.uniq(aliases);
          } else { // We need to create an extra input getting existing aliases
            const generatedAliasesInput = { key: aliasField, value: R.uniq(aliases) };
            preparedElements.push(generatedAliasesInput);
          }
        }
        // Regenerated the internal ids with the instance target aliases
        const aliasesId = generateAliasesId(R.uniq([name, ...aliases]), instance);
        const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
        preparedElements.push(aliasInput);
      } else if (aliasesInput) {
        // No name change asked but aliases addition
        if (upsert) {
          // In upsert we cumulate with current aliases
          aliasesInput.value = R.uniq([...aliasesInput.value, ...(instance[aliasField] || [])]);
        }
        // Internal ids alias must be generated again
        const aliasesId = generateAliasesId(R.uniq([instance.name, ...aliasesInput.value]), instance);
        const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
        preparedElements.push(aliasInput);
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
  const platformStatuses = isWorkflowChange ? await getEntitiesFromCache(context, user, ENTITY_TYPE_STATUS) : [];
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
          // Specific input resolution for workflow
          if (filteredInput.key === X_WORKFLOW_ID) {
            // workflow_id is not a relation but message must contain the name and not the internal id
            const workflowStatus = platformStatuses.find((p) => p.id === R.head(filteredInput.value));
            return {
              operation: filteredInput.operation,
              key: filteredInput.key,
              value: [workflowStatus.name],
              previous,
            };
          }
          return { ...filteredInput, previous };
        });
        updatedInputs.push(...updatedInputsFiltered);
      }
      impactedInputs.push(...ins);
    }
  }
  // Update updated_at
  const today = now();
  // Impact the updated_at only if stix data is impacted
  if (updatedInputs.length > 0 && isUpdatedAtObject(instance.entity_type)) {
    const updatedAtInput = { key: 'updated_at', value: [today] };
    impactedInputs.push(updatedAtInput);
  }
  if (updatedInputs.length > 0 && isModifiedObject(instance.entity_type)) {
    const modifiedAtInput = { key: 'modified', value: [today] };
    impactedInputs.push(modifiedAtInput);
  }
  return {
    updatedInputs, // Sourced inputs for event stream
    impactedInputs, // All inputs that need to be re-indexed. (so without meta relationships)
    updatedInstance: mergeInstanceWithInputs(instance, impactedInputs),
  };
};
export const updateAttribute = async (context, user, id, type, inputs, opts = {}) => {
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
  const metaKeys = [...META_STIX_ATTRIBUTES, ...metaFieldAttributes()];
  const meta = updates.filter((e) => metaKeys.includes(e.key));
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  // Load the element to update
  const initialPromise = storeLoadByIdWithRefs(context, user, id, { type });
  const referencesPromises = opts.references ? internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) : Promise.resolve([]);
  const [initial, references] = await Promise.all([initialPromise, referencesPromises]);
  if (!initial) {
    throw FunctionalError('Cant find element to update', { id, type });
  }
  if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
    throw FunctionalError('Cant find element references for commit', { id, references: opts.references });
  }
  // Individual check
  const { bypassIndividualUpdate } = opts;
  if (initial.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL && !isEmptyField(initial.contact_information) && !bypassIndividualUpdate) {
    const args = { filters: [{ key: 'user_email', values: [initial.contact_information] }], connectionFormat: false };
    const users = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], args);
    if (users.length > 0) {
      throw FunctionalError('Cannot update an individual corresponding to a user');
    }
  }
  if (updates.length === 0) {
    return { element: initial };
  }
  const updated = mergeInstanceWithUpdateInputs(initial, inputs);
  const entitySettings = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_ENTITY_SETTING);
  const keys = R.map((t) => t.key, attributes);
  if (entitySettings.get(initial.entity_type)?.enforce_reference || (entitySettings.get('stix-core-relationship')?.enforce_reference && isStixCoreRelationship(initial.entity_type))) {
    const isNoReferenceKey = noReferenceAttributes.includes(R.head(keys)) && keys.length === 1;
    if (!isNoReferenceKey && isEmptyField(opts.references)) {
      throw ValidationError('references', { message: 'You must provide at least one external reference to update' });
    }
  }
  let locksIds = getInstanceIds(initial);
  // 01. Check if updating alias lead to entity conflict
  if (isStixObjectAliased(initial.entity_type)) {
    // If user ask for aliases modification, we need to check if it not already belong to another entity.
    const isInputAliases = (input) => input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI;
    const aliasedInputs = R.filter((input) => isInputAliases(input), attributes);
    if (aliasedInputs.length > 0) {
      const aliases = R.uniq(aliasedInputs.map((a) => a.value).flat()
        .map((a) => a.trim())
        .filter((a) => isNotEmptyField(a)));
      const aliasesIds = generateAliasesId(aliases, initial);
      const existingEntities = await internalFindByIds(context, user, aliasesIds, { type: initial.entity_type });
      const differentEntities = R.filter((e) => e.internal_id !== initial.id, existingEntities);
      if (differentEntities.length > 0) {
        throw FunctionalError('This update will produce a duplicate', {
          id: initial.id,
          type,
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
      existingByHashedPromise = listEntitiesByHashes(user, initial.entity_type, updated.hashes)
        .then((entities) => entities.filter((e) => e.id !== id));
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
        const noneStandardKeys = Object.keys(elementsByKey).filter((k) => !isFieldContributingToStandardId(initial, [k]));
        const haveExtraKeys = noneStandardKeys.length > 0;
        if (haveExtraKeys) {
          throw UnsupportedError('This update can produce a merge, only one update action supported');
        }
        // Everything ok, let merge
        const target = existingEntities.shift();
        const sources = [updated, ...existingEntities];
        hashMergeValidation([target, ...sources]);
        const sourceEntityIds = sources.map((c) => c.internal_id);
        const merged = await mergeEntities(context, user, target.internal_id, sourceEntityIds, { locks: participantIds });
        logApp.info(`[OPENCTI] Success merge of entity ${merged.id}`);
        // Return merged element after waiting for it.
        return { element: merged };
      }
      // noinspection ExceptionCaughtLocallyJS
      throw FunctionalError('This update will produce a duplicate', {
        id: initial.id,
        type,
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
    const streamOpts = { publishStreamEvent: false, locks: participantIds };
    const attributeToEmbeddedRelation = fieldAttributeToEmbeddedRelation();
    for (let metaIndex = 0; metaIndex < meta.length; metaIndex += 1) {
      const { key: metaKey } = meta[metaIndex];
      const key = STIX_ATTRIBUTE_TO_META_FIELD[metaKey] || metaKey;
      // ref and _refs are expecting direct identifier in the value
      // We dont care about the operation here, the only thing we can do is replace
      if (isSingleStixEmbeddedRelationshipInput(key)) {
        const relType = attributeToEmbeddedRelation[key];
        const currentValue = updatedInstance[key];
        const { value: refIds } = meta[metaIndex];
        const targetCreated = R.head(refIds);
        // If asking for a real change
        if (currentValue?.standard_id !== targetCreated && currentValue?.id !== targetCreated) {
          // Delete the current relation
          if (currentValue?.standard_id) {
            const currentRels = await listAllRelations(context, user, relType, { fromId: initial.id });
            // eslint-disable-next-line no-use-before-define
            await deleteElements(context, user, currentRels, streamOpts);
          }
          // Create the new one
          if (isNotEmptyField(targetCreated)) {
            const inputRel = { fromId: id, toId: targetCreated, relationship_type: relType };
            // eslint-disable-next-line no-use-before-define
            await createRelationRaw(context, user, inputRel, streamOpts);
            const element = await internalLoadById(context, user, targetCreated);
            const previous = currentValue ? [currentValue] : currentValue;
            updatedInputs.push({ key, value: [element], previous });
            updatedInstance[key] = element;
            updatedInstance[relType] = updatedInstance[key].internal_id;
          } else if (currentValue) {
            // Just replace by nothing
            updatedInputs.push({ key, value: null, previous: [currentValue] });
            updatedInstance[key] = null;
            updatedInstance[relType] = null;
          }
        }
      } else {
        const relType = attributeToEmbeddedRelation[key];
        // Special access check for RELATION_GRANTED_TO meta
        if (relType === RELATION_GRANTED_TO && !userHaveCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
          throw ForbiddenAccess();
        }
        const { value: refs, operation = UPDATE_OPERATION_REPLACE } = meta[metaIndex];
        if (operation === UPDATE_OPERATION_REPLACE) {
          // Delete all relations
          const currentRels = await listAllRelations(context, user, relType, { fromId: id });
          const currentRelsToIds = currentRels.map((n) => n.toId);
          const newTargets = await internalFindByIds(context, user, refs);
          const newTargetsIds = newTargets.map((n) => n.id);
          if (R.symmetricDifference(newTargetsIds, currentRelsToIds).length > 0) {
            if (currentRels.length > 0) {
              // eslint-disable-next-line no-use-before-define
              await deleteElements(context, user, currentRels, streamOpts);
            }
            // 02. Create the new relations
            if (newTargets.length > 0) {
              for (let delIndex = 0; delIndex < refs.length; delIndex += 1) {
                const ref = refs[delIndex];
                const inputRel = { fromId: id, toId: ref, relationship_type: relType };
                // eslint-disable-next-line no-use-before-define
                await createRelationRaw(context, user, inputRel, streamOpts);
              }
            }
            updatedInputs.push({ key, value: newTargets, previous: updatedInstance[key] });
            updatedInstance[key] = newTargets;
            updatedInstance[relType] = updatedInstance[key].map((t) => t.internal_id);
          }
        }
        if (operation === UPDATE_OPERATION_ADD) {
          const currentIds = (updatedInstance[key] || []).map((o) => [o.id, o.standard_id]).flat();
          const refsToCreate = refs.filter((r) => !currentIds.includes(r));
          if (refsToCreate.length > 0) {
            const newTargets = await internalFindByIds(context, user, refsToCreate);
            for (let createIndex = 0; createIndex < refsToCreate.length; createIndex += 1) {
              const refToCreate = refsToCreate[createIndex];
              const inputRel = { fromId: id, toId: refToCreate, relationship_type: relType };
              // eslint-disable-next-line no-use-before-define
              await createRelationRaw(context, user, inputRel, streamOpts);
            }
            updatedInputs.push({ key, value: newTargets, operation });
            updatedInstance[key] = [...(updatedInstance[key] || []), ...newTargets];
            updatedInstance[relType] = updatedInstance[key].map((t) => t.internal_id);
          }
        }
        if (operation === UPDATE_OPERATION_REMOVE) {
          const targets = await internalFindByIds(context, user, refs);
          const targetIds = targets.map((t) => t.internal_id);
          const currentRels = await listAllRelations(context, user, relType, { fromId: id });
          const relsToDelete = currentRels.filter((c) => targetIds.includes(c.toId));
          if (relsToDelete.length > 0) {
            // eslint-disable-next-line no-use-before-define
            await deleteElements(context, user, relsToDelete, streamOpts);
            updatedInputs.push({ key, value: targets, operation });
            updatedInstance[key] = (updatedInstance[key] || []).filter((c) => !targetIds.includes(c.internal_id));
            updatedInstance[relType] = updatedInstance[key].map((t) => t.internal_id);
          }
        }
      }
    }
    // endregion
    // Only push event in stream if modifications really happens
    if (updatedInputs.length > 0) {
      const message = generateUpdateMessage(updatedInputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage,
        external_references: references.map((ref) => convertExternalReferenceToStix(ref))
      } : undefined;
      const event = await storeUpdateEvent(context, user, initial, updatedInstance, message, { ...opts, commit });
      return { element: updatedInstance, event };
    }
    // Post-operation to update the individual linked to a user
    if (updatedInstance.entity_type === ENTITY_TYPE_USER) {
      const args = { filters: [{ key: 'contact_information', values: [updatedInstance.user_email] }], connectionFormat: false };
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
export const patchAttributeRaw = async (context, user, instance, patch, opts = {}) => {
  const inputs = transformPatchToInput(patch, opts.operations);
  return updateAttributeRaw(context, user, instance, inputs, opts);
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
  logApp.info('Upsert inferred relation', { relation: patch });
  return await patchAttribute(context, RULE_MANAGER_USER, instance.id, instance.entity_type, patch, opts);
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
    relationAttributes.spec_version = STIX_SPEC_VERSION;
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
  checkRelationConsistency(type, from, to);
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
    relations.push(basicRelation);
  }
  return relations;
};
const upsertIdentifiedFields = async (context, user, element, input, fields) => {
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
      const patched = await patchAttributeRaw(context, user, element, patch, { upsert: true });
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

const upsertElementRaw = async (context, user, element, type, updatePatch) => {
  // Upsert relation
  // If confidence is passed at creation, just compare confidence
  // Else check if update is explicitly true
  const forceUpdate = updatePatch.confidence ? updatePatch.confidence >= element.confidence : updatePatch.update === true;
  const patchInputs = []; // Sourced inputs for event stream
  const impactedInputs = []; // All inputs impacted by modifications (+inner)
  const rawRelations = [];
  // Handle attributes updates
  if (isNotEmptyField(updatePatch.stix_id) || isNotEmptyField(updatePatch.x_opencti_stix_ids)) {
    const ids = [...(updatePatch.x_opencti_stix_ids || [])];
    if (isNotEmptyField(updatePatch.stix_id) && updatePatch.stix_id !== element.standard_id) {
      ids.push(updatePatch.stix_id);
    }
    if (ids.length > 0) {
      const patch = { x_opencti_stix_ids: ids };
      const operations = { x_opencti_stix_ids: UPDATE_OPERATION_ADD };
      const patched = await patchAttributeRaw(context, user, element, patch, { operations, upsert: true });
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  // Upsert observed data
  if (type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    const timePatch = handleRelationTimeUpdate(updatePatch, element, 'first_observed', 'last_observed');
    // Upsert the count only if a time patch is applied.
    if (isNotEmptyField(timePatch)) {
      const basePatch = { number_observed: element.number_observed + updatePatch.number_observed };
      const patch = { ...basePatch, ...timePatch };
      const patched = await patchAttributeRaw(context, user, element, patch, { upsert: true });
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  // Upsert relations
  if (isStixCoreRelationship(type)) {
    const basePatch = {};
    if (updatePatch.confidence && forceUpdate) {
      basePatch.confidence = updatePatch.confidence;
    }
    if (updatePatch.description && forceUpdate) {
      basePatch.description = updatePatch.description;
    }
    const timePatch = handleRelationTimeUpdate(updatePatch, element, 'start_time', 'stop_time');
    const patch = { ...basePatch, ...timePatch };
    if (isNotEmptyField(patch)) {
      const patched = await patchAttributeRaw(context, user, element, patch, { upsert: true });
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  if (isStixSightingRelationship(type)) {
    const basePatch = {};
    if (updatePatch.confidence && forceUpdate) {
      basePatch.confidence = updatePatch.confidence;
    }
    if (updatePatch.description && forceUpdate) {
      basePatch.description = updatePatch.description;
    }
    const timePatch = handleRelationTimeUpdate(updatePatch, element, 'first_seen', 'last_seen');
    const countPatch = isNotEmptyField(timePatch) ? { attribute_count: element.attribute_count + updatePatch.attribute_count, ...timePatch } : {};
    const patch = { ...basePatch, ...countPatch };
    if (isNotEmptyField(patch)) {
      const patched = await patchAttributeRaw(context, user, element, patch, { upsert: true });
      impactedInputs.push(...patched.impactedInputs);
      patchInputs.push(...patched.updatedInputs);
    }
  }
  // Upsert entities
  const upsertAttributes = schemaTypes.getUpsertAttributes(type);
  if (isInternalObject(type) && forceUpdate) {
    const {
      upsertImpacted,
      upsertUpdated
    } = await upsertIdentifiedFields(context, user, element, updatePatch, upsertAttributes);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  if (isStixDomainObject(type) && forceUpdate) {
    const {
      upsertImpacted,
      upsertUpdated
    } = await upsertIdentifiedFields(context, user, element, updatePatch, upsertAttributes);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  if (isStixMetaObject(type) && forceUpdate) {
    const {
      upsertImpacted,
      upsertUpdated
    } = await upsertIdentifiedFields(context, user, element, updatePatch, upsertAttributes);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  // Upsert SCOs
  if (isStixCyberObservable(type) && forceUpdate) {
    const {
      upsertImpacted,
      upsertUpdated
    } = await upsertIdentifiedFields(context, user, element, updatePatch, upsertAttributes);
    impactedInputs.push(...upsertImpacted);
    patchInputs.push(...upsertUpdated);
  }
  // If file directly attached
  if (!isEmptyField(updatePatch.file)) {
    const meta = { entity_id: element.internal_id };
    const file = await upload(context, user, `import/${element.entity_type}/${element.internal_id}`, updatePatch.file, meta);
    const ins = { key: 'x_opencti_files', value: [storeFileConverter(user, file)], operation: UPDATE_OPERATION_ADD };
    impactedInputs.push(ins);
    patchInputs.push(ins);
  }
  // region upsert refs
  const createdTargets = [];
  const removedTargets = [];
  const buildInstanceRelTo = (to, relType) => buildInnerRelation(element, to, relType);
  // region cyber observable
  // -- Upsert multiple refs specific for cyber observable
  const obsInputFields = stixCyberObservableFieldsForType(type);
  for (let fieldIndex = 0; fieldIndex < obsInputFields.length; fieldIndex += 1) {
    const inputField = obsInputFields[fieldIndex];
    if (MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS.includes(inputField)) {
      const stixField = STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[inputField];
      const existingInstances = element[CYBER_OBSERVABLE_FIELD_TO_META_RELATION[inputField]] || [];
      const patchInputData = updatePatch[inputField] ?? [];
      const instancesToCreate = R.filter((m) => !existingInstances.includes(m.internal_id), patchInputData);
      const relType = STIX_ATTRIBUTE_TO_CYBER_RELATIONS[stixField];
      if (instancesToCreate.length > 0) {
        const newRelations = instancesToCreate.map((to) => R.head(buildInstanceRelTo(to, relType)));
        rawRelations.push(...newRelations);
        patchInputs.push({ key: inputField, value: instancesToCreate, operation: UPDATE_OPERATION_ADD });
        createdTargets.push({ key: inputField, instances: instancesToCreate });
      }
      // Handle full synchronization for granted refs if specified
      if (inputField === INPUT_GRANTED_REFS && updatePatch[inputField]) {
        const instancesToRemove = existingInstances.filter((m) => !patchInputData.map((u) => u.internal_id).includes(m));
        if (instancesToRemove.length > 0) {
          const currentRels = await listAllRelations(context, user, relType, {
            fromId: element.internal_id,
            toId: instancesToRemove
          });
          await deleteElements(context, user, currentRels, { publishStreamEvent: false });
          const targetsInstances = await internalFindByIds(context, user, instancesToRemove);
          patchInputs.push({ key: inputField, value: targetsInstances, operation: UPDATE_OPERATION_REMOVE });
          removedTargets.push({ key: inputField, instances: targetsInstances });
        }
      }
    }
  }
  // -- Upsert single refs specific for cyber observable
  // TODO JRI Upsert single refs specific for cyber observable
  // endregion
  // region generic elements
  // -- Upsert multiple refs for other stix elements
  const metaInputFields = STIX_META_RELATIONSHIPS_INPUTS;
  for (let fieldIndex = 0; fieldIndex < metaInputFields.length; fieldIndex += 1) {
    const inputField = metaInputFields[fieldIndex];
    if (MULTIPLE_META_RELATIONSHIPS_INPUTS.includes(inputField)) {
      const relType = fieldToMetaRelation()[inputField];
      const existingInstances = element[relType] || [];
      const patchInputData = updatePatch[inputField] ?? [];
      const instancesToCreate = R.filter((m) => !existingInstances.includes(m.internal_id), patchInputData);
      if (instancesToCreate.length > 0) {
        const newRelations = instancesToCreate.map((to) => R.head(buildInstanceRelTo(to, relType)));
        rawRelations.push(...newRelations);
        patchInputs.push({ key: inputField, value: instancesToCreate, operation: UPDATE_OPERATION_ADD });
        createdTargets.push({ key: inputField, instances: instancesToCreate });
      }
      // Handle full synchronization for granted refs if specified
      if (inputField === INPUT_GRANTED_REFS && updatePatch[inputField]) {
        const instancesToRemove = existingInstances.filter((m) => !patchInputData.map((u) => u.internal_id).includes(m));
        if (instancesToRemove.length > 0) {
          const currentRels = await listAllRelations(context, user, relType, {
            fromId: element.internal_id,
            toId: instancesToRemove
          });
          await deleteElements(context, user, currentRels, { publishStreamEvent: false });
          const targetsInstances = await internalFindByIds(context, user, instancesToRemove);
          patchInputs.push({ key: inputField, value: targetsInstances, operation: UPDATE_OPERATION_REMOVE });
          removedTargets.push({ key: inputField, instances: targetsInstances });
        }
      }
    }
  }
  // -- Upsert single refs specific for generic
  // TODO JRI Upsert single refs specific for generic
  // endregion
  // If modification must be done, reload the instance with dependencies to allow complete stix generation
  if (impactedInputs.length > 0 && patchInputs.length === 0) {
    throw UnsupportedError('[OPENCTI] Upsert will produce only internal modification', {
      element,
      impact: impactedInputs
    });
  }
  const isUpdated = impactedInputs.length > 0 || rawRelations.length > 0 || removedTargets.length > 0;
  // Manage update_at
  if (isUpdated && isUpdatedAtObject(element.entity_type)) {
    const updatedAtInput = { key: 'updated_at', value: [now()] };
    impactedInputs.push(updatedAtInput);
  }
  // -------------------------------------------------------------------
  // All impacted elements must be before that lines
  // -------------------------------------------------------------------
  if (isUpdated) {
    // Resolve dependencies.
    const resolvedInstance = await loadElementWithDependencies(context, user, element, { onlyMarking: false });
    const updatedInstance = mergeInstanceWithInputs(resolvedInstance, impactedInputs);
    // Apply relations create to updatedInstance
    for (let index = 0; index < createdTargets.length; index += 1) {
      const createdTarget = createdTargets[index];
      updatedInstance[createdTarget.key] = [...(resolvedInstance[createdTarget.key] ?? []), ...createdTarget.instances];
    }
    for (let indexRemove = 0; indexRemove < removedTargets.length; indexRemove += 1) {
      const removedTarget = removedTargets[indexRemove];
      resolvedInstance[removedTarget.key] = [...(resolvedInstance[removedTarget.key] ?? []), ...removedTarget.instances];
    }
    // Return the built elements
    return {
      type: TRX_UPDATE,
      update: impactedInputs.length > 0 ? partialInstanceWithInputs(element, impactedInputs) : undefined, // For indexation
      element: updatedInstance,
      message: generateUpdateMessage(patchInputs),
      previous: resolvedInstance,
      relations: rawRelations, // Added meta relationships
    };
  }
  // No update done, return IDLE action
  return { type: TRX_IDLE, element, relations: [] };
};

const buildRelationData = async (context, user, input, opts = {}) => {
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
  data.creator_id = user.internal_id;
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
      // Get statuses
      const platformStatuses = await getEntitiesFromCache(context, user, ENTITY_TYPE_STATUS);
      const statusesForType = platformStatuses.filter((p) => p.type === type);
      if (statusesForType.length > 0) {
        data[X_WORKFLOW_ID] = R.head(statusesForType).id;
      }
    }
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
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
    // because spec is only put in all stix except meta, and stix cyber observable is a meta but requires this
    data.spec_version = STIX_SPEC_VERSION;
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
  // For organizations management
  if (userHaveCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
    relToCreate.push(...buildInnerRelation(data, input[INPUT_GRANTED_REFS], RELATION_GRANTED_TO));
  } else if (!user.inside_platform_organization) {
    // If user is not part of the platform organization, put its own organizations
    relToCreate.push(...buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
  }
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
  return {
    type: TRX_CREATION,
    element: created,
    previous: null,
    relations: relToCreate
  };
};
export const createRelationRaw = async (context, user, input, opts = {}) => {
  let lock;
  const { fromRule, locks = [] } = opts;
  const { fromId, toId, relationship_type: relationshipType } = input;
  // Enforce reference controls
  if (isStixCoreRelationship(relationshipType)) {
    const entitySettings = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_ENTITY_SETTING);
    if (entitySettings.get('stix-core-relationship')?.enforce_reference) {
      if (isEmptyField(input.externalReferences)) {
        throw ValidationError('externalReferences', {
          message: 'You must provide at least one external reference to create a relationship',
        });
      }
    }
  }
  // Pre-check before inputs resolution
  if (fromId === toId) {
    /* istanbul ignore next */
    const errorData = { from: input.fromId, relationshipType };
    throw UnsupportedError('Relation cant be created with the same source and target', { error: errorData });
  }
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(context, user, input, relationshipType);
  const { from, to } = resolvedInput;
  // Check consistency
  checkRelationConsistency(relationshipType, from, to);
  // In some case from and to can be resolved to the same element (because of automatic merging)
  if (from.internal_id === to.internal_id) {
    /* istanbul ignore next */
    if (relationshipType === RELATION_REVOKED_BY) {
      // Because of entity merging, we can receive some revoked-by on the same internal id element
      // In this case we need to revoke the fromId stixId of the relation
      // TODO Handle RELATION_REVOKED_BY special case
    }
    const errorData = { from: input.fromId, to: input.toId, relationshipType };
    throw UnsupportedError('Relation cant be created with the same source and target', { error: errorData });
  }
  // It's not possible to create a single ref relationship if one already exists
  if (isSingleStixEmbeddedRelationship(relationshipType)) {
    const key = stixEmbeddedRelationToField()[relationshipType];
    if (isNotEmptyField(resolvedInput.from[key])) {
      const errorData = { from: input.fromId, to: input.toId, relationshipType };
      throw UnsupportedError('Cant add another relation on single ref', { error: errorData });
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
      const timeFilters = buildRelationTimeFilter(resolvedInput);
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
        return await upsertRelationRule(context, existingRelationship, input, { ...opts, locks: participantIds });
      }
      // If not upsert the element
      dataRel = await upsertElementRaw(context, user, existingRelationship, relationshipType, resolvedInput);
    } else {
      // Check cyclic reference consistency for embedded relationships before creation
      if (isStixEmbeddedRelationship(relationshipType)) {
        const toRefs = instanceMetaRefsExtractor(relationshipType, fromRule !== undefined, to);
        // We are using rel_ to resolve STIX embedded refs, but in some cases it's not a cyclic relationships
        // Checking the direction of the relation to allow relationships
        if (toRefs.includes(from.internal_id) && isRelationConsistent(relationshipType, to, from)) {
          throw FunctionalError(`You cant create a cyclic relation between ${from.standard_id} and ${to.standard_id}`);
        }
      }
      // Just build a standard relationship
      dataRel = await buildRelationData(context, user, resolvedInput, opts);
    }
    // Index the created element
    await indexCreatedElement(context, user, dataRel);
    // Push the input in the stream
    let event;
    if (dataRel.type === TRX_CREATION) {
      // In case on embedded relationship creation, we need to dispatch
      // an update of the from entity that host this embedded ref.
      if (isStixEmbeddedRelationship(relationshipType)) {
        const previous = resolvedInput.from; // Complete resolution done by the input resolver
        const targetElement = { ...resolvedInput.to, i_relation: resolvedInput };
        const instance = R.clone(previous);
        const key = stixEmbeddedRelationToField()[relationshipType];
        if (isSingleStixEmbeddedRelationship(relationshipType)) {
          const inputs = [{ key, value: [targetElement] }];
          const message = generateUpdateMessage(inputs);
          // Generate the new version of the from
          instance[key] = targetElement;
          event = await storeUpdateEvent(context, user, previous, instance, message, opts);
        } else {
          const inputs = [{ key, value: [targetElement], operation: UPDATE_OPERATION_ADD }];
          const message = generateUpdateMessage(inputs);
          // Generate the new version of the from
          instance[key] = [...(instance[key] ?? []), targetElement];
          event = await storeUpdateEvent(context, user, previous, instance, message, opts);
        }
      } else {
        const createdRelation = { ...resolvedInput, ...dataRel.element };
        event = await storeCreateRelationEvent(context, user, createdRelation, opts);
      }
    } else if (dataRel.type === TRX_UPDATE) {
      event = await storeUpdateEvent(context, user, dataRel.previous, dataRel.element, dataRel.message, opts);
    }
    // - TRANSACTION END
    return { element: dataRel.element, event, isCreation: dataRel.type === TRX_CREATION };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
export const createRelation = async (context, user, input) => {
  const data = await createRelationRaw(context, user, input);
  return data.element;
};
export const createInferredRelation = async (context, input, ruleContent, opts = {}) => {
  const args = { ...opts, fromRule: ruleContent.field };
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
/* istanbul ignore next */
export const createRelations = async (context, user, inputs) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improved by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    const relation = await createRelation(context, user, inputs[i]);
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
    R.assoc('creator_id', user.internal_id),
    R.dissoc('update'),
    R.dissoc('file'),
    R.omit(STIX_META_RELATIONSHIPS_INPUTS),
    R.omit(STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS),
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
    const platformStatuses = await getEntitiesFromCache(context, user, ENTITY_TYPE_STATUS);
    const statusesForType = platformStatuses.filter((p) => p.type === type);
    if (statusesForType.length > 0) {
      data = R.assoc(X_WORKFLOW_ID, R.head(statusesForType).id, data);
    }
  }
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    if (input.aliases) {
      data.aliases = R.uniq(input.aliases.map((a) => a.trim()).filter((a) => isNotEmptyField(a)));
    }
    if (input.x_opencti_aliases) {
      data.x_opencti_aliases = R.uniq(input.x_opencti_aliases.map((a) => a.trim()).filter((a) => isNotEmptyField(a)));
    }
    data = R.assoc(INTERNAL_IDS_ALIASES, generateAliasesIdsForInstance(data), data);
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
  // Create the meta relationships (ref, refs)
  const relToCreate = [];
  const isSegregationEntity = !STIX_ORGANIZATIONS_UNRESTRICTED.some((o) => getParentTypes(data.entity_type).includes(o));
  const appendMetaRelationships = (inputField, relType) => {
    if (input[inputField] || relType === RELATION_GRANTED_TO) {
      // For organizations management
      if (relType === RELATION_GRANTED_TO && isSegregationEntity) {
        if (userHaveCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && input[inputField]) {
          relToCreate.push(...buildInnerRelation(data, input[inputField], RELATION_GRANTED_TO));
        } else if (!user.inside_platform_organization) {
          // If user is not part of the platform organization, put its own organizations
          relToCreate.push(...buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
        }
      } else if (input[inputField]) {
        const instancesToCreate = Array.isArray(input[inputField]) ? input[inputField] : [input[inputField]];
        relToCreate.push(...buildInnerRelation(data, instancesToCreate, relType));
      }
    }
  };
  // For meta stix core
  if (isStixCoreObject(type)) {
    const inputFields = STIX_META_RELATIONSHIPS_INPUTS;
    for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
      const inputField = inputFields[fieldIndex];
      const relType = fieldToMetaRelation()[inputField];
      appendMetaRelationships(inputField, relType);
    }
  }
  // For meta observables
  if (isStixCyberObservable(type)) {
    const inputFields = stixCyberObservableFieldsForType(type);
    for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
      const inputField = inputFields[fieldIndex];
      const stixField = STIX_CYBER_OBSERVABLE_FIELD_TO_STIX_ATTRIBUTE[inputField];
      const relType = STIX_ATTRIBUTE_TO_CYBER_RELATIONS[stixField];
      appendMetaRelationships(inputField, relType);
    }
  }

  // Transaction succeed, complete the result to send it back
  const created = R.pipe(
    R.assoc('id', internalId),
    R.assoc('base_type', BASE_TYPE_ENTITY),
    R.assoc('parent_types', getParentTypes(type))
  )(data);
  // If file directly attached
  if (!isEmptyField(input.file)) {
    const meta = { entity_id: created.internal_id };
    const file = await upload(context, user, `import/${created.entity_type}/${created.internal_id}`, input.file, meta);
    created.x_opencti_files = [storeFileConverter(user, file)];
  }

  // Simply return the data
  return {
    type: TRX_CREATION,
    update: null,
    element: created,
    message: generateCreateMessage(created),
    previous: null,
    relations: relToCreate, // Added meta relationships
  };
};
const userHaveCapability = (user, capability) => {
  const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
  return userCapabilities.includes(BYPASS) || userCapabilities.includes(capability);
};
const createEntityRaw = async (context, user, input, type, opts = {}) => {
  const entitySettings = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_ENTITY_SETTING);
  const isAllowedToByPass = userHaveCapability(user, BYPASS_REFERENCE);
  if (!isAllowedToByPass && entitySettings.get(type)?.enforce_reference) {
    if (isEmptyField(input.externalReferences)) {
      throw ValidationError('externalReferences', {
        message: 'You must provide at least one external reference for this type of entity',
      });
    }
  }
  const { fromRule } = opts;
  // We need to check existing dependencies
  const resolvedInput = await inputResolveRefs(context, user, input, type);
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
        dataEntity = await upsertElementRaw(context, user, R.head(filteredEntities), type, resolvedInput);
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
          await mergeEntities(context, user, target.internal_id, sources.map((s) => s.internal_id), { locks: participantIds });
          dataEntity = await upsertElementRaw(context, user, target, type, resolvedInput);
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
          const key = resolveAliasesField(type);
          const concurrentAliases = R.flatten(R.map((c) => [c[key], c.name], concurrentEntities));
          const normedAliases = R.uniq(concurrentAliases.map((c) => normalizeName(c)));
          const filteredAliases = R.filter((i) => !normedAliases.includes(normalizeName(i)), resolvedInput[key] || []);
          const inputAliases = { ...resolvedInput, [key]: filteredAliases };
          dataEntity = await upsertElementRaw(context, user, existingByStandard, type, inputAliases);
        } else {
          // If not we dont know what to do, just throw an exception.
          throw UnsupportedError('Cant upsert entity. Too many entities resolved', { input, entityIds });
        }
      }
    } else {
      // Create the object
      dataEntity = await buildEntityData(context, user, resolvedInput, type, opts);
    }
    // Index the created element
    await indexCreatedElement(context, user, dataEntity);
    // Push the input in the stream
    let event;
    if (dataEntity.type === TRX_CREATION) {
      const createdElement = { ...resolvedInput, ...dataEntity.element };
      event = await storeCreateEntityEvent(context, user, createdElement, dataEntity.message, opts);
    } else if (dataEntity.type === TRX_UPDATE) {
      event = await storeUpdateEvent(context, user, dataEntity.previous, dataEntity.element, dataEntity.message, opts);
    }
    // Return created element after waiting for it.
    return { element: dataEntity.element, event, isCreation: dataEntity.type === TRX_CREATION };
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const createEntity = async (context, user, input, type) => {
  // volumes of objects relationships must be controlled
  if (input.objects && input.objects.length > MAX_BATCH_SIZE) {
    const objectSequences = R.splitEvery(MAX_BATCH_SIZE, input.objects);
    const firstSequence = objectSequences.shift();
    const subObjectsEntity = R.assoc(INPUT_OBJECTS, firstSequence, input);
    const created = await createEntityRaw(context, user, subObjectsEntity, type);
    // For each subsequences of objects
    // We need to produce a batch upsert of object that will be upserted.
    for (let index = 0; index < objectSequences.length; index += 1) {
      const objectSequence = objectSequences[index];
      const upsertInput = R.assoc(INPUT_OBJECTS, objectSequence, input);
      await createEntityRaw(context, user, upsertInput, type);
    }
    return created.element;
  }
  const data = await createEntityRaw(context, user, input, type);
  // In case of creation, start an enrichment
  if (data.isCreation) {
    await createEntityAutoEnrichment(context, user, data.element.id, type);
  }
  return data.element;
};
export const createInferredEntity = async (context, input, ruleContent, type) => {
  const opts = { fromRule: ruleContent.field, impactStandardId: false };
  // Inferred entity have a specific standardId generated from dependencies data.
  const standardId = idGenFromData(type, ruleContent.content.dependencies.sort());
  const instance = { standard_id: standardId, ...input, [ruleContent.field]: [ruleContent.content] };
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
    throw FunctionalError('Cant find element to delete', { id });
  }
  // Prevent individual deletion if linked to a user
  if (element.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL && !isEmptyField(element.contact_information)) {
    const args = { filters: [{ key: 'user_email', values: [element.contact_information] }], connectionFormat: false };
    const users = await listEntities(context, SYSTEM_USER, [ENTITY_TYPE_USER], args);
    if (users.length > 0) {
      throw FunctionalError('Cannot delete an individual corresponding to a user');
    }
  }
  // Check inference operation
  checkIfInferenceOperationIsValid(user, element);
  // Apply deletion
  const participantIds = [element.internal_id];
  try {
    // Try to get the lock in redis
    lock = await lockResource(participantIds);
    if (isStixEmbeddedRelationship(element.entity_type)) {
      const targetElement = { ...element.to, i_relation: element };
      const previous = await storeLoadByIdWithRefs(context, user, element.fromId);
      const key = stixEmbeddedRelationToField()[element.entity_type];
      const instance = R.clone(previous);
      let message;
      if (isSingleStixEmbeddedRelationship(element.entity_type)) {
        const inputs = [{ key, value: [] }];
        message = generateUpdateMessage(inputs);
        instance[key] = undefined; // Generate the new version of the from
      } else {
        const inputs = [{ key, value: [targetElement], operation: UPDATE_OPERATION_REMOVE }];
        message = generateUpdateMessage(inputs);
        // To prevent to many patch operations, removed key must be put at the end
        const withoutElementDeleted = (previous[key] ?? []).filter((e) => e.internal_id !== targetElement.internal_id);
        previous[key] = [...withoutElementDeleted, targetElement];
        // Generate the new version of the from
        instance[key] = withoutElementDeleted;
      }
      const taskPromise = createContainerSharingTask(context, ACTION_TYPE_UNSHARE, element);
      const deletePromise = elDeleteElements(context, user, [element], storeLoadByIdWithRefs);
      const eventPromise = storeUpdateEvent(context, user, previous, instance, message, opts);
      const [, , updateEvent] = await Promise.all([taskPromise, deletePromise, eventPromise]);
      event = updateEvent;
    } else {
      // Start by deleting external files
      const importDeletePromise = deleteAllFiles(context, user, `import/${element.entity_type}/${element.internal_id}/`);
      const exportDeletePromise = deleteAllFiles(context, user, `export/${element.entity_type}/${element.internal_id}/`);
      await Promise.all([importDeletePromise, exportDeletePromise]);
      // Delete all linked elements
      const dependencyDeletions = await elDeleteElements(context, user, [element], storeLoadByIdWithRefs);
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
const deleteElements = async (context, user, elements, opts = {}) => {
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    await deleteElementById(context, user, element.internal_id, element.entity_type, opts);
  }
};
export const deleteElementById = async (context, user, elementId, type, opts = {}) => {
  if (R.isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError('You need to specify a type when deleting an entity');
  }
  const { element: deleted } = await internalDeleteElementById(context, user, elementId, opts);
  return deleted.internal_id;
};
export const deleteInferredRuleElement = async (rule, instance, deletedDependencies, opts = {}) => {
  const context = executionContext(rule.name, RULE_MANAGER_USER);
  // Check if deletion is really targeting an inference
  const isInferred = isInferredIndex(instance._index);
  if (!isInferred) {
    throw UnsupportedError(`Instance ${instance.id} is not inferred, cant be deleted`);
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
        logApp.info('Delete inferred element', { rule, id: instance.id });
        const deletionData = await internalDeleteElementById(context, RULE_MANAGER_USER, instance.id, opts);
        logApp.info('Delete inferred element', { id: instance.id, type: instance.entity_type });
        return deletionData.event;
      }
      // If not we need to clean the rule and keep the element for other rules.
      logApp.info('Cleanup inferred element', { rule, id: instance.id });
      const input = { [completeRuleName]: null };
      const upsertOpts = { fromRule, ruleOverride: true };
      const { event } = await upsertRelationRule(context, instance, input, upsertOpts);
      return event;
    }
    logApp.info('Upsert inferred element', { rule, id: instance.id });
    // Rule still have other explanation, update the rule
    const input = { [completeRuleName]: rebuildRuleContent };
    const ruleOpts = { fromRule, ruleOverride: true };
    const { event } = await upsertRelationRule(context, instance, input, ruleOpts);
    return event;
  } catch (e) {
    logApp.error('Error deleting inference', { error: e.message });
  }
  return undefined;
};
export const deleteRelationsByFromAndTo = async (context, user, fromId, toId, relationshipType, scopeType, opts = {}) => {
  /* istanbul ignore if */
  if (R.isNil(scopeType) || R.isNil(fromId) || R.isNil(toId)) {
    throw FunctionalError('You need to specify a scope type when deleting a relation with from and to');
  }
  const fromThing = await internalLoadById(context, user, fromId, opts);
  const toThing = await internalLoadById(context, user, toId, opts);
  // Looks like the caller doesnt give the correct from, to currently
  const relationsToDelete = await elFindByFromAndTo(context, user, fromThing.internal_id, toThing.internal_id, relationshipType);
  for (let i = 0; i < relationsToDelete.length; i += 1) {
    const r = relationsToDelete[i];
    await deleteElementById(context, user, r.internal_id, r.entity_type);
  }
  return true;
};
// endregion
