import moment from 'moment';
import * as R from 'ramda';
import DataLoader from 'dataloader';
import Bluebird, { Promise as BluePromise } from 'bluebird';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { compareUnsorted } from 'js-deep-equals';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import * as jsonpatch from 'fast-json-patch';
import nconf from 'nconf';
import {
  AccessRequiredError,
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
import { extractEntityRepresentativeName } from './entity-representative';
import {
  computeAverage,
  extractIdsFromStoreObject,
  extractObjectsPirsFromInputs,
  extractObjectsRestrictionsFromInputs,
  fillTimeSeries,
  INDEX_INFERRED_RELATIONSHIPS,
  inferIndexFromConceptType,
  isEmptyField,
  isInferredIndex,
  isNotEmptyField,
  isObjectPathTargetMultipleAttribute,
  READ_DATA_INDICES,
  READ_DATA_INDICES_INFERRED,
  READ_INDEX_HISTORY,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_RELATIONSHIPS_INDICES,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE,
} from './utils';
import {
  type AggregationRelationsCount,
  elAggregationCount,
  elAggregationRelationsCount,
  elConnection,
  elDeleteElements,
  elFindByIds,
  type ElFindByIdsOpts,
  elHistogramCount,
  elIndexElements,
  elList,
  elMarkElementsAsDraftDelete,
  elPaginate,
  elUpdateElement,
  elUpdateEntityConnections,
  elUpdateRelationConnections,
  ES_MAX_CONCURRENCY,
  ES_MAX_PAGINATION,
  type HistogramCountOpts,
  isImpactedTypeAndSide,
  MAX_BULK_OPERATIONS,
  type RepaginateOpts,
  ROLE_FROM,
  ROLE_TO,
} from './engine';
import {
  FIRST_OBSERVED,
  FIRST_SEEN,
  generateAliasesId,
  generateHashedObservableStandardIds,
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
import { notify, redisAddDeletions } from './redis';
import { storeCreateEntityEvent, storeCreateRelationEvent, storeDeleteEvent, storeMergeEvent, storeUpdateEvent } from './stream/stream-handler';
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
  INPUT_CREATED_BY,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INTERNAL_IDS_ALIASES,
  INTERNAL_PREFIX,
  REL_INDEX_PREFIX,
  RULE_PREFIX,
} from '../schema/general';
import { isAnId, isValidDate } from '../schema/schemaUtils';
import {
  isStixRefRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_GRANTED_TO,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  STIX_REF_RELATIONSHIP_TYPES,
} from '../schema/stixRefRelationship';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isBasicRelationship } from '../schema/stixRelationship';
import {
  dateForEndAttributes,
  dateForLimitsAttributes,
  dateForStartAttributes,
  extractNotFuzzyHashValues,
  isModifiedObject,
  isUpdatedAtObject,
  noReferenceAttributes,
} from '../schema/fieldDataAdapter';
import { isStixCoreRelationship, RELATION_REVOKED_BY, RELATION_TARGETS, RELATION_USES } from '../schema/stixCoreRelationship';
import {
  ATTRIBUTE_ADDITIONAL_NAMES,
  ATTRIBUTE_ALIASES,
  ATTRIBUTE_ALIASES_OPENCTI,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObjectIdentity,
  isStixDomainObjectShareableContainer,
  isStixObjectAliased,
  resolveAliasesField,
  STIX_ORGANIZATIONS_UNRESTRICTED,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, isStixCyberObservable, isStixCyberObservableHashedObservable } from '../schema/stixCyberObservable';
import conf, { BUS_TOPICS, extendedErrors, logApp } from '../config/conf';
import { computeDateFromEventId, FROM_START_STR, mergeDeepRightAll, now, prepareDate, UNTIL_END_STR, utcDate } from '../utils/format';
import { checkObservableSyntax } from '../utils/syntax';
import { elUpdateRemovedFiles } from './file-search';
import {
  AccessOperation,
  CONTAINER_SHARING_USER,
  controlUserRestrictDeleteAgainstElement,
  executionContext,
  isBypassUser,
  isMarkingAllowed,
  isOrganizationAllowed,
  isUserCanAccessStoreElement,
  isUserHasCapability,
  KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE,
  KNOWLEDGE_ORGANIZATION_RESTRICT,
  RULE_MANAGER_USER,
  SYSTEM_USER,
  userFilterStoreElements,
  validateUserAccessOperation,
} from '../utils/access';
import { isRuleUser, RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules-utils';
import { instanceMetaRefsExtractor, isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { createEntityAutoEnrichment, updateEntityAutoEnrichment } from '../domain/enrichment';
import { convertExternalReferenceToStix, convertStoreToStix_2_1 } from './stix-2-1-converter';
import { convertStoreToStix } from './stix-common-converter';
import {
  buildAggregationRelationFilter,
  buildEntityFilters,
  buildThingsFilters,
  type EntityFilters,
  type EntityOptions,
  fullEntitiesThroughRelationsToList,
  fullRelationsList,
  internalFindByIds,
  internalLoadById,
  type RelationFilters,
  storeLoadById,
  topEntitiesList,
  topRelationsList,
} from './middleware-loader';
import { checkRelationConsistency, isRelationConsistent } from '../utils/modelConsistency';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache } from './cache';
import { ACTION_TYPE_SHARE, ACTION_TYPE_UNSHARE, createListTask } from '../domain/backgroundTask-common';
import { type BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY, vocabularyDefinitions } from '../modules/vocabulary/vocabulary-types';
import { getVocabulariesCategories, getVocabularyCategoryForField, isEntityFieldAnOpenVocabulary, updateElasticVocabularyValue } from '../modules/vocabulary/vocabulary-utils';
import { depsKeysRegister, isDateAttribute, isMultipleAttribute, isNumericAttribute, isObjectAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import { fillDefaultValues, getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { validateInputCreation, validateInputUpdate } from '../schema/schema-validator';
import { telemetry } from '../config/tracing';
import { cleanMarkings, handleMarkingOperations } from '../utils/markingDefinition-utils';
import { buildUpdatePatchForUpsert, generateInputsForUpsert } from '../utils/upsert-utils';
import { generateCreateMessage, generateRestoreMessage, generateUpdatePatchMessage, getKeyName, getKeyValuesFromPatchElements } from './generate-message';
import {
  authorizedMembers,
  authorizedMembersActivationDate,
  confidence,
  creators as creatorsAttribute,
  iAliasedIds,
  iAttributes,
  modified,
  type RefAttribute,
  updatedAt,
} from '../schema/attribute-definition';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { type EditInput, EditOperation, FilterMode, FilterOperator, Version, type Vulnerability } from '../generated/graphql';
import { getMandatoryAttributesForSetting } from '../modules/entitySetting/entitySetting-attributeUtils';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, type StoreEntityOrganization } from '../modules/organization/organization-types';
import {
  adaptUpdateInputsConfidence,
  controlCreateInputWithUserConfidence,
  controlUpsertInputWithUserConfidence,
  controlUserConfidenceAgainstElement,
  type ObjectWithConfidence,
  shouldCheckConfidenceOnRefRelationship,
} from '../utils/confidence-level';
import { buildEntityData, buildInnerRelation, buildRelationData } from './data-builder';
import { isIndividualAssociatedToUser, verifyCanDeleteIndividual, verifyCanDeleteOrganization } from './data-consistency';
import { deleteAllObjectFiles, moveAllFilesFromEntityToAnother, storeFileConverter, uploadToStorage } from './file-storage';
import { getFileContent } from './raw-file-storage';
import { getDraftContext } from '../utils/draftContext';
import { getDraftChanges, isDraftSupportedEntity } from './draft-utils';
import { lockResources } from '../lock/master-lock';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { isRequestAccessEnabled } from '../modules/requestAccess/requestAccessUtils';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { type BasicStoreEntityEntitySetting, ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';
import { generateVulnerabilitiesUpdates } from '../utils/vulnerabilities';
import { idLabel } from '../schema/schema-labels';
import { pirExplanation } from '../modules/attributes/internalRelationship-registrationAttributes';
import { modules } from '../schema/module';
import { doYield } from '../utils/eventloop-utils';
import { ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED } from '../modules/securityCoverage/securityCoverage-types';
import { findById as findDraftById } from '../modules/draftWorkspace/draftWorkspace-domain';
import type { AuthContext, AuthUser } from '../types/user';
import type {
  BasicConnection,
  BasicStoreBase,
  BasicStoreCommon,
  BasicStoreCyberObservable,
  BasicStoreEntity,
  BasicStoreEntityMarkingDefinition,
  BasicStoreObject,
  BasicStoreRelation,
  BasicWorkflowStatus,
  StoreCommon,
  StoreEntity,
  StoreFile,
  StoreObject,
  StoreRelation,
} from '../types/store';
import type { BasicStoreSettings } from '../types/settings';
import type * as S from '../types/stix-2-1-common';
import type { StixId } from '../types/stix-2-1-common';
import type * as S2 from '../types/stix-2-0-common';
import type { Change, CreateEventOpts, EventOpts, UpdateEvent, UpdateEventOpts } from '../types/event';

// region global variables
const MAX_BATCH_SIZE = nconf.get('elasticsearch:batch_loader_max_size') ?? 300;
const MAX_EXPLANATIONS_PER_RULE = nconf.get('rule_engine:max_explanations_per_rule') ?? 100;
// endregion

// region request access
export const canRequestAccess = async (context: AuthContext, user: AuthUser, elements: BasicStoreCommon[]) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const hasPlatformOrg = !!settings.platform_organization;
  const elementsThatRequiresAccess = [];
  for (let i = 0; i < elements.length; i += 1) {
    const currentElement = elements[i];
    if (!isOrganizationAllowed(context, currentElement, user, hasPlatformOrg)) {
      // Check that group has marking allowed or else request accesss RFI will be useless
      const requestAccessSettings = await loadEntity<BasicStoreEntityEntitySetting>(context, user, [ENTITY_TYPE_ENTITY_SETTING], {
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['target_type'], values: [ENTITY_TYPE_CONTAINER_CASE_RFI] }],
          filterGroups: [],
        },
      });
      if (requestAccessSettings && requestAccessSettings.request_access_workflow && requestAccessSettings.request_access_workflow?.approval_admin.length > 0) {
        const adminGroupId = requestAccessSettings.request_access_workflow?.approval_admin[0];
        const adminGroupMarking = await fullEntitiesThroughRelationsToList(context, user, adminGroupId, RELATION_ACCESSES_TO, ENTITY_TYPE_MARKING_DEFINITION);
        const authorizedGroupMarkings = adminGroupMarking.map((a) => a.internal_id);

        if (isMarkingAllowed(currentElement, authorizedGroupMarkings)) {
          elementsThatRequiresAccess.push(elements[i]);
        }
      }
    }
  }
  return elementsThatRequiresAccess;
};
// end region request access

// region Loader common
export const batchLoader = (
  loader: (context: AuthContext, user: AuthUser, elements: any[]) => Promise<BasicStoreBase[]>,
  context: AuthContext,
  user: AuthUser,
) => {
  const loadFn = (elements: ReadonlyArray<{ elementToLoad: any }>): Promise<BasicStoreBase[]> => {
    const elementsToLoad = elements.map((e) => e.elementToLoad);
    return loader(context, user, elementsToLoad);
  };
  const dataLoader = new DataLoader(loadFn, { maxBatchSize: MAX_BATCH_SIZE, cache: false });
  return {
    load: (element: any) => {
      return dataLoader.load({ elementToLoad: element });
    },
  };
};

const checkIfInferenceOperationIsValid = (user: AuthUser, element: BasicStoreBase) => {
  const isRuleManaged = isRuleUser(user);
  const ifElementInferred = isInferredIndex(element._index);
  if (ifElementInferred && !isRuleManaged) {
    throw UnsupportedError('Manual inference deletion is not allowed', { id: element.id });
  }
};
// endregion

// Standard listing
export const topEntitiesOrRelationsList = async <T extends BasicStoreCommon> (
  context: AuthContext,
  user: AuthUser,
  thingsTypes: string[],
  args: RelationFilters<T> = {},
): Promise<T[]> => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildThingsFilters(thingsTypes, args);
  const result = await elPaginate<T>(context, user, indices, { ...paginateArgs, connectionFormat: false });
  return result as T[];
};
export const pageEntitiesOrRelationsConnection = async <T extends BasicStoreCommon> (
  context: AuthContext,
  user: AuthUser,
  thingsTypes: string[] | undefined | null,
  args: RelationFilters<T> = {},
): Promise<BasicConnection<T>> => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildThingsFilters(thingsTypes, args);
  const result = await elPaginate<T>(context, user, indices, { ...paginateArgs, connectionFormat: true });
  return result as BasicConnection<T>;
};
export const fullEntitiesOrRelationsList = async <T extends BasicStoreCommon> (
  context: AuthContext,
  user: AuthUser,
  thingsTypes: string[],
  args: RelationFilters<T> = {},
): Promise<T[]> => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildThingsFilters(thingsTypes, args);
  return elList<T>(context, user, indices, paginateArgs);
};
export const fullEntitiesOrRelationsConnection = async <T extends BasicStoreCommon> (
  context: AuthContext,
  user: AuthUser,
  thingsTypes: string[] | null | undefined,
  args: RelationFilters<T> = {},
): Promise<BasicConnection<T>> => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildThingsFilters(thingsTypes, args);
  return elConnection(context, user, indices, paginateArgs);
};
export const loadEntity = async <T extends BasicStoreEntity> (
  context: AuthContext,
  user: AuthUser,
  entityTypes: string[],
  args: EntityOptions<T> = {},
): Promise<T | undefined> => {
  const entities = await topEntitiesList(context, user, entityTypes, args);
  if (entities.length > 1) {
    throw DatabaseError('Expect only one response', { entityTypes, args });
  }
  return R.head(entities);
};
// endregion

// region Loader element
const loadElementMetaDependencies = async (
  context: AuthContext,
  user: AuthUser,
  elements: { internal_id: string; entity_type: string }[],
  args: { onlyMarking?: boolean } = {},
): Promise<Map<string, BasicStoreBase>> => {
  const { onlyMarking = true } = args;
  const workingElements = Array.isArray(elements) ? elements : [elements];
  const workingElementsMap = new Map(workingElements.map((i) => [i.internal_id, i]));
  const workingIds = Array.from(workingElementsMap.keys());
  const relTypes = onlyMarking ? [RELATION_OBJECT_MARKING] : STIX_REF_RELATIONSHIP_TYPES;
  // Resolve all relations, huge filters are inefficient, splitting will maximize the query speed
  const refsRelations: BasicStoreRelation[] = [];
  const groupOfWorkingIds = R.splitEvery(ES_MAX_PAGINATION, workingIds);
  for (let i = 0; i < groupOfWorkingIds.length; i += 1) {
    const fromIds = groupOfWorkingIds[i];
    const relationFilter = { mode: FilterMode.And, filters: [{ key: ['fromId'], values: fromIds }], filterGroups: [] };
    // All callback to iteratively push the relations to the global ref relations array
    // As fullRelationsList can bring more than 100K+ relations, we need to split the append
    // due to nodejs limitation to 100K function parameters limit
    const allRelCallback = async (relations: BasicStoreRelation[]) => {
      refsRelations.push(...relations);
    };
    await fullRelationsList<BasicStoreRelation>(context, user, relTypes, { baseData: true, filters: relationFilter, callback: allRelCallback });
  }
  const refsPerElements = R.groupBy((r) => r.fromId, refsRelations);
  // Parallel resolutions
  const toResolvedIds = R.uniq(refsRelations.map((rel) => rel.toId));
  const toResolvedTypes = R.uniq(refsRelations.map((rel) => rel.toType));
  const toResolvedElements = await elFindByIds(context, user, toResolvedIds, { type: toResolvedTypes, toMap: true }) as Record<string, BasicStoreBase>;
  const refEntries = Object.entries(refsPerElements);
  const loadedElementMap = new Map<string, BasicStoreBase>();
  for (let indexRef = 0; indexRef < refEntries.length; indexRef += 1) {
    const [refId, dependencies] = refEntries[indexRef];
    const element = workingElementsMap.get(refId);
    // Build flatten view inside the data for stix meta
    const data: Record<string, any> = {};
    if (element) {
      const grouped = R.groupBy((a) => a.entity_type, dependencies as BasicStoreRelation[]) as Record<string, BasicStoreRelation[]>;
      const entries = Object.entries(grouped);
      for (let index = 0; index < entries.length; index += 1) {
        const [key, values] = entries[index];
        const invalidRelations = [];
        const resolvedElementsWithRelation = [];
        for (let valueIndex = 0; valueIndex < values.length; valueIndex += 1) {
          await doYield();
          const v = values[valueIndex];
          const resolvedElement = toResolvedElements[v.toId];
          if (resolvedElement) {
            resolvedElementsWithRelation.push({ ...resolvedElement, i_relation: v });
          } else {
            invalidRelations.push({ relation_id: v.id, target_id: v.toId });
          }
        }
        if (invalidRelations.length > 0) {
          // Some targets can be unresolved in case of potential inconsistency between relation and target
          // This kind of situation can happen if:
          // - Access rights are asymmetric, should not happen for meta relationships.
          // - Relations is invalid, should not happen in platform data consistency.
          logApp.info('Targets of loadElementMetaDependencies not found', { invalidRelations });
        }
        const inputKey = schemaRelationsRefDefinition.convertDatabaseNameToInputName(element.entity_type, key);
        const metaRefKey = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputKey);
        if (isEmptyField(metaRefKey)) {
          throw UnsupportedError('Schema validation failure when loading dependencies', { key, inputKey, type: element.entity_type });
        }
        const definedMetaRefKey = metaRefKey as RefAttribute;
        data[key] = !definedMetaRefKey.multiple ? R.head(resolvedElementsWithRelation)?.internal_id : resolvedElementsWithRelation.map((r) => r.internal_id);
        if (inputKey) {
          data[inputKey] = !definedMetaRefKey.multiple ? R.head(resolvedElementsWithRelation) : resolvedElementsWithRelation;
        }
      }
      loadedElementMap.set(refId, data as BasicStoreBase);
    }
  }
  return loadedElementMap;
};

export const loadElementsWithDependencies = async (
  context: AuthContext,
  user: AuthUser,
  elements: BasicStoreBase[],
  opts: { onlyMarking?: boolean } = {},
): Promise<BasicStoreCommon[]> => {
  const fileMarkings: string[] = [];
  const elementsToDeps: { internal_id: string; entity_type: string }[] = [...elements];
  let fromAndToPromise: Bluebird<Record<string, BasicStoreBase>> | undefined;
  let fileMarkingsPromise: Bluebird<Record<string, BasicStoreEntityMarkingDefinition>> | undefined;
  const targetsToResolved: string[] = [];
  elements.forEach((e) => {
    const isRelation = e.base_type === BASE_TYPE_RELATION;
    if (isRelation) {
      const relationElement = e as BasicStoreRelation;
      elementsToDeps.push({ internal_id: relationElement.fromId, entity_type: relationElement.fromType });
      elementsToDeps.push({ internal_id: relationElement.toId, entity_type: relationElement.toType });
      targetsToResolved.push(...[relationElement.fromId, relationElement.toId]);
    }
    e.x_opencti_files?.forEach((f) => {
      if (isNotEmptyField(f.file_markings)) {
        const fileMarkings = f.file_markings as string[];
        fileMarkings.push(...fileMarkings);
      }
    });
  });
  const depsPromise = loadElementMetaDependencies(context, user, elementsToDeps, opts) as Bluebird<Map<string, BasicStoreBase>>;
  if (targetsToResolved.length > 0) {
    // Load with System user, access rights will be dynamically change after
    fromAndToPromise = elFindByIds(context, SYSTEM_USER, targetsToResolved, { toMap: true }) as Bluebird<Record<string, BasicStoreBase>>;
  }
  if (fileMarkings.length > 0) {
    const args = { type: ENTITY_TYPE_MARKING_DEFINITION, toMap: true, baseData: true };
    fileMarkingsPromise = elFindByIds<BasicStoreEntityMarkingDefinition>(
      context, SYSTEM_USER,
      R.uniq(fileMarkings),
      args,
    ) as Bluebird<Record<string, BasicStoreEntityMarkingDefinition>>;
  }
  const promisesMap: any[] = [depsPromise, fromAndToPromise, fileMarkingsPromise];
  const [depsElementsMap, fromAndToMap, fileMarkingsMap] = await BluePromise.all(promisesMap);
  const loadedElements = [];
  for (let i = 0; i < elements.length; i += 1) {
    await doYield();
    const element = elements[i];
    const files: StoreFile[] = [];
    if (isNotEmptyField(element.x_opencti_files) && isNotEmptyField(fileMarkingsMap)) {
      element.x_opencti_files?.forEach((f) => {
        if (isNotEmptyField(f.file_markings)) {
          files.push({ ...f, [INPUT_MARKINGS]: f.file_markings?.map((m) => fileMarkingsMap[m]).filter((fm) => fm) });
        } else {
          files.push(f);
        }
      });
    }
    const deps = depsElementsMap.get(element.id) ?? {};
    if (isNotEmptyField(files)) {
      deps.x_opencti_files = files;
    }
    const isRelation = element.base_type === BASE_TYPE_RELATION;
    if (isRelation) {
      const relationElement = element as BasicStoreRelation;
      const rawFrom = fromAndToMap[relationElement.fromId];
      const rawTo = fromAndToMap[relationElement.toId];
      // Check relations consistency
      if (isEmptyField(rawFrom) || isEmptyField(rawTo)) {
        const validFrom = isEmptyField(rawFrom) ? 'invalid' : 'valid';
        const validTo = isEmptyField(rawTo) ? 'invalid' : 'valid';
        const detail = `From ${relationElement.fromId} is ${validFrom}, To ${relationElement.toId} is ${validTo}`;
        logApp.warn('Auto delete of invalid relation', { id: relationElement.id, detail });
        // Auto deletion of the invalid relation
        await elDeleteElements(context, SYSTEM_USER, [relationElement]);
      } else {
        const from = { ...rawFrom, ...depsElementsMap.get(relationElement.fromId) };
        const to = { ...rawTo, ...depsElementsMap.get(relationElement.toId) };
        // Check relations marking access.
        const canAccessFrom = await isUserCanAccessStoreElement(context, user, from);
        const canAccessTo = await isUserCanAccessStoreElement(context, user, to);
        if (canAccessFrom && canAccessTo) {
          loadedElements.push(R.mergeRight(relationElement, { from, to, ...deps }));
        }
      }
    } else {
      loadedElements.push(R.mergeRight(element, { ...deps }));
    }
  }
  return loadedElements;
};
type LoadByIdsWithDependeciesOpts = ElFindByIdsOpts & {
  onlyMarking?: boolean;
};
const loadByIdsWithDependencies = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  opts: LoadByIdsWithDependeciesOpts = {},
): Promise<BasicStoreCommon[]> => {
  const elements = await elFindByIds<BasicStoreCommon>(context, user, ids, opts) as BasicStoreCommon[];
  if (elements.length > 0) {
    return loadElementsWithDependencies(context, user, elements, opts);
  }
  return [];
};
const loadByFiltersWithDependencies = async (
  context: AuthContext,
  user: AuthUser,
  types: string[] | null,
  args: EntityFilters<BasicStoreCommon> & RepaginateOpts<BasicStoreBase> & { onlyMarking?: boolean } = {},
) => {
  const { indices = READ_DATA_INDICES } = args;
  const paginateArgs = buildEntityFilters(types, args);
  const elements = await elList(context, user, indices, paginateArgs);
  if (elements.length > 0) {
    return loadElementsWithDependencies(context, user, elements, { ...args, onlyMarking: false });
  }
  return [] as BasicStoreCommon[];
};
// Get element with every elements connected element -> rel -> to
export const storeLoadByIdsWithRefs = async <T extends StoreObject> (context: AuthContext, user: AuthUser, ids: string[], opts: LoadByIdsWithDependeciesOpts = {}) => {
  // When loading with explicit references, data must be loaded without internal rels
  // As rels are here for search and sort there is some data that conflict after references explication resolutions
  return await loadByIdsWithDependencies(context, user, ids, { ...opts, onlyMarking: false }) as T[];
};
export const storeLoadByIdWithRefs = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  id: string | null | undefined,
  opts: LoadByIdsWithDependeciesOpts = {},
): Promise<T | null> => {
  if (!id) {
    return null;
  }
  const elements = await storeLoadByIdsWithRefs(context, user, [id], opts);
  return elements.length > 0 ? elements[0] as T : null;
};
export const stixLoadById = async (
  context: AuthContext,
  user: AuthUser,
  id: string | null | undefined,
  opts: { version?: Version } & LoadByIdsWithDependeciesOpts = {},
): Promise<S.StixObject | S2.StixObject | null> => {
  if (!id) {
    return null;
  }
  const instance = await storeLoadByIdWithRefs(context, user, id, opts);
  const { version = Version.Stix_2_1 } = opts;
  return instance ? convertStoreToStix(instance, version) : null;
};
const convertStoreToStixWithResolvedFiles = async (
  instance: StoreCommon,
  version = Version.Stix_2_1,
): Promise<S.StixObject | S2.StixObject> => {
  const instanceInStix = convertStoreToStix(instance, version);
  const nonResolvedFiles = ('x_opencti_files' in instanceInStix && instanceInStix.x_opencti_files) || ('extensions' in instanceInStix && instanceInStix.extensions[STIX_EXT_OCTI].files);
  if (nonResolvedFiles) {
    for (let i = 0; i < nonResolvedFiles.length; i += 1) {
      const currentFile = nonResolvedFiles[i];
      const currentFileUri = currentFile.uri;
      const fileId = currentFileUri.replace('/storage/get/', '');
      currentFile.data = await getFileContent(fileId, 'base64');
      currentFile.no_trigger_import = true;
    }
  }
  return instanceInStix;
};
export const stixLoadByIds = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  opts: { resolveStixFiles?: boolean; version?: Version } & LoadByIdsWithDependeciesOpts = {},
): Promise<(S.StixObject | S2.StixObject)[]> => {
  const { resolveStixFiles = false, version = Version.Stix_2_1 } = opts;
  const elements = await storeLoadByIdsWithRefs(context, user, ids, opts);
  // As stix load by ids doesn't respect the ordering we need to remap the result
  const elementsMappedToIds = elements.map((i) => ({ instance: i, ids: extractIdsFromStoreObject(i) }));
  const flatElementsMapped = elementsMappedToIds.flat();
  const idsToInstanceArray = flatElementsMapped.map((o) => o.ids.map((id) => [id, o.instance]) as [string, BasicStoreCommon][]);
  const flatInstancesPreparedForMap = idsToInstanceArray.flat();
  const loadedInstancesMap = new Map(flatInstancesPreparedForMap);
  if (resolveStixFiles) {
    const fileResolvedInstancesPromise = ids.map((id) => loadedInstancesMap.get(id))
      .filter((i) => isNotEmptyField(i))
      .map((e) => (convertStoreToStixWithResolvedFiles(e as BasicStoreCommon, version)));
    return BluePromise.all(fileResolvedInstancesPromise);
  }
  return ids.map((id) => loadedInstancesMap.get(id))
    .filter((i) => isNotEmptyField(i))
    .map((e) => (convertStoreToStix(e as BasicStoreCommon, version)));
};
export const stixBundleByIdStringify = async (
  context: AuthContext,
  user: AuthUser,
  type: string,
  id: string,
): Promise<string | null> => {
  const resolver = modules.get(type)?.bundleResolver;
  if (!resolver) {
    return null;
  }
  return await resolver(context, user, id);
};

export const stixLoadByIdStringify = async (
  context: AuthContext,
  user: AuthUser,
  id: string | null | undefined,
  opts: { version?: Version } = {},
): Promise<string> => {
  const { version = Version.Stix_2_1 } = opts;
  const data = await stixLoadById(context, user, id, { version });
  return data ? JSON.stringify(data) : '';
};
export const stixLoadByFilters = async (
  context: AuthContext,
  user: AuthUser,
  types: string[] | null,
  args: EntityFilters<BasicStoreCommon> & RepaginateOpts<BasicStoreBase> & { onlyMarking?: boolean },
): Promise<S.StixObject[]> => {
  const elements = await loadByFiltersWithDependencies(context, user, types, args);
  return elements ? elements.map((element) => convertStoreToStix_2_1(element)) : [];
};
// endregion

// used to get a "restricted" value of a current attribute value depending on the value type
const restrictValue = (entityValue: any) => {
  if (Array.isArray((entityValue))) return [];
  if (isValidDate(entityValue)) return FROM_START_STR;
  const type = typeof entityValue;
  switch (type) {
    case 'string': return 'Restricted';
    case 'object': return null;
    default: return undefined;
  }
};

// restricted entities need to be able to be queried through the API
// we need to keep all of the entity attributes, but restrict their values
export const buildRestrictedEntity = (resolvedEntity: BasicStoreEntity): BasicStoreEntity => {
  // we first create a deep copy of the resolved entity
  const restrictedEntity = structuredClone(resolvedEntity);
  // for every attribute of the entity, we restrict it's value: we obfuscate the real value with a fake default value
  for (let i = 0; i < Object.keys(restrictedEntity).length; i += 1) {
    const item = Object.keys(restrictedEntity)[i];
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    restrictedEntity[item] = restrictedEntity[item] ? restrictValue(restrictedEntity[item]) : restrictedEntity[item];
  }
  // we return the restricted entity with some additional restricted data in it
  return {
    ...restrictedEntity,
    id: resolvedEntity.internal_id,
    name: 'Restricted',
    entity_type: resolvedEntity.entity_type,
    parent_types: resolvedEntity.parent_types,
    representative: { main: 'Restricted', secondary: 'Restricted' },
  };
};

// region Graphics
const convertAggregateDistributions = async (
  context: AuthContext,
  user: AuthUser,
  limit: number,
  orderingFunction: any,
  distribution: { label: string; value: number }[],
): Promise<{ label: string; value: number; entity: BasicStoreEntity }[]> => {
  const data = R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distribution)) as { label: string; value: number }[];
  // resolve all of them with system user
  const allResolveLabels = await elFindByIds<BasicStoreEntity>(context, SYSTEM_USER, data.map((d) => d.label), { toMap: true }) as Record<string, BasicStoreEntity>;
  // filter out unresolved data (like the SYSTEM user for instance)
  const filteredData = data.filter((n) => isNotEmptyField(allResolveLabels[n.label.toLowerCase()]));
  // entities not granted shall be sent as "restricted" with limited information
  const grantedIds: string[] = [];
  for (let i = 0; i < filteredData.length; i += 1) {
    const resolved = allResolveLabels[filteredData[i].label.toLowerCase()];
    const canAccess = await isUserCanAccessStoreElement(context, user, resolved);
    if (canAccess) {
      grantedIds.push(filteredData[i].label.toLowerCase());
    }
  }
  return filteredData
    .map((n) => {
      const element = allResolveLabels[n.label.toLowerCase()];
      if (grantedIds.includes(n.label.toLowerCase())) {
        return {
          ...n,
          entity: element,
        };
      }
      return {
        ...n,
        entity: buildRestrictedEntity(element),
      };
    });
};
export const timeSeriesHistory = async (
  context: AuthContext,
  user: AuthUser,
  _types: string[],
  args: { startDate: Date; endDate: Date; interval: string } & HistogramCountOpts,
) => {
  const { startDate, endDate, interval } = args;
  const histogramData = await elHistogramCount(context, user, READ_INDEX_HISTORY, args);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesEntities = async (
  context: AuthContext,
  user: AuthUser,
  types: string[],
  args: EntityFilters<BasicStoreEntity> & { onlyInferred?: boolean } & { startDate: Date; endDate: Date; interval: string },
) => {
  const timeSeriesArgs = buildEntityFilters(types, args);
  const histogramData = await elHistogramCount(context, user, args.onlyInferred ? READ_DATA_INDICES_INFERRED : READ_DATA_INDICES, timeSeriesArgs);
  const { startDate, endDate, interval } = args;
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesRelations = async (
  context: AuthContext,
  user: AuthUser,
  args: EntityFilters<BasicStoreEntity> & { onlyInferred?: boolean } & { startDate: Date; endDate: Date; interval: string; relationship_type?: string[] },
) => {
  const { startDate, endDate, relationship_type: relationshipTypes, interval } = args;
  const types = relationshipTypes || ['stix-core-relationship', 'object', 'stix-sighting-relationship'];
  const timeSeriesArgs = buildEntityFilters(types, args);
  const histogramData = await elHistogramCount(context, user, args.onlyInferred ? INDEX_INFERRED_RELATIONSHIPS : READ_RELATIONSHIPS_INDICES, timeSeriesArgs);
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionHistory = async (
  context: AuthContext,
  user: AuthUser,
  _types: string[],
  args: { limit?: number; order?: string; field: string },
): Promise<{ label: string; value: number; entity: BasicStoreEntity }[]> => {
  const { limit = 10, order = 'desc', field } = args;
  if (field.includes('.') && (!field.endsWith('internal_id') && !field.includes('context_data') && !field.includes('opinions_metrics'))) {
    throw FunctionalError('Distribution entities does not support relation aggregation field', { field });
  }
  let finalField = field;
  if (field.includes('.') && !field.includes('context_data') && !field.includes('opinions_metrics')) {
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
    let result: { label: string; value: number; entity: BasicStoreEntity }[] = [];
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
  // TODO this return problably doesn't work when it happens: API always expects an entity in returned data, but there is none with this return
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
export const distributionEntities = async (
  context: AuthContext,
  user: AuthUser,
  types: string | string[] | undefined | null,
  args: EntityFilters<BasicStoreEntity> & { limit?: number | null; order?: string | null; field: string } & { onlyInferred?: boolean },
): Promise<{ label: string; value: number; entity: BasicStoreEntity }[]> => {
  const distributionArgs = buildEntityFilters(types, args);
  const { limit = 10, order = 'desc', field } = args;
  const aggregationNotSupported = field.includes('.')
    && !field.endsWith('internal_id')
    && !field.includes('opinions_metrics');
  if (aggregationNotSupported) {
    throw FunctionalError('Distribution entities does not support relation aggregation field', { field });
  }
  let finalField = field;
  if (field.includes('.') && !field.includes('opinions_metrics')) {
    finalField = REL_INDEX_PREFIX + field;
  }
  if (field === 'name') {
    finalField = 'internal_id';
  }
  const distributionData = await elAggregationCount(context, user, args.onlyInferred ? READ_DATA_INDICES_INFERRED : READ_DATA_INDICES, {
    ...distributionArgs,
    field: finalField,
  });
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL) || field === 'creator_id' || field === 'x_opencti_workflow_id') {
    return convertAggregateDistributions(context, user, limit as number, orderingFunction, distributionData);
  }
  if (field === 'name') {
    let result: { label: string; value: number; entity: BasicStoreEntity }[] = [];
    await convertAggregateDistributions(context, user, limit as number, orderingFunction, distributionData)
      .then((hits) => {
        result = hits.map((hit) => ({
          label: hit.entity.name ?? extractEntityRepresentativeName(hit.entity),
          value: hit.value,
          entity: hit.entity,
        }));
      });
    return result;
  }
  // TODO this return problably doesn't work when it happens: API always expects an entity in returned data, but there is none with this return
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData)); // label not good
};
export const distributionRelations = async (
  context: AuthContext,
  user: AuthUser,
  args: {
    field: string;
    limit?: number | null;
    order?: string | null;
    relationship_type: string[];
    dateAttribute?: string | null;
    onlyInferred?: boolean; } & RelationFilters<BasicStoreCommon>,
) => {
  const { field } = args; // Mandatory fields
  const { limit = 50, order } = args;
  const { relationship_type: relationshipTypes, dateAttribute = 'created_at' } = args;
  const types = relationshipTypes || [ABSTRACT_BASIC_RELATIONSHIP];
  const distributionDateAttribute = dateAttribute || 'created_at';
  let finalField = field;
  if (field.includes('.') && !field.includes(pirExplanation.name)) {
    finalField = REL_INDEX_PREFIX + field;
  }
  // Using elastic can only be done if the distribution is a count on types
  const opts = { ...args, dateAttribute: distributionDateAttribute, field: finalField };
  const distributionArgs = buildAggregationRelationFilter(types, opts) as unknown as AggregationRelationsCount;
  const distributionData = await elAggregationRelationsCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_RELATIONSHIPS : READ_RELATIONSHIPS_INDICES, distributionArgs);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? R.ascend : R.descend;
  if (field.includes(ID_INTERNAL) || field === 'creator_id' || field === 'x_opencti_workflow_id' || field.includes('author_id')) {
    return convertAggregateDistributions(context, user, limit as number, orderingFunction, distributionData);
  }
  // TODO this return problably doesn't work when it happens: API always expects an entity in returned data, but there is none with this return
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return R.take(limit, R.sortWith([orderingFunction(R.prop('value'))])(distributionData));
};
// endregion

// region mutation common
const depsKeys = (type: string): { src: string; dst?: string; types?: string[] }[] => ([
  ...depsKeysRegister.get(),
  ...[
    // Relationship
    { src: 'fromId', dst: 'from' },
    { src: 'toId', dst: 'to' },
    // Other meta refs
    ...schemaRelationsRefDefinition.getInputNames(type).map((e) => ({ src: e })),
  ],
]);

const idVocabulary = (nameOrId: string, category: string) => {
  return isAnId(nameOrId) ? nameOrId : generateStandardId(ENTITY_TYPE_VOCABULARY, { name: nameOrId, category });
};

/**
 * Verify that the Entity in createdBy is one of Identity entity.
 * If not throw functional error to stop creation or update.
 * @param context
 * @param user
 * @param createdById
 * @returns {Bluebird.Promise<void>}
 */
export const validateCreatedBy = async (context: AuthContext, user: AuthUser, createdById: string | null | undefined) => {
  if (createdById) {
    const createdByEntity = await internalLoadById(context, user, createdById);
    if (createdByEntity && createdByEntity.entity_type) {
      if (!isStixDomainObjectIdentity(createdByEntity.entity_type)) {
        throw FunctionalError('CreatedBy relation must be an Identity entity.', {
          createdBy: createdById,
        });
      }
    }
  }
};

export const inputResolveRefs = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  type: string,
  entitySetting: BasicStoreEntityEntitySetting,
): Promise<Record<string, any>> => {
  const inputResolveRefsFn = async () => {
    const fetchingIdsMap = new Map<string, { id: string; destKey?: string; multiple?: boolean; vocab?: { field: any; data: string } }[]>();
    const expectedIds: string[] = [];
    const cleanedInput: Record<string, any> | null = { _index: inferIndexFromConceptType(type), ...input };
    let embeddedFromResolution;
    const dependencyKeys = depsKeys(type);
    for (let index = 0; index < dependencyKeys.length; index += 1) {
      const { src, dst, types } = dependencyKeys[index];
      const depTypes = types ?? [];
      const destKey = dst || src;
      const id = input[src];
      const isValidType = depTypes.length > 0 ? depTypes.includes(type) : true;
      const isAlreadyResolved = Array.isArray(id) ? id[0]?._id : id?._id;
      if (isValidType && !R.isNil(id) && !R.isEmpty(id) && !isAlreadyResolved) {
        const isListing = Array.isArray(id);
        const hasOpenVocab = isEntityFieldAnOpenVocabulary(destKey, type);
        // Handle specific case of object label that can be directly the value instead of the key.
        if (src === INPUT_LABELS) {
          const labelsIds = id as string[];
          R.uniq(labelsIds.map((label) => idLabel(label)))
            .forEach((labelId) => {
              const labelElement = { id: labelId, destKey, multiple: true };
              if (fetchingIdsMap.has(labelId)) {
                fetchingIdsMap.get(labelId)?.push(labelElement);
              } else {
                fetchingIdsMap.set(labelId, [labelElement]);
              }
              expectedIds.push(labelId);
            });
        } else if (hasOpenVocab) {
          const ids = isListing ? id : [id];
          const { category, field } = getVocabularyCategoryForField(destKey, type);
          ids.forEach((i) => {
            if (field?.composite && field?.multiple) {
              throw FunctionalError('Composite vocab only support single definition', { field });
            }
            const vocabularyId = field?.composite ? idVocabulary(i[field?.composite], category) : idVocabulary(i, category);
            const vocabularyElement = { id: vocabularyId, destKey, vocab: { field, data: i }, multiple: isListing };
            if (fetchingIdsMap.has(vocabularyId)) {
              fetchingIdsMap.get(vocabularyId)?.push(vocabularyElement);
            } else {
              fetchingIdsMap.set(vocabularyId, [vocabularyElement]);
            }
          });
        } else if (isListing) {
          const listingIds = id as string[];
          listingIds.forEach((i) => {
            const listingElement = { id: i, destKey, multiple: true };
            if (fetchingIdsMap.has(i)) {
              if (fetchingIdsMap.get(i)?.map((e) => e.destKey).includes(destKey)) {
                return;
              }
              fetchingIdsMap.get(i)?.push(listingElement);
            } else {
              fetchingIdsMap.set(i, [listingElement]);
            }
            expectedIds.push(i);
          });
        } else { // Single
          if (dst === 'from' && isStixRefRelationship(type)) {
            // If resolution is due to embedded ref, the from must be fully resolved
            // This will be used to generated a correct stream message
            embeddedFromResolution = id;
          } else {
            const singleElement = { id, destKey, multiple: false };
            if (fetchingIdsMap.has(id)) {
              fetchingIdsMap.get(id)?.push(singleElement);
            } else {
              fetchingIdsMap.set(id, [singleElement]);
            }
          }
          if (!expectedIds.includes(id)) {
            expectedIds.push(id);
          }
        }
        cleanedInput[src] = null;
      }
    }
    // TODO Improve type restriction from targeted ref inferred types
    // This information must be added in the model
    const idsToFetch = Array.from(fetchingIdsMap.keys());
    const simpleResolutionsPromise = internalFindByIds(context, user, idsToFetch);
    let embeddedFromPromise;
    if (embeddedFromResolution) {
      fetchingIdsMap.set(embeddedFromResolution, [{ id: embeddedFromResolution, destKey: 'from', multiple: false }]);
      embeddedFromPromise = storeLoadByIdWithRefs(context, user, embeddedFromResolution);
    }
    const promisesToResolve: any[] = [simpleResolutionsPromise, embeddedFromPromise];
    const [resolvedElements, embeddedFrom] = await BluePromise.all(promisesToResolve);
    if (embeddedFrom) {
      resolvedElements.push(embeddedFrom);
    }
    const resolutionsMap = new Map();
    const resolvedIds = new Set();
    for (let i = 0; i < resolvedElements.length; i += 1) {
      const resolvedElement = resolvedElements[i] as BasicStoreObject;
      const instanceIds = getInstanceIds(resolvedElement);
      const matchingConfigs: any[] = [];
      instanceIds.forEach((instanceId) => {
        resolvedIds.add(instanceId);
        if (fetchingIdsMap.has(instanceId)) {
          const fetchingId = fetchingIdsMap.get(instanceId) as any[];
          matchingConfigs.push(...fetchingId);
        }
      });
      for (let configIndex = 0; configIndex < matchingConfigs.length; configIndex += 1) {
        await doYield();
        const c = matchingConfigs[configIndex];
        const data = { ...resolvedElement, i_group: c };
        const dataKey = `${resolvedElement.internal_id}|${c.destKey}`;
        resolutionsMap.set(dataKey, data);
      }
    }
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const groupByTypeElements = R.groupBy((e) => e.i_group.destKey, resolutionsMap.values());
    const resolved = Object.entries(groupByTypeElements).map(([k, val]) => {
      const attr = schemaAttributesDefinition.getAttribute(type, k);
      const ref = schemaRelationsRefDefinition.getRelationRef(type, k);
      if (!ref && !attr) {
        throw UnsupportedError('Invalid attribute resolution', { key: k, type, doc_code: 'ELEMENT_NOT_FOUND' });
      }
      const isMultiple = attr?.multiple || ref?.multiple;
      // If single value
      if (!isMultiple) {
        const rawValues = Array.isArray(val) ? val : [val];
        if (rawValues.length > 1) {
          throw UnsupportedError('Input resolve refs expect single value', { key: k, values: rawValues, doc_code: 'ELEMENT_ID_COLLISION' });
        }
        const rawValue = rawValues[0];
        const { vocab } = rawValue.i_group;
        if (vocab) {
          if (vocab.field.composite) {
            return { [k]: { ...vocab.data, [vocab.field.composite]: rawValue.name } };
          }
          return { [k]: rawValue.name };
        }
        return { [k]: rawValue };
      }
      // If multiple values
      const result: any[] = [];
      val.forEach((rawValue: any) => {
        const { vocab } = rawValue.i_group;
        if (vocab) {
          if (vocab.field.composite) {
            result.push({ ...vocab.data, [vocab.field.composite]: rawValue.name });
          } else {
            result.push(rawValue.name);
          }
        } else {
          result.push(rawValue);
        }
      });
      return { [k]: result };
    });
    const unresolvedIds = expectedIds.filter((id) => !resolvedIds.has(id));
    // In case of missing from / to, fail directly
    const expectedUnresolvedIds = unresolvedIds.filter((u) => u === input.fromId || u === input.toId);
    if (expectedUnresolvedIds.length > 0) {
      throw MissingReferenceError({ unresolvedIds: expectedUnresolvedIds, doc_code: 'ELEMENT_NOT_FOUND', ...extendedErrors({ input }) });
    }
    // In case of missing reference NOT from or to, we reject twice before accepting
    // TODO this retry must be removed in favor of reworking the workers synchronization
    const retryNumber = user.origin?.call_retry_number;
    const optionalRefsUnresolvedIds = unresolvedIds.filter((u) => u !== input.fromId || u !== input.toId);
    const attributesConfiguration = getAttributesConfiguration(entitySetting);
    const defaultValues = attributesConfiguration?.map((attr) => attr.default_values).flat() ?? [];
    const expectedUnresolvedIdsNotDefault = optionalRefsUnresolvedIds.filter((id) => !defaultValues.includes(id));
    if (isNotEmptyField(retryNumber) && expectedUnresolvedIdsNotDefault.length > 0 && retryNumber && retryNumber <= 2) {
      throw MissingReferenceError({ unresolvedIds: expectedUnresolvedIdsNotDefault, doc_code: 'ELEMENT_NOT_FOUND', ...extendedErrors({ input }) });
    }
    const complete = { ...cleanedInput, entity_type: type };
    const inputResolved = R.mergeRight(complete, R.mergeAll(resolved));
    // Check Open vocab in resolved to convert them back to the raw value
    const entityVocabs = Object.values(vocabularyDefinitions).filter(({ entity_types }) => entity_types.includes(type));
    entityVocabs.forEach(({ fields }) => {
      const existingFields = fields.filter(({ key }) => Boolean(input[key]));
      existingFields.forEach(({ key, required, composite, multiple }) => {
        const resolvedData = inputResolved[key];
        if (isEmptyField(resolvedData) && required) {
          throw FunctionalError('Missing mandatory attribute for vocabulary', { key });
        }
        if (isNotEmptyField(resolvedData)) {
          const isArrayValues = Array.isArray(resolvedData);
          if (isArrayValues && !multiple && !composite) {
            throw FunctionalError('Find multiple vocabularies for single one', { key, data: resolvedData });
          }
        }
      });
    });
    // Check the marking allow for the user and asked inside the input
    if (!isBypassUser(user) && inputResolved[INPUT_MARKINGS]) {
      const inputMarkingIds = inputResolved[INPUT_MARKINGS].map((marking: BasicStoreEntityMarkingDefinition) => marking.internal_id);
      const userMarkingIds = user.allowed_marking.map((marking) => marking.internal_id);
      if (!inputMarkingIds.every((v: string) => userMarkingIds.includes(v))) {
        throw MissingReferenceError({ reason: 'User trying to create the data has missing markings', doc_code: 'ELEMENT_NOT_FOUND' });
      }
    }
    // Check if available created_by is a correct identity
    const inputCreatedBy = inputResolved[INPUT_CREATED_BY];
    if (inputCreatedBy) {
      if (!isStixDomainObjectIdentity(inputCreatedBy.entity_type)) {
        throw FunctionalError('CreatedBy relation must be an Identity entity', { entityType: inputCreatedBy.entity_type });
      }
    }
    return inputResolved;
  };
  return telemetry(context, user, `INPUTS RESOLVE ${type}`, {
    [SEMATTRS_DB_NAME]: 'middleware',
    [SEMATTRS_DB_OPERATION]: 'resolver',
  }, inputResolveRefsFn);
};
const isRelationTargetGrants = (elementGrants: any[], relation: Record<string, any>, type: string) => {
  const isTargetType = relation.base_type === BASE_TYPE_RELATION && relation.entity_type === RELATION_OBJECT;
  if (!isTargetType) return false;
  const allTypes = [relation.to?.entity_type, ...(relation.to?.parent_types ?? [])] as string[];
  const isUnrestricted = allTypes.some((r) => STIX_ORGANIZATIONS_UNRESTRICTED.includes(r));
  if (isUnrestricted) return false;
  return type === ACTION_TYPE_UNSHARE || !elementGrants.every((v) => ((relation.to as BasicStoreCommon)[RELATION_GRANTED_TO] ?? []).includes(v));
};
const createContainerSharingTask = (
  context: AuthContext,
  type: string,
  element: Record<string, any>,
  relations: Record<string, any>[] = [],
) => {
  // If object_refs relations are newly created
  // One side is a container, the other side must inherit from the granted_refs
  const targetGrantIds = [];
  let taskPromise = BluePromise.resolve();
  const elementGrants = (relations ?? []).filter((e) => e.entity_type === RELATION_GRANTED_TO).map((r) => r.to?.internal_id);
  // If container is granted, we need to grant every new children.
  if (element.base_type === BASE_TYPE_ENTITY && isStixDomainObjectShareableContainer(element.entity_type)) {
    elementGrants.push(...(element[RELATION_GRANTED_TO] ?? []));
    if (elementGrants.length > 0) {
      // A container has created or modified (addition of some object_refs)
      // We need to compute the granted_refs on the container and apply it on new child
      // Apply will be done on a background task to not slow the main ingestion process.
      const newChildrenIds = (relations ?? [])
        .filter((e) => isRelationTargetGrants(elementGrants, e, type))
        .map((r) => r.to?.internal_id);
      targetGrantIds.push(...newChildrenIds);
    }
  }
  if (element.base_type === BASE_TYPE_RELATION && isStixDomainObjectShareableContainer((element as StoreRelation).from?.entity_type)) {
    const relationElement = element as StoreRelation;
    elementGrants.push(...((relationElement.from as BasicStoreCommon)[RELATION_GRANTED_TO] ?? []));
    // A new object_ref relation was created between a shareable container and an element
    // If this element is compatible we need to apply the granted_refs of the container on this new element
    if (elementGrants.length > 0 && isRelationTargetGrants(elementGrants, relationElement, type)) {
      targetGrantIds.push(relationElement.to?.internal_id);
    }
  }
  // If element needs to be updated, start a SHARE background task
  if (targetGrantIds.length > 0) {
    const entityElement = element as BasicStoreEntity;
    const sharingDescription = `${type} organizations of ${entityElement.name} to contained objects`;
    const input = { ids: targetGrantIds, scope: 'KNOWLEDGE', actions: [{ type, context: { values: elementGrants } }], description: sharingDescription };
    taskPromise = createListTask(context, CONTAINER_SHARING_USER, input) as Bluebird<void>;
  }
  return taskPromise;
};
const indexCreatedElement = async (
  context: AuthContext,
  user: AuthUser,
  { element, relations }: { element: Record<string, any>; relations: Record<string, any>[] },
) => {
  // Continue the creation of the element and the connected relations
  const indexPromise = elIndexElements(context, user, element.entity_type, [element, ...(relations ?? [])]);
  const taskPromise = createContainerSharingTask(context, ACTION_TYPE_SHARE, element, relations);
  await BluePromise.all([taskPromise, indexPromise]);
};
export const updatedInputsToData = (instance: Record<string, any>, inputs: EditInput[]) => {
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
export const mergeInstanceWithInputs = (instance: Record<string, any>, inputs: EditInput[]): Record<string, any> => {
  // standard_id must be maintained
  // const inputsWithoutId = inputs.filter((i) => i.key !== ID_STANDARD);
  const data = updatedInputsToData(instance, inputs);
  const updatedInstance = R.mergeRight(instance, data);
  return R.reject(R.equals(null))(updatedInstance);
};
const partialInstanceWithInputs = (instance: Record<string, any>, inputs: EditInput[]) => {
  const inputData = updatedInputsToData(instance, inputs);
  return {
    _index: instance._index,
    _id: instance._id,
    internal_id: instance.internal_id,
    entity_type: instance.entity_type,
    ...inputData,
  };
};
const rebuildAndMergeInputFromExistingData = (rawInput: EditInput, instance: Record<string, any>): EditInput | object => {
  const { key, value, object_path, operation = UPDATE_OPERATION_REPLACE } = rawInput; // value can be multi valued
  const isMultiple = isMultipleAttribute(instance.entity_type, key);
  let finalVal;
  if (isMultiple) {
    const filledCurrentValues = isNotEmptyField(instance[key]) ? instance[key] : [];
    const currentValues = Array.isArray(filledCurrentValues) ? filledCurrentValues : [filledCurrentValues];
    if (operation === UPDATE_OPERATION_ADD) {
      if (isObjectAttribute(key)) {
        const path = object_path ?? key;
        const preparedPath = path.startsWith('/') ? path : `/${path}`;
        const instanceKeyValues = jsonpatch.getValueByPointer(instance, preparedPath);
        let patch;
        if (instanceKeyValues === undefined) {
          // if the instance has not yet this key, we need to add the full key as a new array
          patch = [{ op: 'add' as const, path: `${preparedPath}`, value }];
        } else {
          // otherwise we need to add the values to the existing array, using jsonpatch indexed path
          patch = value.map((v, index) => {
            const afterIndex = index + instanceKeyValues.length;
            return { op: 'add' as const, path: `${preparedPath}/${afterIndex}`, value: v };
          });
        }
        const patchedInstance = jsonpatch.applyPatch(structuredClone(instance), patch).newDocument;
        finalVal = patchedInstance[key];
      } else {
        finalVal = R.uniq([...currentValues, value].flat().filter((v) => isNotEmptyField(v)));
      }
    }
    if (operation === UPDATE_OPERATION_REMOVE) {
      if (isObjectAttribute(key)) {
        const path = object_path ?? key;
        const preparedPath = path.startsWith('/') ? path : `/${path}`;
        const patch = [{ op: 'remove' as const, path: preparedPath, value: null }];
        const patchedInstance = jsonpatch.applyPatch(structuredClone(instance), patch).newDocument;
        finalVal = patchedInstance[key];
      } else {
        finalVal = R.filter((n) => !R.includes(n, value), currentValues);
      }
    }
    if (operation === UPDATE_OPERATION_REPLACE) {
      if (isObjectAttribute(key)) {
        const path = object_path ?? key;
        const preparedPath = path.startsWith('/') ? path : `/${path}`;
        const targetIsMultiple = isObjectPathTargetMultipleAttribute(instance as BasicStoreCommon, preparedPath);
        const patch = [{ op: 'replace' as const, path: preparedPath, value: targetIsMultiple ? value : R.head(value) }];
        const patchedInstance = jsonpatch.applyPatch(structuredClone(instance), patch).newDocument;
        finalVal = patchedInstance[key];
      } else { // Replace general
        finalVal = value;
      }
    }
    // TODO: solve case where ordering is important and we should use regular 'compare'
    if (key !== 'overview_layout_customization' && (compareUnsorted(finalVal ?? [], currentValues) || (isEmptyField(finalVal) && isEmptyField(currentValues)))) {
      return {}; // No need to update the attribute
    }
  } else if (isObjectAttribute(key) && object_path) {
    const preparedPath = object_path.startsWith('/') ? object_path : `/${object_path}`;
    const targetIsMultiple = isObjectPathTargetMultipleAttribute(instance as BasicStoreCommon, preparedPath);
    const patch = [{ op: operation as EditOperation, path: preparedPath, value: targetIsMultiple ? value : R.head(value) }];
    const clonedInstance = structuredClone(instance);
    clonedInstance[key] = clonedInstance[key] ?? {}; // Patch on complete empty value is not supported by jsonpatch
    const patchedInstance = jsonpatch.applyPatch(clonedInstance, patch).newDocument;
    if (compareUnsorted(patchedInstance[key], instance[key])) {
      return {}; // No need to update the attribute
    }
    finalVal = [patchedInstance[key]];
  } else {
    // now we  check if the new value would actually result in no change in database
    let evaluateValue = value ? R.head(value) : null;
    // string values will be trimmed before indexing ; we should not update attribute if the value once trimmed is identical.
    if (typeof evaluateValue === 'string') {
      evaluateValue = evaluateValue.trim();
    }
    if (isDateAttribute(key)) {
      if (isEmptyField(evaluateValue)) {
        if (instance[key] === FROM_START_STR || instance[key] === UNTIL_END_STR) {
          return {};
        }
      }
      if (utcDate(instance[key]).isSame(utcDate(evaluateValue))) {
        return {};
      }
    }
    if (R.equals(instance[key], evaluateValue) || (isEmptyField(instance[key]) && isEmptyField(evaluateValue))) {
      return {}; // No need to update the attribute
    }
    finalVal = value;
  }
  // endregion
  // region cleanup cases
  if (key === IDS_STIX) {
    // Special stixIds uuid v1 cleanup.
    finalVal = cleanStixIds(finalVal);
  }
  // endregion
  if (isDateAttribute(key)) {
    const finalValElement = R.head(finalVal);
    if (isEmptyField(finalValElement)) {
      finalVal = [null];
    }
  }
  if (dateForLimitsAttributes.includes(key)) {
    const finalValElement = R.head(finalVal);
    if (dateForStartAttributes.includes(key) && isEmptyField(finalValElement)) {
      finalVal = [FROM_START_STR];
    }
    if (dateForEndAttributes.includes(key) && isEmptyField(finalValElement)) {
      finalVal = [UNTIL_END_STR];
    }
  }
  return { key, value: finalVal, operation };
};
const mergeInstanceWithUpdateInputs = (base: Record<string, any>, inputs: EditInput[]) => {
  const instance = structuredClone(base);
  const updates = Array.isArray(inputs) ? inputs : [inputs];
  const metaKeys = [...schemaRelationsRefDefinition.getStixNames(instance.entity_type), ...schemaRelationsRefDefinition.getInputNames(instance.entity_type)];
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  const mergeInput = (input: EditInput) => rebuildAndMergeInputFromExistingData(input, instance);
  const remappedInputs = R.map((i) => mergeInput(i), attributes);
  const resolvedInputs = R.filter((f) => !R.isEmpty(f), remappedInputs);
  return mergeInstanceWithInputs(instance, resolvedInputs as EditInput[]);
};
const listEntitiesByHashes = async (
  context: AuthContext,
  user: AuthUser,
  type: string,
  hashes: Record<string, string> | null | undefined,
): Promise<BasicStoreEntity[]> => {
  if (isEmptyField(hashes)) {
    return [];
  }
  const searchHashes = extractNotFuzzyHashValues(hashes as Record<string, string>); // Search hashes must filter the fuzzy hashes
  if (searchHashes.length === 0) {
    return [];
  }
  return topEntitiesList(context, user, [type], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['hashes.*'], values: searchHashes, operator: FilterOperator.Wildcard }],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
};
export const hashMergeValidation = (instances: { hashes?: { [k: string]: string } }[]) => {
  // region Specific check for observables with hashes
  // If multiple results start by checking the possible merge validity
  const allHashes = instances.map((h) => h.hashes).filter((e) => isNotEmptyField(e)) as Record<string, string>[];
  if (allHashes.length > 0) {
    const elements = allHashes.map((e) => Object.entries(e)).flat();
    const groupElements = R.groupBy(([key]) => key, elements) as Record<string, [string, string][]>;
    Object.entries(groupElements).forEach(([algo, values]) => {
      const hashes = R.uniq(values.map(([, data]) => data));
      if (hashes.length > 1) {
        const field = `hashes_${algo.toUpperCase()}`;
        throw ValidationError('Hashes collision', field, { algorithm: algo });
      }
    });
  }
};
// endregion

// region mutation update
const ed = (date?: string) => isEmptyField(date) || date === FROM_START_STR || date === UNTIL_END_STR;
const noDate = (
  e: { first_seen?: string; last_seen?: string; start_time?: string; stop_time?: string },
) => ed(e.first_seen) && ed(e.last_seen) && ed(e.start_time) && ed(e.stop_time);
const filterTargetByExisting = async (
  context: AuthContext,
  targetEntity: BasicStoreBase,
  redirectSide: 'from' | 'to',
  sourcesDependencies: MergeEntitiesDependency,
  targetDependencies: MergeEntitiesDependency,
): Promise<{ deletions: BasicStoreRelation[]; redirects: MergeEntityDependency[] }> => {
  const cache: string[] = [];
  const filtered: MergeEntityDependency[] = [];
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
    const finder = (t: MergeEntityDependency) => {
      const sameTarget = t.internal_id === source.internal_id;
      const sameRelationType = t.i_relation.entity_type === source.i_relation.entity_type;
      return sameRelationType && sameTarget && noDate(t.i_relation as unknown as any);
    };
    // In case of single meta to move, check if the target have not already this relation.
    // If yes, we keep it, if not we rewrite it
    const relationRefType = redirectSide === 'from' ? source.i_relation.fromType : source.i_relation.toType;
    const isSingleMeta = isSingleRelationsRef(relationRefType, source.i_relation.entity_type);
    const relationInputName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(targetEntity.entity_type, source.i_relation.entity_type) as string;
    const targetEntityRelValue = (targetEntity as any)[relationInputName];
    const existingSingleMeta = isSingleMeta && isNotEmptyField(targetEntityRelValue);
    // For single meta only rely on entity type to prevent relation duplications
    const id = (isSingleMeta && redirectSide === 'from') ? source.i_relation.entity_type : `${source.i_relation.entity_type}-${source.internal_id}`;
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

const mergeEntitiesRaw = async (
  context: AuthContext,
  user: AuthUser,
  targetEntity: BasicStoreEntity,
  sourceEntities: BasicStoreCommon[],
  targetDependencies: MergeEntitiesDependency,
  sourcesDependencies: MergeEntitiesDependency,
  opts: { chosenFields?: Record<string, any> } = {},
): Promise<void> => {
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
      inferences: elementsInferences.map((e) => e.internal_id),
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
    const targetVocabularyEntity = targetEntity as BasicStoreEntityVocabulary;
    const sourceVocabularyEntities = sourceEntities as BasicStoreEntityVocabulary[];
    const categories = new Set([targetVocabularyEntity.category, ...sourceVocabularyEntities.map((s) => s.category)]);
    if (categories.size > 1) {
      throw FunctionalError('Cannot merge vocabularies of different category', { categories });
    }
    const completeCategory = getVocabulariesCategories().find(({ key }) => key === targetVocabularyEntity.category);
    if (completeCategory) {
      await updateElasticVocabularyValue(sourceVocabularyEntities.map((s) => s.name), targetVocabularyEntity.name, completeCategory);
    }
  }

  // Prepare S3 file move
  // Merge files on S3 and update x_opencti_files path in source => it will be added to target by the merge operation.
  logApp.info('[OPENCTI] Copying files on S3 before merging x_opencti_files');
  const sourceEntitiesWithFiles = sourceEntities.filter((entity) => {
    return entity.x_opencti_files ? entity.x_opencti_files.length > 0 : true;
  });
  for (let i = 0; i < sourceEntitiesWithFiles.length; i += 1) {
    const sourceEntity = sourceEntitiesWithFiles[i];
    if (sourceEntity.x_opencti_files && sourceEntity.x_opencti_files.length > 0) {
      sourceEntity.x_opencti_files = await moveAllFilesFromEntityToAnother(context, user, sourceEntity, targetEntity);
    }
  }
  logApp.info('[OPENCTI] Copy of files on S3 ended.');

  // 2. EACH SOURCE (Ignore createdBy)
  // - EVERYTHING I TARGET (->to) ==> We change to relationship FROM -> TARGET ENTITY
  // - EVERYTHING TARGETING ME (-> from) ==> We change to relationship TO -> TARGET ENTITY
  // region CHANGING FROM
  const { deletions: fromDeletions, redirects: relationsToRedirectFrom } = await filterTargetByExisting(context, targetEntity, 'from', sourcesDependencies, targetDependencies);
  // region CHANGING TO
  const { deletions: toDeletions, redirects: relationsFromRedirectTo } = await filterTargetByExisting(context, targetEntity, 'to', sourcesDependencies, targetDependencies);
  type UpdateConnection = {
    _index: string;
    id: string;
    standard_id: string;
    toReplace: string;
    entity_type: string;
    side: 'source_ref' | 'target_ref';
    data: { internal_id: string; name: string };
  };
  const updateConnections: UpdateConnection[] = [];
  type UpdateEntity = {
    _index: string;
    id: string;
    toReplace: string | null;
    relationType: string;
    entity_type: string;
    data: { internal_id: string | string[] };
  };
  const updateEntities: UpdateEntity[] = [];
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
      side: 'source_ref' as const,
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, entity.i_relation.fromType, entity.i_relation.toType, ROLE_TO)) {
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
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, entity.i_relation.fromType, entity.i_relation.toType, ROLE_FROM)) {
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
      side: 'target_ref' as const,
      data: { internal_id: sideTarget, name: targetEntity.name },
    };
    updateConnections.push(relUpdate);
    // Update the side that will remain (RELATED_ELEMENT)
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, entity.i_relation.fromType, entity.i_relation.toType, ROLE_FROM)) {
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
    if (isImpactedTypeAndSide(entity.i_relation.entity_type, entity.i_relation.fromType, entity.i_relation.toType, ROLE_TO)) {
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
  const concurrentRelsUpdate = async (connsToUpdate: UpdateConnection[]) => {
    await elUpdateRelationConnections(connsToUpdate);
    currentRelsUpdateCount += connsToUpdate.length;
    logApp.info(`[OPENCTI] Merging, updating relations ${currentRelsUpdateCount} / ${updateConnections.length}`);
  };
  await BluePromise.map(groupsOfRelsUpdate, concurrentRelsUpdate, { concurrency: ES_MAX_CONCURRENCY });
  // Update all impacted entities
  logApp.info(`[OPENCTI] Merging impacting ${updateEntities.length} entities for ${targetEntity.internal_id}`);
  const updatesByEntity = R.groupBy((i) => i.id, updateEntities);
  const entries = Object.entries(updatesByEntity) as [string, UpdateEntity[]][];
  let currentEntUpdateCount = 0;
  const updateBulkEntities = entries.filter(([, values]) => values?.length === 1).map(([, values]) => values).flat();
  const groupsOfEntityUpdate = R.splitEvery(MAX_BULK_OPERATIONS, updateBulkEntities);
  const concurrentEntitiesUpdate = async (entitiesToUpdate: UpdateEntity[]) => {
    await elUpdateEntityConnections(entitiesToUpdate);
    currentEntUpdateCount += entitiesToUpdate.length;
    logApp.info(`[OPENCTI] Merging updating bulk entities ${currentEntUpdateCount} / ${updateBulkEntities.length}`);
  };
  await BluePromise.map(groupsOfEntityUpdate, concurrentEntitiesUpdate, { concurrency: ES_MAX_CONCURRENCY });
  // Take care of multi update
  const updateMultiEntities = entries.filter(([, values]) => values.length > 1);
  await BluePromise.map(
    updateMultiEntities,
    async ([id, values]) => {
      logApp.info(`[OPENCTI] Merging, updating single entity ${id} / ${values.length}`);
      const changeOperations = values.filter((element) => element.toReplace !== null);
      const addOperations = values.filter((element) => element.toReplace === null);
      // Group all simple add into single operation
      const groupedAddOperations = R.groupBy((s) => s.relationType, addOperations) as Record<string, UpdateEntity[]>;
      const operations = Object.entries(groupedAddOperations)
        .map(([key, vals]) => {
          const { _index, entity_type } = R.head(vals) as UpdateEntity;
          const ids = vals.map((v) => v.data.internal_id);
          return { id, _index, toReplace: null, relationType: key, entity_type, data: { internal_id: ids } } as UpdateEntity;
        })
        .flat();
      operations.push(...changeOperations);
      // then execute each other one by one
      for (let index = 0; index < operations.length; index += 1) {
        const operation = operations[index];
        await elUpdateEntityConnections([operation]);
      }
    },
    { concurrency: ES_MAX_CONCURRENCY },
  );

  // Take care of relations deletions to prevent duplicate marking definitions.
  const elementToRemoves = [...sourceEntities, ...fromDeletions, ...toDeletions];
  // All not move relations will be deleted, so we need to remove impacted rel in entities.
  await elDeleteElements(context, SYSTEM_USER, elementToRemoves);
  // Everything if fine update remaining attributes
  const updateAttributes: EditInput[] = [];
  // 1. Update all possible attributes
  const attributes = schemaAttributesDefinition.getAttributeNames(targetType);
  const targetFields = attributes.filter((s) => !s.startsWith(INTERNAL_PREFIX));
  for (let fieldIndex = 0; fieldIndex < targetFields.length; fieldIndex += 1) {
    const targetFieldKey = targetFields[fieldIndex];
    const mergedEntityCurrentFieldValue = (targetEntity as Record<string, any>)[targetFieldKey];
    const chosenSourceEntityId = chosenFields[targetFieldKey];
    // Select the one that will fill the empty MONO value of the target
    const takenFrom = chosenSourceEntityId
      ? R.find((i) => i.standard_id === chosenSourceEntityId, sourceEntities)
      : R.head(sourceEntities); // If not specified, take the first one.
    const sourceFieldValue = (takenFrom as Record<string, any>)[targetFieldKey];
    const fieldValues = R.flatten((sourceEntities as Record<string, any>[]).map((s) => s[targetFieldKey])).filter((s) => isNotEmptyField(s));
    // Check if we need to do something
    if (isObjectAttribute(targetFieldKey)) {
      // Special case of object that need to be merged
      const isObjectMultiple = isMultipleAttribute(targetType, targetFieldKey);
      if (isObjectMultiple) {
        updateAttributes.push({ key: targetFieldKey, value: fieldValues, operation: EditOperation.Add });
      } else {
        const mergedDict = R.mergeAll([...fieldValues, mergedEntityCurrentFieldValue]);
        if (isNotEmptyField(mergedDict)) {
          updateAttributes.push({ key: targetFieldKey, value: [mergedDict] });
        }
      }
    } else if (isMultipleAttribute(targetType, targetFieldKey)) {
      const sourceValues = fieldValues || [];
      // For aliased entities, get name of the source to add it as alias of the target
      if (targetFieldKey === ATTRIBUTE_ALIASES || targetFieldKey === ATTRIBUTE_ALIASES_OPENCTI) {
        sourceValues.push(...(sourceEntities as BasicStoreEntity[]).map((s) => s.name).filter((n) => isNotEmptyField(n)));
      }
      // For x_opencti_additional_names exists, add the source name inside
      if (targetFieldKey === ATTRIBUTE_ADDITIONAL_NAMES) {
        sourceValues.push(...(sourceEntities as BasicStoreEntity[]).map((s) => s.name).filter((n) => isNotEmptyField(n)));
      }
      // standard_id of merged entities must be kept in x_opencti_stix_ids
      if (targetFieldKey === IDS_STIX) {
        sourceValues.push(...sourceEntities.map((s) => s.standard_id));
      }
      // If multiple attributes, concat all values
      if (sourceValues.length > 0) {
        const concatSource = mergedEntityCurrentFieldValue as any[] ?? [];
        const multipleValues = R.uniq(R.concat(concatSource, sourceValues));
        updateAttributes.push({ key: targetFieldKey, value: multipleValues, operation: EditOperation.Add });
      }
    } else if (isEmptyField(mergedEntityCurrentFieldValue) && isNotEmptyField(sourceFieldValue)) {
      // Single value. Put the data in the merged field only if empty.
      updateAttributes.push({ key: targetFieldKey, value: [sourceFieldValue] });
    }
  }

  const data = await updateAttributeRaw(context, user, targetEntity, updateAttributes);
  const { impactedInputs } = data;
  // region Update elasticsearch
  // Elastic update with partial instance to prevent data override
  if (impactedInputs.length > 0) {
    const updateAsInstance = partialInstanceWithInputs(targetEntity, impactedInputs) as BasicStoreBase;
    await elUpdateElement(context, user, updateAsInstance);
    logApp.info(`[OPENCTI] Merging attributes success for ${targetEntity.internal_id}`, { update: updateAsInstance });
  }
};
type MergeEntityDependency = {
  _index: string;
  internal_id: string;
  entity_type: string;
  name: string;
  i_relation: StoreRelation;
};
type MergeEntitiesDependency = {
  [INTERNAL_FROM_FIELD]: MergeEntityDependency[];
  [INTERNAL_TO_FIELD]: MergeEntityDependency[];
};
const loadMergeEntitiesDependencies = async (
  context: AuthContext,
  user: AuthUser,
  entityIds: string[],
): Promise<MergeEntitiesDependency> => {
  const data: MergeEntitiesDependency = { [INTERNAL_FROM_FIELD]: [], [INTERNAL_TO_FIELD]: [] };
  for (let entityIndex = 0; entityIndex < entityIds.length; entityIndex += 1) {
    const entityId = entityIds[entityIndex];
    // Internal From
    const listFromCallback = async (elements: StoreRelation[]) => {
      const findArgs = { toMap: true, baseData: true };
      const relTargets = await internalFindByIds(context, user, elements.map((rel) => rel.toId), findArgs) as Record<string, BasicStoreObject>;
      for (let index = 0; index < elements.length; index += 1) {
        const rel = elements[index];
        if (relTargets[rel.toId]) {
          data[INTERNAL_FROM_FIELD].push({
            _index: relTargets[rel.toId]._index,
            internal_id: rel.toId,
            entity_type: rel.toType,
            name: rel.toName,
            i_relation: rel,
          });
        }
      }
    };
    const fromArgs = { baseData: true, fromId: entityId, callback: listFromCallback };
    await fullRelationsList(context, user, ABSTRACT_STIX_RELATIONSHIP, fromArgs);
    // Internal to
    const listToCallback = async (elements: StoreRelation[]) => {
      const findArgs = { toMap: true, baseData: true };
      const relSources = await internalFindByIds(context, user, elements.map((rel) => rel.fromId), findArgs) as Record<string, BasicStoreObject>;
      for (let index = 0; index < elements.length; index += 1) {
        const rel = elements[index];
        if (relSources[rel.fromId]) {
          data[INTERNAL_TO_FIELD].push({
            _index: relSources[rel.fromId]._index,
            internal_id: rel.fromId,
            entity_type: rel.fromType,
            name: rel.fromName,
            i_relation: rel,
          });
        }
      }
    };
    const toArgs = { baseData: true, toId: entityId, callback: listToCallback };
    await fullRelationsList(context, user, ABSTRACT_STIX_RELATIONSHIP, toArgs);
  }
  return data;
};

export const mergeEntities = async (
  context: AuthContext,
  user: AuthUser,
  targetEntityId: string,
  sourceEntityIds: string[],
  opts: { locks?: string[]; chosenFields?: Record<string, any> } & EventOpts = {},
) => {
  // Pre-checks
  if (sourceEntityIds.includes(targetEntityId)) {
    throw FunctionalError('Cannot merge entities, same ID detected in source and destination', {
      targetEntityId,
      sourceEntityIds,
    });
  }
  logApp.info(`[OPENCTI] Merging ${sourceEntityIds} in ${targetEntityId}`);
  // targetEntity and sourceEntities must be accessible
  const mergedIds = [targetEntityId, ...sourceEntityIds];
  const mergedInstances = await internalFindByIds(context, user, mergedIds) as BasicStoreObject[];
  if (mergedIds.length !== mergedInstances.length) {
    throw FunctionalError('Cannot access all entities for merging');
  }
  mergedInstances.forEach((instance) => controlUserConfidenceAgainstElement(user, instance));
  if (mergedInstances.some((o) => o.entity_type === ENTITY_TYPE_VOCABULARY && Boolean((o as BasicStoreEntityVocabulary).builtIn))) {
    throw FunctionalError('Cannot merge builtin vocabularies');
  }
  // We need to lock all elements not locked yet.
  const { locks = [] } = opts;
  const participantIds = mergedIds.filter((e) => !locks.includes(e));
  let lock;
  try {
    // Lock the participants that will be merged
    lock = await lockResources(participantIds, { draftId: getDraftContext(context, user) });
    // Entities must be fully loaded with admin user to resolve/move all dependencies
    const initialInstance = await storeLoadByIdWithRefs<StoreObject>(context, user, targetEntityId);
    if (!initialInstance) {
      throw FunctionalError('Cannot access initial instance', { targetEntityId });
    }
    const target = { ...initialInstance } as BasicStoreEntity;
    const sources = await storeLoadByIdsWithRefs(context, SYSTEM_USER, sourceEntityIds);
    const sourcesDependencies = await loadMergeEntitiesDependencies(context, SYSTEM_USER, sources.map((s) => s.internal_id));
    const targetDependencies = await loadMergeEntitiesDependencies(context, SYSTEM_USER, [initialInstance.internal_id]);
    // - TRANSACTION PART
    lock.signal.throwIfAborted();
    await mergeEntitiesRaw(context, user, target, sources, targetDependencies, sourcesDependencies, opts);
    const mergedInstance = await storeLoadByIdWithRefs<StoreObject>(context, user, targetEntityId);
    if (!mergedInstance) {
      throw FunctionalError('Cannot access merged instance', { targetEntityId });
    }
    await storeMergeEvent(context, user, initialInstance, mergedInstance, sources, opts);
    // Temporary stored the deleted elements to prevent concurrent problem at creation
    await redisAddDeletions(sources.map((s) => s.internal_id), getDraftContext(context, user));
    // - END TRANSACTION
    return await storeLoadById(context, user, target.id, ABSTRACT_STIX_OBJECT).then((finalStixCoreObject) => {
      return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalStixCoreObject, user);
    });
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const transformPatchToInput = (
  patch: Record<string, any>,
  operations: Record<string, undefined | 'add' | 'remove' | 'replace'> = {},
): EditInput[] => {
  return R.pipe(
    R.toPairs,
    R.map((t) => {
      const val = R.last(t) as any;
      const key = R.head(t) as string;
      const operation = operations[key] || UPDATE_OPERATION_REPLACE;
      if (!R.isNil(val)) {
        return { key, value: Array.isArray(val) ? val : [val], operation };
      }
      return { key, value: null, operation } as any;
    }),
  )(patch);
};
const checkAttributeConsistency = (entityType: string, key: string) => {
  if (key.startsWith(RULE_PREFIX)) {
    return;
  }
  // Always ok for creator_id, need a stronger schema definition
  // Waiting for merge of https://github.com/OpenCTI-Platform/opencti/issues/1850
  if (key === 'creator_id') {
    return;
  }
  const entityAttributes = schemaAttributesDefinition.getAttributeNames(entityType);
  if (!R.includes(key, entityAttributes)) {
    throw FunctionalError('This attribute key is not allowed, please check your registration attribute name', { key, entity_type: entityType });
  }
};
const innerUpdateAttribute = (instance: BasicStoreBase, rawInput: EditInput): EditInput | undefined => {
  const { key } = rawInput;
  // Check consistency
  checkAttributeConsistency(instance.entity_type, key);
  const input = rebuildAndMergeInputFromExistingData(rawInput, instance);
  if (R.isEmpty(input)) {
    return undefined;
  }
  return input as EditInput;
};
const prepareAttributesForUpdate = async (
  context: AuthContext,
  user: AuthUser,
  instance: BasicStoreBase,
  elements: EditInput[],
) => {
  const instanceType = instance.entity_type;
  const platformStatuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  return elements.map((input) => {
    // Dynamic cases, attributes not defined in the schema
    if (input.key.startsWith(RULE_PREFIX) || input.key.startsWith(REL_INDEX_PREFIX)) {
      return input;
    }
    // Fixed cases in schema definition
    const def = schemaAttributesDefinition.getAttribute(instance.entity_type, input.key);
    if (!def) {
      throw UnsupportedError('Cant prepare attribute for update', { type: instance.entity_type, name: input.key });
    }
    // Specific case for Label
    if (input.key === VALUE_FIELD && instanceType === ENTITY_TYPE_LABEL) {
      return {
        key: input.key,
        value: input.value.map((v) => v.toLowerCase()),
      };
    }
    // Aliases can't have the same name as entity name and an already existing normalized alias
    if (input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI) {
      const filteredValues = input.value.filter((e) => normalizeName(e) !== normalizeName((instance as BasicStoreEntity).name));
      const uniqAliases = R.uniqBy((e) => normalizeName(e), filteredValues);
      return { key: input.key, value: uniqAliases };
    }
    // For upsert or update, workflow cant be reset or setup on un-existing workflow
    if (input.key === X_WORKFLOW_ID) {
      const workflowId = R.head(input.value);
      const instanceTypeStatuses = platformStatuses.filter((status) => status.type === instance.entity_type);
      // If workflow is not found for current entity type, remove the input
      if (instanceTypeStatuses?.length === 0 || !instanceTypeStatuses.some((entityStatus) => entityStatus.internal_id === workflowId)) {
        return null;
      }
    }
    // Check integer
    if (def.type === 'numeric') {
      return {
        key: input.key,
        value: (input.value ?? []).map((value) => {
          // Like at creation, we need to be sure that confidence is default to 0
          const baseValue = (input.key === confidence.name && isEmptyField(value)) ? 0 : value;
          const parsedValue = baseValue ? Number(baseValue) : baseValue;
          return Number.isNaN(parsedValue) ? null : parsedValue;
        }),
      };
    }
    // Check boolean
    if (def.type === 'boolean') {
      return {
        key: input.key,
        value: (input.value ?? []).map((value) => {
          return value === true || value === 'true';
        }),
      };
    }
    // Check dates for empty values
    if (def.type === 'date') {
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
    }
    // No need to rework the input
    return input;
  }).filter((i) => isNotEmptyField(i)) as EditInput[];
};

const getPreviousInstanceValue = (key: string, instance: Record<string, any>) => {
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

const updateDateRangeValidation = (instance: Record<string, any>, inputs: EditInput[], from: string, to: string) => {
  const fromVal = R.head(R.find((e) => e.key === from, inputs)?.value || [instance[from]]);
  const toVal = R.head(R.find((e) => e.key === to, inputs)?.value || [instance[to]]);
  if (utcDate(fromVal) > utcDate(toVal)) {
    const data = { [from]: fromVal, [to]: toVal };
    throw DatabaseError(`You cant update an element with ${to} less than ${from}`, data);
  }
};
type UpdateAttribueRawOpts = {
  impactStandardId?: boolean;
  upsert?: boolean;
};
const updateAttributeRaw = async (
  context: AuthContext,
  user: AuthUser,
  instance: BasicStoreBase,
  inputs: EditInput[] | EditInput,
  opts: UpdateAttribueRawOpts = {},
): Promise<{
  updatedInputs: (EditInput & { previous: any })[]; // Sourced inputs for event stream
  impactedInputs: EditInput[]; // All inputs that need to be re-indexed. (so without meta relationships)
  updatedInstance: Record<string, any>;
}> => {
  const today = now();
  // Upsert option is only useful to force aliases to be kept when upserting the entity
  const { impactStandardId = true, upsert = false } = opts;
  const elements = Array.isArray(inputs) ? inputs : [inputs];
  const instanceType = instance.entity_type;
  // Prepare attributes
  const preparedElements = await prepareAttributesForUpdate(context, user, instance, elements);
  // region Check date range
  const inputKeys = elements.map((i) => i.key);
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
    const aliasedInstance = instance as BasicStoreEntity;
    const aliasField = resolveAliasesField(instanceType).name;
    const nameInput = R.find((e) => e.key === NAME_FIELD, preparedElements);
    const aliasesInput = R.find((e) => e.key === aliasField, preparedElements);
    if (nameInput || aliasesInput) {
      const askedModificationName = nameInput ? R.head(nameInput.value) : undefined;
      // Cleanup the alias input.
      if (aliasesInput) {
        const preparedAliases = (aliasesInput.value ?? [])
          .filter((a) => isNotEmptyField(a))
          .filter((a) => normalizeName(a) !== normalizeName(aliasedInstance.name)
            && normalizeName(a) !== normalizeName(askedModificationName))
          .map((a) => a.trim());
        aliasesInput.value = R.uniqBy((e) => normalizeName(e), preparedAliases);
      }
      // In case of upsert name change, old name must be pushed in aliases
      // If aliases are also ask for modification, we need to change the input
      if (askedModificationName && normalizeName(aliasedInstance.name) !== normalizeName(askedModificationName)) {
        // If name change, we need to add the old name in aliases
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const aliases = [...(aliasedInstance[aliasField] ?? [])];
        if (upsert) {
          // For upsert, we concatenate everything to be none destructive
          aliases.push(...(aliasesInput ? aliasesInput.value : []));
          if (!aliases.includes(aliasedInstance.name)) {
            // If name changing is part of an upsert, the previous name must be copied into aliases
            aliases.push(aliasedInstance.name);
          }
          const uniqAliases = R.uniqBy((e) => normalizeName(e), aliases).filter((a) => a !== askedModificationName);
          if (aliasesInput) { // If aliases input also exists
            aliasesInput.value = uniqAliases;
          } else { // We need to create an extra input getting existing aliases
            const generatedAliasesInput = { key: aliasField, value: uniqAliases };
            preparedElements.push(generatedAliasesInput);
          }
        } else if (!aliasesInput) {
          // Name change can create a duplicate with aliases
          // If it's the case aliases must be also patched.
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          const currentAliases = aliasedInstance[aliasField] || [];
          const targetAliases = currentAliases.filter((a: string) => a !== askedModificationName);
          if (currentAliases.length !== targetAliases.length) {
            const generatedAliasesInput = { key: aliasField, value: targetAliases };
            preparedElements.push(generatedAliasesInput);
          }
        }
        // Regenerated the internal ids with the instance target aliases
        const aliasesId = generateAliasesId(aliases, aliasedInstance);
        const aliasInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
        preparedElements.push(aliasInput);
      } else if (aliasesInput) {
        // No name change asked but aliases addition
        if (upsert) {
          // In upsert we cumulate with current aliases
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          aliasesInput.value = R.uniqBy((e) => normalizeName(e), [...aliasesInput.value, ...(aliasedInstance[aliasField] || [])]);
        }
        // Internal ids alias must be generated again
        const aliasesId = generateAliasesId(aliasesInput.value, aliasedInstance);
        const aliasIdsInput = { key: INTERNAL_IDS_ALIASES, value: aliasesId };
        preparedElements.push(aliasIdsInput);
        // Purge removed alias IDs from other stix IDS
        const currentStixIds = aliasedInstance[IDS_STIX] ?? [];
        const removedAliasesIds = aliasedInstance[INTERNAL_IDS_ALIASES]?.filter((aid) => !aliasesId.includes(aid));
        const stixIdsInput = R.find((e) => e.key === IDS_STIX, preparedElements);
        if (stixIdsInput) {
          stixIdsInput.value = stixIdsInput.value.filter((sid) => !removedAliasesIds?.includes(sid));
        } else {
          const newStixIds = currentStixIds.filter((sid) => !removedAliasesIds?.includes(sid));
          if (newStixIds.length < currentStixIds.length) {
            const newStixIdsInput = { key: IDS_STIX, value: newStixIds };
            preparedElements.push(newStixIdsInput);
          }
        }
      }
    }
  }
  // endregion
  // region Artifact and file additional names
  // In case of artifact and file, we need to keep name in additional names in case of upsert
  const isNamedObservable = instanceType === ENTITY_HASHED_OBSERVABLE_ARTIFACT || instanceType === ENTITY_HASHED_OBSERVABLE_STIX_FILE;
  if (upsert && isNamedObservable) {
    const namedObservableInstance = instance as BasicStoreCyberObservable;
    const nameInput = R.find((e) => e.key === NAME_FIELD, preparedElements);
    // In Upsert mode, x_opencti_additional_names update must not be destructive, previous names must be kept
    const additionalNamesInput = R.find((e) => e.key === ATTRIBUTE_ADDITIONAL_NAMES, preparedElements);
    if (additionalNamesInput) {
      const names = [...additionalNamesInput.value, ...(namedObservableInstance[ATTRIBUTE_ADDITIONAL_NAMES] ?? [])];
      if (nameInput) { // If name will be replaced, add it in additional names
        names.push(namedObservableInstance[NAME_FIELD]);
      }
      additionalNamesInput.value = R.uniq(names);
    } else if (nameInput) { // If name will be replaced, add it in additional names
      const newAdditional = [namedObservableInstance[NAME_FIELD], ...(namedObservableInstance[ATTRIBUTE_ADDITIONAL_NAMES] ?? [])];
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
      if (isStixCyberObservableHashedObservable(instanceType) && preparedElements.length > 0) {
        const instanceStandardIds = generateHashedObservableStandardIds(instance);
        const updatedInstanceStandardIds = generateHashedObservableStandardIds(updatedInstance) as StixId[];
        const instanceStixIds = (instance[IDS_STIX] ?? []);
        const instanceOtherStixIds = instanceStixIds.filter((id) => !instanceStandardIds.includes(id));
        const newStixIds = [...instanceOtherStixIds, ...updatedInstanceStandardIds].filter((id) => id !== standardId);
        const stixIdsHaveNotChanged = instanceStixIds.length === newStixIds.length
          && newStixIds.every((id: StixId) => instanceStixIds.includes(id));

        const stixInput = R.find((e) => e.key === IDS_STIX, preparedElements);
        if (stixInput) {
          // If update already contains a change of the other stix ids
          // we need to impact directly the impacted and updated related input
          if (stixInput.operation === UPDATE_OPERATION_REPLACE) {
            const stixIds = [...stixInput.value, ...updatedInstanceStandardIds].filter((id) => id !== standardId);
            stixInput.value = R.uniq(stixIds);
          } else if (stixInput.operation === UPDATE_OPERATION_REMOVE) {
            stixInput.value = R.uniq(newStixIds.filter((id) => !stixInput.value.includes(id)));
          } else {
            stixInput.value = R.uniq([...stixInput.value, ...newStixIds]);
          }
          stixInput.operation = EditOperation.Replace;
        } else if (!stixIdsHaveNotChanged) {
          // If no stix ids modification, add the standard id in the list and patch the element
          preparedElements.push({ key: IDS_STIX, value: R.uniq(newStixIds) });
        }
      } else if (isStandardIdUpgraded(instance, updatedInstance)) {
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
          stixInput.operation = EditOperation.Replace;
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
  const updatedInputs: (EditInput & { previous: any })[] = [];
  const impactedInputs: EditInput[] = [];
  for (let index = 0; index < preparedElements.length; index += 1) {
    const input = preparedElements[index];
    const ins = innerUpdateAttribute(instance, input);
    if (ins) { // If update will really produce a data change
      impactedInputs.push(ins);
      // region Compute the update to push in the stream
      if (!input.key.startsWith('i_') && input.key !== 'x_opencti_graph_data' && !input.key.startsWith('decay_') && input.key !== 'opinions_metrics') {
        const previous = getPreviousInstanceValue(input.key, instance);
        if (input.operation === UPDATE_OPERATION_ADD || input.operation === UPDATE_OPERATION_REMOVE) {
          // Check symmetric difference for add and remove
          updatedInputs.push({
            operation: input.operation,
            key: input.key,
            value: R.symmetricDifference(previous ?? [], ins.value ?? []),
            previous,
          });
        } else {
          updatedInputs.push({ ...input, previous });
        }
      }
      // endregion
    }
  }
  // Impact the updated_at only if stix data is impacted
  // In case of upsert, this addition will be supported by the parent function
  if (impactedInputs.length > 0 && isUpdatedAtObject(instance.entity_type)
    && !impactedInputs.find((i) => i.key === 'updated_at')) {
    const updatedAtInput = { key: 'updated_at', value: [today] };
    impactedInputs.push(updatedAtInput);
  }
  if (impactedInputs.length > 0 && isModifiedObject(instance.entity_type)
    && !impactedInputs.find((i) => i.key === 'modified')) {
    const modifiedAtInput = { key: 'modified', value: [today] };
    impactedInputs.push(modifiedAtInput);
  }
  if (impactedInputs.length > 0 && isUpdatedAtObject(instance.entity_type)
    && !impactedInputs.find((i) => i.key === 'refreshed_at')) {
    const refreshedAtInput = { key: 'refreshed_at', value: [today] };
    impactedInputs.push(refreshedAtInput);
  }
  return {
    updatedInputs, // Sourced inputs for event stream
    impactedInputs, // All inputs that need to be re-indexed. (so without meta relationships)
    updatedInstance: mergeInstanceWithInputs(instance, impactedInputs),
  };
};

export const generateUpdateMessage = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  inputs: EditInput[],
): Promise<string> => {
  const isWorkflowChange = inputs.filter((i) => i.key === X_WORKFLOW_ID).length > 0;
  const platformStatuses = isWorkflowChange ? await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS) : [];
  const resolvedInputs = inputs.map((i) => {
    if (i.key === X_WORKFLOW_ID) {
      // workflow_id is not a relation but message must contain the name and not the internal id
      const workflowId = R.head(i.value);
      const workflowStatus = workflowId ? platformStatuses.find((p) => p.id === workflowId) : workflowId;
      return ({
        ...i,
        value: [workflowStatus ? workflowStatus.name : null],
      });
    }
    return i;
  });

  const inputsByOperations = R.groupBy((m) => m.operation ?? UPDATE_OPERATION_REPLACE, resolvedInputs);
  const patchElements = Object.entries(inputsByOperations);
  if (patchElements.length === 0) {
    throw UnsupportedError('Generating update message with empty inputs fail');
  }

  const authorizedMembersIds = getKeyValuesFromPatchElements(patchElements, authorizedMembers.name).map(({ id }: { id: string }) => id);
  let members: BasicStoreBase[] = [];
  if (authorizedMembersIds.length > 0) {
    members = await internalFindByIds(context, SYSTEM_USER, authorizedMembersIds, {
      baseData: true,
      baseFields: ['internal_id', 'name'],
    }) as BasicStoreBase[];
  }

  const creatorsIds = getKeyValuesFromPatchElements(patchElements, creatorsAttribute.name);
  let creators = [];
  if (creatorsIds.length > 0 && !(creatorsIds.length === 1 && creatorsIds.includes(user.id))) {
    // get creators only if it's not the current user (which will be 'itself')
    const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
    creators = creatorsIds.map((id: string) => platformUsers.get(id));
  }
  return generateUpdatePatchMessage(patchElements, entityType, { members, creators });
};
const buildAttribute = async (context: AuthContext, user: AuthUser, key: string, array: any[]) => {
  const results = await Promise.all(array.map(async (item) => {
    if (!item) {
      return item;
    }
    if (typeof item === 'object') {
      if (item?.entity_type !== undefined) {
        return extractEntityRepresentativeName(item);
      } else {
        return item?.toString();
      }
    } else if (typeof item === 'string' && key === creatorsAttribute.name) {
      const users = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_USER);
      const creator = users.get(item);
      if (creator) {
        return extractEntityRepresentativeName(creator);
      }
    }
    return item;
  }));
  return results.filter((item) => item !== null && item !== undefined);
};
export const buildChanges = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  inputs: (EditInput & { previous?: any })[],
): Promise<Change[]> => {
  const changes: Change[] = [];
  for (const input of inputs) {
    const { key, previous, value, operation } = input;
    if (!key) continue;
    const field = getKeyName(entityType, key);
    const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
    const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
    let isMultiple = false;
    if (attributeDefinition) {
      isMultiple = schemaAttributesDefinition.isMultipleAttribute(entityType, (attributeDefinition?.name ?? ''));
    } else if (relationsRefDefinition) {
      isMultiple = relationsRefDefinition.multiple;
    }

    const previousArrayFull = Array.isArray(previous) ? previous : [previous];
    const valueArrayFull = Array.isArray(value) ? value : [value];
    const previousArray = await buildAttribute(context, user, key, previousArrayFull);
    const valueArray = await buildAttribute(context, user, key, valueArrayFull);

    if (isMultiple) {
      let added = [];
      let removed = [];
      let newValues = [];
      if (operation === UPDATE_OPERATION_ADD) {
        added = valueArray.filter((valueItem) => !previousArray.find((previousItem) => JSON.stringify(previousItem) === JSON.stringify(valueItem)));
        newValues = previousArray.concat(valueArray);
      } else if (operation === UPDATE_OPERATION_REMOVE) {
        removed = valueArray;
        newValues = previousArray.filter((valueItem) => !valueArray.find((previousItem) => JSON.stringify(previousItem) === JSON.stringify(valueItem)));
      } else {
        // UPDATE_OPERATION_REPLACE or no operation is the same
        removed = previousArray.filter((previousItem) => !valueArray.find((valueItem) => JSON.stringify(previousItem) === JSON.stringify(valueItem)));
        added = valueArray.filter((valueItem) => !previousArray.find((previousItem) => JSON.stringify(previousItem) === JSON.stringify(valueItem)));
        newValues = valueArray;
      }

      if (added.length > 0 || removed.length > 0) {
        changes.push({
          field,
          previous: previousArray,
          new: newValues,
          added,
          removed,
        });
      }
    } else if (isMultiple === false) {
      const isStatusChange = inputs.filter((i) => i.key === X_WORKFLOW_ID).length > 0;
      const platformStatuses = isStatusChange ? await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS) : [];
      const resolvedValue = (array: any[]) => {
        if (field === 'Workflow status') {
          // we want the status name and not its internal id
          const statusId = array[0];
          const status = statusId ? platformStatuses.find((p) => p.id === statusId) : statusId;
          return status ? [status.name] : null;
        }
        return array;
      };

      changes.push({
        field,
        previous: resolvedValue(previousArray),
        new: resolvedValue(valueArray),
      });
    } else {
      // This should not happen so better at least log at info level to be able to debug.
      logApp.info('Changes cannot be computed', { inputs, entityType });
    }
  }
  return changes;
};
type UpdateAttributeMetaResolvedOpts = {
  locks?: string[];
  impactStandardId?: boolean;
  references?: string[];
  commitMessage?: string;
  bypassIndividualUpdate?: boolean;
  bypassValidation?: boolean;
};
export const updateAttributeMetaResolved = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  initial: T,
  inputs: EditInput[],
  opts: UpdateAttributeMetaResolvedOpts = {},
): Promise<{ element: T; event?: UpdateEvent | null; isCreation?: boolean }> => {
  const { locks = [], impactStandardId = true } = opts;
  const updates = Array.isArray(inputs) ? inputs : [inputs];
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  // Region - Pre-Check
  const references: BasicStoreObject[] = opts.references
    ? await internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) as BasicStoreObject[]
    : [];
  if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
    throw FunctionalError('Cant find element references for commit', { id: initial.internal_id, references: opts.references });
  }
  // Endregion
  // Individual check
  const { bypassIndividualUpdate } = opts;
  if (initial.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL && !isEmptyField((initial as BasicStoreEntity).contact_information) && !bypassIndividualUpdate) {
    const isIndividualUser = await isIndividualAssociatedToUser(context, initial as BasicStoreEntity);
    if (isIndividualUser) {
      throw FunctionalError('Cannot update an individual corresponding to a user', { id: initial.internal_id });
    }
  }
  if (updates.length === 0) {
    return { element: initial };
  }
  // Check user access update
  let accessOperation = AccessOperation.EDIT;
  if (updates.some((e) => e.key === authorizedMembers.name)) {
    accessOperation = AccessOperation.MANAGE_ACCESS;
    if (schemaAttributesDefinition.getAttribute(initial.entity_type, authorizedMembersActivationDate.name)
      && (!initial.restricted_members || initial.restricted_members.length === 0)
      && updates.some((e) => e.key === authorizedMembers.name && e.value?.length > 0)) {
      updates.push({
        key: authorizedMembersActivationDate.name,
        value: [now()],
      });
    }
  }

  // Vulnerabilities updates
  if (initial.entity_type === ENTITY_TYPE_VULNERABILITY) {
    const vulnerabilitiesUpdates = generateVulnerabilitiesUpdates(initial as unknown as Vulnerability, updates);
    if (vulnerabilitiesUpdates.length > 0) {
      updates.push(...vulnerabilitiesUpdates);
    }
  }

  if (updates.some((e) => e.key === 'authorized_authorities')) {
    accessOperation = AccessOperation.MANAGE_AUTHORITIES_ACCESS;
  }
  const draftId = getDraftContext(context, user);
  const draft = draftId ? await findDraftById(context, user, draftId) : null;
  if (!validateUserAccessOperation(user, initial, accessOperation, draft)) {
    throw ForbiddenAccess();
  }
  // Split attributes and meta
  // Supports inputs meta or stix meta
  const metaKeys = [
    ...schemaRelationsRefDefinition.getStixNames(initial.entity_type),
    ...schemaRelationsRefDefinition.getInputNames(initial.entity_type),
  ];
  const meta = updates.filter((e) => metaKeys.includes(e.key));
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  const updated = mergeInstanceWithUpdateInputs(initial, inputs);
  const keys = R.map((t) => t.key, attributes);
  if (opts.bypassValidation !== true) { // Allow creation directly from the back-end
    const entitySetting = await getEntitySettingFromCache(context, initial.entity_type);
    const isAllowedToByPass = isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE);
    if (!isAllowedToByPass && entitySetting?.enforce_reference) {
      const isNoReferenceKey = keys.length === 1 && noReferenceAttributes.includes(keys[0]);
      if (!isNoReferenceKey && isEmptyField(opts.references)) {
        throw ValidationError('You must provide at least one external reference to update', 'references');
      }
    }
  }
  let locksIds = getInstanceIds(initial);
  // 01. Check if updating alias lead to entity conflict
  if (isStixObjectAliased(initial.entity_type)) {
    // If user ask for aliases modification, we need to check if it not already belong to another entity.
    const isInputAliases = (input: { key: string }) => input.key === ATTRIBUTE_ALIASES || input.key === ATTRIBUTE_ALIASES_OPENCTI;
    const aliasedInputs = R.filter((input) => isInputAliases(input), attributes);
    if (aliasedInputs.length > 0) {
      const aliases = R.uniq(aliasedInputs.map((a) => a.value).flat().filter((a) => isNotEmptyField(a)).map((a) => a.trim()));
      const aliasesIds = generateAliasesId(aliases, initial);
      const existingEntities = await internalFindByIds(context, SYSTEM_USER, aliasesIds, { type: initial.entity_type }) as BasicStoreObject[];
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
    const otherIds = [...(initial[IDS_STIX] ?? []), ...(initial.i_aliases_ids ?? [])];
    if (targetStandardId !== initial.standard_id && !otherIds.includes(targetStandardId)) {
      locksIds.push(targetStandardId);
      eventualNewStandardId = targetStandardId;
    }
  }
  // --- take lock, ensure no one currently create or update this element
  let lock;
  const participantIds = R.uniq(locksIds.filter((e) => !locks.includes(e)));
  try {
    // Try to get the lock in redis
    lock = await lockResources(participantIds, { draftId: getDraftContext(context, user) });
    // region handle attributes
    // Only for StixCyberObservable
    const lookingEntities: BasicStoreBase[] = [];
    let existingEntityPromise;
    let existingByHashedPromise;
    if (eventualNewStandardId) {
      existingEntityPromise = internalLoadById(context, SYSTEM_USER, eventualNewStandardId, { type: initial.entity_type });
    }
    if (isStixCyberObservableHashedObservable(initial.entity_type)) {
      existingByHashedPromise = listEntitiesByHashes(context, SYSTEM_USER, initial.entity_type, updated.hashes)
        .then((entities) => entities.filter((e) => e.id !== initial.internal_id));
    }
    const [existingEntity, existingByHashed] = await BluePromise.all([existingEntityPromise, existingByHashedPromise]);
    if (existingEntity) {
      lookingEntities.push(existingEntity);
    }
    if (existingByHashed) {
      lookingEntities.push(...existingByHashed);
    }
    const existingEntities = R.uniqBy((e) => e.internal_id, lookingEntities);
    // If already exist entities
    if (existingEntities.length > 0) {
      // If stix observable, we can merge. If not throw an error.
      if (isStixCyberObservable(initial.entity_type)) {
        // Everything ok, let merge
        hashMergeValidation([updated, ...(existingEntities as BasicStoreCommon[])]);
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
    // endregion
    // region handle metas
    const relationsToCreate: any[] = [];
    const relationsToDelete: any[] = [];
    const buildInstanceRelTo = (
      to: BasicStoreBase | BasicStoreBase[],
      relType: string | undefined,
    ): any[] => buildInnerRelation(initial, to, relType);
    for (let metaIndex = 0; metaIndex < meta.length; metaIndex += 1) {
      const { key: metaKey } = meta[metaIndex];
      const key = schemaRelationsRefDefinition.convertStixNameToInputName(updatedInstance.entity_type, metaKey) || metaKey;
      const relDef = schemaRelationsRefDefinition.getRelationRef(updatedInstance.entity_type, key);
      if (!relDef) {
        throw FunctionalError('Cant find updated instance relation ref from key');
      }
      const relType = relDef.databaseName;
      // ref and _refs are expecting direct identifier in the value
      // We don't care about the operation here, the only thing we can do is replace
      if (!relDef.multiple) {
        const currentValue = updatedInstance[key];
        const { value: targetsCreated } = meta[metaIndex];
        const targetCreated = R.head(targetsCreated);
        // If asking for a real change
        if (currentValue?.id !== targetCreated?.internal_id) {
          // Delete the current relation
          if (currentValue?.standard_id) {
            const currentRels = (await fullRelationsList(context, user, relType, { fromId: initial.id }))
              .map((rel) => ({
                ...rel,
                // we resolve from and to without need of an extra query
                to: targetCreated,
                from: initial,
              }));
            relationsToDelete.push(...currentRels);
          }
          // Create the new one
          if (isNotEmptyField(targetCreated)) {
            relationsToCreate.push(...buildInstanceRelTo(targetCreated, relType));
            const previous = currentValue ? [currentValue] : currentValue;
            updatedInputs.push({ key, value: [targetCreated], previous });
            updatedInstance[key] = targetCreated;
            updatedInstance[relType] = targetCreated.internal_id;
          } else if (currentValue) {
            // Just replace by nothing
            updatedInputs.push({ key, value: [null], previous: [currentValue] });
            updatedInstance[key] = null;
            updatedInstance[relType] = null;
          }
        }
      } else {
        // Special access check for RELATION_GRANTED_TO meta
        // If not supported, update must be rejected
        const isUserCanManipulateGrantedRefs = isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && settings.valid_enterprise_edition === true;
        if (relType === RELATION_GRANTED_TO && !isUserCanManipulateGrantedRefs) {
          throw ForbiddenAccess();
        }
        let { value: refs, operation = UPDATE_OPERATION_REPLACE } = meta[metaIndex];
        if (relType === RELATION_OBJECT_MARKING) {
          const markingsCleaned = await handleMarkingOperations(context, (initial as StoreCommon).objectMarking, refs, operation);
          ({ operation, refs } = { operation: markingsCleaned.operation, refs: markingsCleaned.refs });
        }
        if (operation === UPDATE_OPERATION_REPLACE) {
          // Delete all relations
          const currentRels = await fullRelationsList(context, user, relType, { indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, fromId: initial.internal_id });
          const currentRelsToIds = currentRels.map((n: BasicStoreRelation) => n.toId);
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
            updatedInstance[relType] = newTargetsIds;
          }
        }
        if (operation === UPDATE_OPERATION_ADD) {
          const filteredList = (updatedInstance[key] || []).filter((d: any) => !isInferredIndex(d.i_relation._index));
          const currentIds = filteredList.map((o: any) => [o.id, o.standard_id]).flat();
          const refsToCreate = refs.filter((r) => !currentIds.includes(r.internal_id));
          if (refsToCreate.length > 0) {
            const newRelations = buildInstanceRelTo(refsToCreate, relType);
            relationsToCreate.push(...newRelations);
            updatedInputs.push({ key, value: refsToCreate, operation: operation as unknown as any, previous: updatedInstance[key] });
            updatedInstance[key] = [...(updatedInstance[key] || []), ...refsToCreate];
            updatedInstance[relType] = updatedInstance[key].map((u: any) => u.internal_id);
          }
        }
        if (operation === UPDATE_OPERATION_REMOVE) {
          const targetIds = refs.map((t) => t.internal_id);
          const currentRels = await fullRelationsList(context, user, relType, { indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, fromId: initial.internal_id });
          const relsToDelete = currentRels.filter((c) => targetIds.includes(c.toId))
            .map((r) => ({
              ...r,
              // we resolve from and to without need of an extra query
              to: refs.find((ref) => ref.internal_id === r.toId),
              from: initial,
            }));

          if (relsToDelete.length > 0) {
            relationsToDelete.push(...relsToDelete);
            updatedInputs.push({ key, value: refs, operation: operation as unknown as any, previous: updatedInstance[key] });
            updatedInstance[key] = (updatedInstance[key] || []).filter((c: any) => !targetIds.includes(c.internal_id));
            updatedInstance[relType] = updatedInstance[key].map((u: any) => u.internal_id);
          }
        }
      }
    }
    // endregion
    // region build attributes inner information
    lock.signal.throwIfAborted();
    const impactedKeys: string[] = impactedInputs.map((input) => input.key);
    impactedKeys.push(...[...relationsToCreate, ...relationsToDelete].map((rel: any) => {
      if (!updatedInstance.entity_type || !rel.relationship_type) {
        return null;
      }
      return schemaRelationsRefDefinition.convertDatabaseNameToInputName(updatedInstance.entity_type, rel.relationship_type);
    }) as string[]);
    const preventAttributeFollow = [updatedAt.name, modified.name, iAliasedIds.name];
    const uniqImpactKeys = R.uniq(impactedKeys.filter((key) => !preventAttributeFollow.includes(key)));
    if (uniqImpactKeys.length > 0) {
      // Impact the updated_at only if stix data is impacted
      const updatePatch = mergeInstanceWithInputs(initial, impactedInputs);
      const { confidenceLevelToApply } = controlUpsertInputWithUserConfidence(user, updatePatch as ObjectWithConfidence, initial);
      const currentAttributes = initial.i_attributes ?? [];
      const attributesMap = new Map(currentAttributes.map((obj: any) => [obj.name, obj]));
      for (let i = 0; i < uniqImpactKeys.length; i += 1) {
        const uniqImpactKey = uniqImpactKeys[i];
        attributesMap.set(uniqImpactKey, {
          name: uniqImpactKey,
          updated_at: context?.eventId ? computeDateFromEventId(context.eventId) : now(),
          confidence: confidenceLevelToApply,
          user_id: user.internal_id,
        });
      }
      const attributesAtInput = { key: iAttributes.name, value: Array.from(attributesMap.values()) };
      impactedInputs.push(attributesAtInput);
    }
    // endregion
    // Impacting information
    if ((getDraftContext(context, user) && isDraftSupportedEntity(initial))) {
      const lastElementVersion = await internalLoadById(context, user, initial.internal_id);
      if (updatedInputs.length > 0) {
        const updateAsInstance = partialInstanceWithInputs(updatedInstance, impactedInputs) as BasicStoreBase;
        updateAsInstance._index = lastElementVersion._index;
        updateAsInstance._id = lastElementVersion._id;
        updateAsInstance.draft_change = getDraftChanges(lastElementVersion, updatedInputs);
        await elUpdateElement(context, user, updateAsInstance);
      }
    } else if (impactedInputs.length > 0) {
      const updateAsInstance = partialInstanceWithInputs(updatedInstance, impactedInputs) as BasicStoreBase;
      await elUpdateElement(context, user, updateAsInstance);
    }
    if (relationsToDelete.length > 0) {
      await elDeleteElements(context, user, relationsToDelete);
      // in case of deletion in a container objects, we chose not to UNSHARE the elements that were in the container
    }
    if (relationsToCreate.length > 0) {
      await elIndexElements(context, user, initial.entity_type, relationsToCreate);
      // in case of addition in a container objects, we need to propagate the sharing to these new objects
      const objectsRefRelationships = relationsToCreate.filter((r) => r.relationship_type === RELATION_OBJECT);
      if (objectsRefRelationships.length > 0) {
        await createContainerSharingTask(context, ACTION_TYPE_SHARE, initial, objectsRefRelationships);
      }
    }
    // Post-operation to update the individual linked to a user
    if (updatedInstance.entity_type === ENTITY_TYPE_USER && !getDraftContext(context, user)) {
      const args = {
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['contact_information'], values: [updatedInstance.user_email] }],
          filterGroups: [],
        },
        noFiltersChecking: true,
      };
      const individuals = await topEntitiesList(context, user, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], args);
      if (individuals.length > 0) {
        const individualId = individuals[0].id;
        const patch = {
          contact_information: updatedInstance.user_email,
          name: updatedInstance.name,
          x_opencti_firstname: updatedInstance.firstname,
          x_opencti_lastname: updatedInstance.lastname,
        };
        await patchAttribute(context, user, individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL, patch, { bypassIndividualUpdate: true });
      }
    }
    // Only push event in stream if modifications really happens
    if (updatedInputs.length > 0) {
      const message = await generateUpdateMessage(context, user, updatedInstance.entity_type, updatedInputs);
      const changes = await buildChanges(context, user, updatedInstance.entity_type, updatedInputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage ?? '',
        external_references: references.map((ref) => convertExternalReferenceToStix(ref as StoreEntity)),
      } : undefined;
      const relatedRestrictions = extractObjectsRestrictionsFromInputs(updatedInputs, initial.entity_type);
      const { pir_ids } = extractObjectsPirsFromInputs(updatedInputs, initial.entity_type);
      const event = await storeUpdateEvent(
        context,
        user,
        initial as StoreObject,
        updatedInstance as StoreObject,
        message,
        changes,
        {
          ...opts,
          commit: commit as unknown as any,
          related_restrictions: relatedRestrictions,
          pir_ids,
        },
      );
      // region Security coverage hook
      // TODO Implements a more generic approach to notify enrichment
      // If entity is currently covered
      const isRefUpdate = relationsToCreate.length > 0 || relationsToDelete.length > 0;
      if (isRefUpdate && data.updatedInstance[RELATION_COVERED]) {
        const { element: securityCoverage } = await updateAttribute(
          context,
          user,
          data.updatedInstance[RELATION_COVERED],
          ENTITY_TYPE_SECURITY_COVERAGE,
          [{ key: 'modified', value: [now()] }],
          { noEnrich: true },
        );
        await triggerEntityUpdateAutoEnrichment(context, user, securityCoverage as BasicStoreBase);
      }
      // endregion
      return { element: updatedInstance as T, event, isCreation: false };
    }
    // Return updated element after waiting for it.
    return { element: updatedInstance as T, event: null, isCreation: false };
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const updateAttributeFromLoadedWithRefs = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  initial: T | undefined | null,
  inputs: EditInput[],
  opts: UpdateAttributeMetaResolvedOpts = {},
) => {
  if (!initial) {
    throw FunctionalError('Cant update undefined element');
  }
  // region confidence control
  const checkConfidence = (Array.isArray(inputs) ? inputs : [inputs]).some(({ key, operation }) => {
    if (operation !== 'add') return true;
    return shouldCheckConfidenceOnRefRelationship(key);
  });
  if (checkConfidence && !opts.bypassIndividualUpdate) {
    controlUserConfidenceAgainstElement(user, initial);
  }
  const newInputs = adaptUpdateInputsConfidence(user, inputs, initial);
  // endregion
  const metaKeys = [...schemaRelationsRefDefinition.getStixNames(initial.entity_type), ...schemaRelationsRefDefinition.getInputNames(initial.entity_type)];
  const meta = newInputs.filter((e) => metaKeys.includes(e.key as string));
  const metaIds = R.uniq(meta.map((i) => i.value ?? []).flat());
  const metaDependencies = await elFindByIds(context, user, metaIds, { toMap: true, mapWithAllIds: true }) as Record<string, BasicStoreBase>;
  const revolvedInputs = newInputs.map((input) => {
    if (metaKeys.includes(input.key as string)) {
      const resolvedValues = (input.value ?? []).map((refId) => metaDependencies[refId]).filter((o) => isNotEmptyField(o));
      return { ...input, value: resolvedValues };
    }
    return input;
  });
  return updateAttributeMetaResolved<T>(context, user, initial, revolvedInputs as EditInput[], opts);
};

const generateEnrichmentLoaders = (context: AuthContext, user: AuthUser, element: BasicStoreBase) => {
  return {
    loadById: () => stixLoadByIdStringify(context, user, element.internal_id),
    bundleById: () => stixBundleByIdStringify(context, user, element.entity_type, element.internal_id),
  };
};
const triggerCreateEntityAutoEnrichment = async (context: AuthContext, user: AuthUser, element: BasicStoreBase) => {
  const loaders = generateEnrichmentLoaders(context, user, element);
  await createEntityAutoEnrichment(context, user, element, element.entity_type, loaders);
};
const triggerEntityUpdateAutoEnrichment = async (context: AuthContext, user: AuthUser, element: BasicStoreBase) => {
  // If element really updated, try to enrich if needed
  const loaders = generateEnrichmentLoaders(context, user, element);
  await updateEntityAutoEnrichment(context, user, element, element.entity_type, loaders);
};
type UpdateAttributeOpts = LoadByIdsWithDependeciesOpts & UpdateAttributeMetaResolvedOpts;
export const updateAttribute = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  type: string,
  inputs: EditInput[],
  opts: { noEnrich?: boolean } & UpdateAttributeOpts = {},
) => {
  const initial = await storeLoadByIdWithRefs<T>(context, user, id, { ...opts, type });
  if (!initial) {
    throw FunctionalError('Cant find element to update', { id, type });
  }
  // Validate input attributes
  const entitySetting = await getEntitySettingFromCache(context, initial.entity_type);
  await validateInputUpdate(context, user, initial.entity_type, initial as Record<string, any>, inputs, entitySetting as BasicStoreEntityEntitySetting);
  // Continue update
  const data = await updateAttributeFromLoadedWithRefs<T>(context, user, initial, inputs, opts);
  if (!opts.noEnrich && data.event) {
    // If element really updated, try to enrich if needed
    await triggerEntityUpdateAutoEnrichment(context, user, data.element as BasicStoreBase);
  }
  return data;
};
type PatchAttributeOpts = UpdateAttributeOpts & {
  operations?: Record<string, undefined | 'add' | 'remove' | 'replace'>;
};
export const patchAttribute = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  type: string,
  patch: Record<string, any>,
  opts: PatchAttributeOpts = {},
) => {
  const inputs = transformPatchToInput(patch, opts.operations);
  return updateAttribute<T>(context, user, id, type, inputs, opts);
};

export const patchAttributeFromLoadedWithRefs = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  initial: T | undefined | null,
  patch: Record<string, any>,
  opts: PatchAttributeOpts = {},
) => {
  const inputs = transformPatchToInput(patch, opts.operations);
  return updateAttributeFromLoadedWithRefs<T>(context, user, initial, inputs, opts);
};
// endregion

// region rules
const getAllRulesField = (instance: Record<string, any>, field: string) => {
  return Object.keys(instance)
    .filter((key) => key.startsWith(RULE_PREFIX))
    .map((key) => instance[key])
    .filter((rule) => isNotEmptyField(rule)) // Rule can have been already reset
    .flat()
    .map((rule) => rule.data?.[field])
    .flat()
    .filter((val) => isNotEmptyField(val));
};
const convertRulesTimeValues = (timeValues: Date[]) => timeValues.map((d) => moment(d));
const createRuleDataPatch = (instance: Record<string, any>) => {
  // 01 - Compute the attributes
  const weight = Object.keys(instance)
    .filter((key) => key.startsWith(RULE_PREFIX))
    .map((key) => instance[key])
    .flat().length;
  const patch: any = {};
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
          // TODO R.min might be broken here? R.min(values) is returning a function instead of a value
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
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
          // TODO R.min might be broken here? R.max(values) is returning a function instead of a value
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
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

const getRuleExplanationsSize = (fromRule: string, instance: Record<string, any>) => {
  return (instance[fromRule] ?? []).flat().length;
};

const createUpsertRulePatch = async (
  instance: Record<string, any>,
  input: Record<string, any>,
  opts: { fromRule: string; fromRuleDeletion?: boolean },
) => {
  const { fromRule, fromRuleDeletion = false } = opts;
  const updatedRule = fromRuleDeletion ? input[fromRule] : (input[fromRule] ?? []).slice(-MAX_EXPLANATIONS_PER_RULE);
  const rulePatch = { [fromRule]: updatedRule };
  const ruleInstance = R.mergeRight(instance, rulePatch);
  // 02 - Create the patch
  const innerPatch = createRuleDataPatch(ruleInstance);
  return { ...rulePatch, ...innerPatch };
};
type UpsertEntityRuleOpts = PatchAttributeOpts & {
  fromRule: string;
  fromRuleDeletion?: boolean;
};
const upsertEntityRule = async (
  context: AuthContext,
  user: AuthUser,
  instance: Record<string, any>,
  input: Record<string, any>,
  opts: UpsertEntityRuleOpts,
) => {
  const { fromRule } = opts;
  // 01. If relation already have max explanation, don't do anything
  // Strict equals to clean existing element with too many explanations
  const ruleExplanationsSize = getRuleExplanationsSize(fromRule, instance);
  if (ruleExplanationsSize === MAX_EXPLANATIONS_PER_RULE) {
    return instance;
  }
  logApp.debug('Upsert inferred entity', { input });
  const patch = await createUpsertRulePatch(instance, input, opts);
  const element = await storeLoadByIdWithRefs(context, user, instance.internal_id, { type: instance.entity_type });
  return await patchAttributeFromLoadedWithRefs(context, RULE_MANAGER_USER, element, patch, opts);
};
const upsertRelationRule = async (
  context: AuthContext,
  user: AuthUser,
  instance: Record<string, any>,
  input: Record<string, any>,
  opts: { fromRule: string; fromRuleDeletion?: boolean } & PatchAttributeOpts,
) => {
  const { fromRule, fromRuleDeletion = false } = opts;
  // 01. If relation already have max explanation, don't do anything
  // Strict equals to clean existing element with too many explanations
  const ruleExplanationsSize = getRuleExplanationsSize(fromRule, instance);
  if (!fromRuleDeletion && ruleExplanationsSize === MAX_EXPLANATIONS_PER_RULE) {
    return instance;
  }
  logApp.debug('Upsert inferred relation', { input });
  // 02 - Update the rule
  const updatedRule = input[fromRule];
  if (!fromRuleDeletion) {
    const keepRuleHashes = input[fromRule].map((i: any) => i.hash);
    const instanceRuleToKeep = (instance[fromRule] ?? []).filter((i: any) => !keepRuleHashes.includes(i.hash));
    updatedRule.push(...instanceRuleToKeep);
  }
  // 03 - Create the patch
  const patch = await createUpsertRulePatch(instance, input, opts);
  const element = await storeLoadByIdWithRefs(context, user, instance.internal_id, { type: instance.entity_type });
  return await patchAttributeFromLoadedWithRefs(context, RULE_MANAGER_USER, element, patch, opts);
};
// endregion

const validateEntityAndRelationCreation = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  type: string,
  entitySetting: BasicStoreEntityEntitySetting,
  opts: { bypassValidation?: boolean } = {},
) => {
  if (opts.bypassValidation !== true) { // Allow creation directly from the back-end
    const isAllowedToByPass = isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE);
    if (!isAllowedToByPass && entitySetting?.enforce_reference) {
      if (isEmptyField(input.externalReferences)) {
        throw ValidationError('You must provide at least one external reference for this type of entity/relationship', 'externalReferences');
      }
    }
    await validateInputCreation(context, user, type, input, entitySetting);
  }
};

const buildRelationDeduplicationFilters = (input: Record<string, any>) => {
  const filters = [];
  const { from, relationship_type: relationshipType, createdBy } = input;
  const deduplicationConfig = conf.get('relations_deduplication') ?? {
    past_days: 30,
    next_days: 30,
    created_by_based: false,
    types_overrides: {},
  };
  const config = deduplicationConfig.types_overrides?.[relationshipType] ?? deduplicationConfig;
  if (config.created_by_based && createdBy) {
    // args.relationFilter = { relation: RELATION_CREATED_BY, id: createdBy.id };
    filters.push({ key: [buildRefRelationKey(RELATION_CREATED_BY)], values: [createdBy.id] });
  }
  const prepareBeginning = (key: string) => prepareDate(moment(input[key]).subtract(config.past_days, 'days').utc());
  const prepareStopping = (key: string) => prepareDate(moment(input[key]).add(config.next_days, 'days').utc());
  // Prepare for stix core
  if (isStixCoreRelationship(relationshipType)) {
    if (!R.isNil(input.start_time)) {
      // args.startTimeStart = prepareBeginning('start_time');
      filters.push({ key: ['start_time'], values: [prepareBeginning('start_time')], operator: FilterOperator.Gt });
      // args.startTimeStop = prepareStopping('start_time');
      filters.push({ key: ['start_time'], values: [prepareStopping('start_time')], operator: FilterOperator.Lt });
    }
    if (!R.isNil(input.stop_time)) {
      // args.stopTimeStart = prepareBeginning('stop_time');
      filters.push({ key: ['stop_time'], values: [prepareBeginning('stop_time')], operator: FilterOperator.Gt });
      // args.stopTimeStop = prepareStopping('stop_time');
      filters.push({ key: ['stop_time'], values: [prepareStopping('stop_time')], operator: FilterOperator.Lt });
    }
  }
  // Prepare for stix ref
  if (isStixRefRelationship(relationshipType) && schemaRelationsRefDefinition.isDatable(from.entity_type, relationshipType)) {
    if (!R.isNil(input.start_time)) {
      // args.startTimeStart = prepareBeginning('start_time');
      filters.push({ key: ['start_time'], values: [prepareBeginning('start_time')], operator: FilterOperator.Gt });
      // args.startTimeStop = prepareStopping('start_time');
      filters.push({ key: ['start_time'], values: [prepareStopping('start_time')], operator: FilterOperator.Lt });
    }
    if (!R.isNil(input.stop_time)) {
      // args.stopTimeStart = prepareBeginning('stop_time');
      filters.push({ key: ['stop_time'], values: [prepareBeginning('stop_time')], operator: FilterOperator.Gt });
      // args.stopTimeStop = prepareStopping('stop_time');
      filters.push({ key: ['stop_time'], values: [prepareStopping('stop_time')], operator: FilterOperator.Lt });
    }
  }
  // Prepare for stix sighting
  if (isStixSightingRelationship(relationshipType)) {
    if (!R.isNil(input.first_seen)) {
      // args.firstSeenStart = prepareBeginning('first_seen');
      filters.push({ key: ['first_seen'], values: [prepareBeginning('first_seen')], operator: FilterOperator.Gt });
      // args.firstSeenStop = prepareStopping('first_seen');
      filters.push({ key: ['first_seen'], values: [prepareStopping('first_seen')], operator: FilterOperator.Lt });
    }
    if (!R.isNil(input.last_seen)) {
      // args.lastSeenStart = prepareBeginning('last_seen');
      filters.push({ key: ['last_seen'], values: [prepareBeginning('last_seen')], operator: FilterOperator.Gt });
      // args.lastSeenStop = prepareStopping('last_seen');
      filters.push({ key: ['last_seen'], values: [prepareStopping('last_seen')], operator: FilterOperator.Lt });
    }
  }
  return filters;
};

const upsertElement = async (
  context: AuthContext,
  user: AuthUser,
  element: BasicStoreBase,
  type: string,
  basePatch: Record<string, any>,
  opts: { elementAlreadyResolved?: boolean } & UpdateAttributeMetaResolvedOpts = {},
) => {
  // -- Independent update
  let resolvedElement = element as StoreObject;
  if (!opts.elementAlreadyResolved) {
    const finalResolvedElement = await storeLoadByIdWithRefs(context, user, element?.internal_id, { type });
    if (!finalResolvedElement) {
      throw FunctionalError('Cant find element to resolve', { id: element?.internal_id });
    }
    resolvedElement = finalResolvedElement;
  }

  // If a decay exclusion rule is already applied, we must not apply a new decay rule or a new decay exclusion rule
  if ((resolvedElement as Record<string, any>).decay_exclusion_applied_rule) {
    if (basePatch.decay_applied_rule) {
      delete basePatch.decay_next_reaction_date;
      delete basePatch.decay_base_score;
      delete basePatch.decay_base_score_date;
      delete basePatch.decay_applied_rule;
      delete basePatch.decay_history;
    }
    if (basePatch.decay_exclusion_applied_rule) {
      delete basePatch.decay_exclusion_applied_rule;
    }
  }

  const confidenceForUpsert = controlUpsertInputWithUserConfidence(user, basePatch as ObjectWithConfidence, resolvedElement);

  const updatePatch = buildUpdatePatchForUpsert(user, resolvedElement, type, basePatch, confidenceForUpsert);

  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const validEnterpriseEdition = settings.valid_enterprise_edition;
  // All inputs impacted by modifications (+inner)
  const inputs = await generateInputsForUpsert(context, user, resolvedElement, type, updatePatch, confidenceForUpsert, validEnterpriseEdition);

  // -- If modifications need to be done, add updated_at and modified
  if (inputs.length > 0) {
    // Update the attribute and return the result
    const updateOpts = { ...opts, upsert: context.synchronizedUpsert !== true };
    return await updateAttributeMetaResolved(context, user, resolvedElement, inputs as any[], updateOpts);
  }
  // -- No modification applied
  return { element: resolvedElement, event: null, isCreation: false };
};

export const getExistingRelations = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  opts: { fromRule?: string } = {},
) => {
  const { from, to, relationship_type: relationshipType } = input;
  const { fromRule } = opts;
  const existingRelationships = [];
  if (fromRule) {
    // In case inferred rule, try to find the relation with basic filters
    // Only in inferred indices.
    const fromRuleArgs = {
      fromId: from.internal_id,
      toId: to.internal_id,
      indices: [READ_INDEX_INFERRED_RELATIONSHIPS],
    };
    const inferredRelationships = await topRelationsList(context, SYSTEM_USER, relationshipType, fromRuleArgs);
    existingRelationships.push(...inferredRelationships);
  } else {
    // In case of direct relation, try to find the relation with time filters
    // Only in standard indices.
    const deduplicationFilters = buildRelationDeduplicationFilters(input);
    const searchFilters = {
      mode: FilterMode.Or,
      filters: [{ key: ['ids'], values: getInputIds(relationshipType, input, false) }],
      filterGroups: [{
        mode: FilterMode.And,
        filters: [
          {
            key: ['connections'],
            nested: [
              { key: 'internal_id', values: [from.internal_id] },
              { key: 'role', values: ['*_from'], operator: FilterOperator.Wildcard },
            ],
            values: [],
          },
          {
            key: ['connections'],
            nested: [
              { key: 'internal_id', values: [to.internal_id] },
              { key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard },
            ],
            values: [],
          },
          ...deduplicationFilters,
        ],
        filterGroups: [],
      }],
    };
    // inputIds
    const manualArgs = { indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, filters: searchFilters };
    const manualRelationships = await topRelationsList(context, SYSTEM_USER, relationshipType, manualArgs);
    existingRelationships.push(...manualRelationships);
  }
  return existingRelationships;
};
type CreateRelationRawOpts = UpdateEventOpts & {
  fromRule?: string;
  locks?: string[];
  bypassValidation?: boolean;
  references?: string[];
  commitMessage?: string;
  restore?: boolean;
};
export const createRelationRaw = async (
  context: AuthContext,
  user: AuthUser,
  rawInput: Record<string, any>,
  opts: CreateRelationRawOpts = {},
) => {
  let lock;
  const { fromRule, locks = [] } = opts;
  const { fromId, toId, relationship_type: relationshipType } = rawInput;

  // region confidence control
  const input = structuredClone(rawInput);
  const { confidenceLevelToApply } = controlCreateInputWithUserConfidence(user, input as ObjectWithConfidence, relationshipType);
  input.confidence = confidenceLevelToApply; // confidence of the new relation will be capped to user's confidence
  // endregion

  // Pre-check before inputs resolution
  if (fromId === toId) {
    /* v8 ignore next */
    const errorData = { from: input.fromId, relationshipType, doc_code: 'SELF_REFERENCING_RELATION' };
    throw UnsupportedError('Relation cant be created with the same source and target', errorData);
  }
  const entitySetting = await getEntitySettingFromCache(context, relationshipType) as BasicStoreEntityEntitySetting;

  // We need to check existing dependencies
  let resolvedInput = await inputResolveRefs(context, user, input, relationshipType, entitySetting);
  const { from, to } = resolvedInput;

  // when creating stix ref, we must check confidence on from side (this count has modifying this element itself)
  if (isStixRefRelationship(relationshipType) && shouldCheckConfidenceOnRefRelationship(relationshipType)) {
    controlUserConfidenceAgainstElement(user, from);
  }

  // check if user has "edit" access on from and to
  const draftId = getDraftContext(context, user);
  const draft = draftId ? await findDraftById(context, user, draftId) : null;
  const canEditFrom = validateUserAccessOperation(user, from, AccessOperation.EDIT, draft);
  const canEditTo = validateUserAccessOperation(user, to, AccessOperation.EDIT, draft);
  if (!canEditFrom || !canEditTo) {
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
    const errorData = { from: input.fromId, to: input.toId, relationshipType, doc_code: 'SELF_REFERENCING_RELATION' };
    throw UnsupportedError('Relation cant be created with the same source and target', errorData);
  }
  // It's not possible to create a single ref relationship if one already exists
  if (isSingleRelationsRef(resolvedInput.from.entity_type, relationshipType)) {
    const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(resolvedInput.from.entity_type, relationshipType);
    if (key && isNotEmptyField(resolvedInput.from[key])) {
      const errorData = { from: input.fromId, to: input.toId, relationshipType };
      throw UnsupportedError('Cant add another relation on single ref', errorData);
    }
  }

  // Build lock ids
  const inputIds = getInputIds(relationshipType, resolvedInput, fromRule);
  if (isImpactedTypeAndSide(relationshipType, from.entity_type, to.entity_type, ROLE_FROM)) inputIds.push(from.internal_id);
  if (isImpactedTypeAndSide(relationshipType, from.entity_type, to.entity_type, ROLE_TO)) inputIds.push(to.internal_id);
  const participantIds = inputIds.filter((e) => !locks.includes(e));
  try {
    // Try to get the lock in redis
    lock = await lockResources(participantIds, { draftId: getDraftContext(context, user) });
    // region check existing relationship
    const existingRelationships = await getExistingRelations(context, user, resolvedInput, opts);
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
          type: relationshipType,
          fromId: from.internal_id,
        });
      }
      // TODO Handling merging relation when updating to prevent multiple relations finding
      // resolve all refs so we can upsert properly
      existingRelationship = await storeLoadByIdWithRefs(context, user, filteredRelations[0].internal_id);
    }
    if (!existingRelationship) {
      // We do not use default values on upsert.
      resolvedInput = fillDefaultValues(user, resolvedInput, entitySetting);
      resolvedInput = await inputResolveRefs(context, user, resolvedInput, relationshipType, entitySetting);
    }
    await validateEntityAndRelationCreation(context, user, resolvedInput, relationshipType, entitySetting, opts);

    // endregion
    if (existingRelationship) {
      // If upsert come from a rule, do a specific upsert.
      if (fromRule) {
        return await upsertRelationRule(context, user, existingRelationship, input, { ...opts, fromRule, locks: participantIds });
      }
      // If not upsert the element
      return upsertElement(context, user, existingRelationship, relationshipType, resolvedInput, { ...opts, locks: participantIds, elementAlreadyResolved: true });
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
      let referencesPromises;
      if (opts.references) {
        referencesPromises = internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) as Promise<BasicStoreBase[]>;
      }
      const references = referencesPromises ? await BluePromise.all(referencesPromises) : [];
      if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
        throw FunctionalError('Cant find element references for commit', {
          id: input.fromId,
          references: opts.references,
        });
      }
      const previous = resolvedInput.from; // Complete resolution done by the input resolver
      const targetElement = { ...resolvedInput.to, i_relation: resolvedInput };
      const instance = { ...previous };
      const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(instance.entity_type, relationshipType);
      let inputs: EditInput[] = [];
      if (key) {
        if (isSingleRelationsRef(instance.entity_type, relationshipType)) {
          inputs = [{ key, value: [targetElement] }];
          // Generate the new version of the from
          instance[key] = targetElement;
        } else {
          inputs = [{ key, value: [targetElement], operation: EditOperation.Add }];
          // Generate the new version of the from
          instance[key] = [...(instance[key] ?? []), targetElement];
        }
      }
      const message = await generateUpdateMessage(context, user, instance.entity_type, inputs);
      const changes = await buildChanges(context, user, instance.entity_type, inputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage ?? '',
        external_references: references.map((ref) => convertExternalReferenceToStix(ref as StoreEntity)),
      } : undefined;
      const storeUpdateEventsOpts = { ...opts, commit: commit as unknown as any };
      event = await storeUpdateEvent(context, user, previous, instance, message, changes, storeUpdateEventsOpts);
      dataRel.element.from = instance; // dynamically update the from to have an up to date relation
    } else {
      const createdRelation = { ...resolvedInput, ...dataRel.element };
      event = await storeCreateRelationEvent(context, user, createdRelation, opts);
    }
    // - TRANSACTION END
    // region Security coverage hook
    // TODO Implements a more generic approach to notify enrichment
    // If relation is created from/to an element currently covered
    // (from) Element[covered] <- use -> Attack pattern (to)
    // (from) Element[covered] <- targets -> Vulnerability (to)
    if (dataRel.element.from[RELATION_COVERED]) {
      const isVuln = relationshipType === RELATION_TARGETS && dataRel.element.to.entity_type === ENTITY_TYPE_VULNERABILITY;
      const isAttackPattern = relationshipType === RELATION_USES && dataRel.element.to.entity_type === ENTITY_TYPE_ATTACK_PATTERN;
      if (isVuln || isAttackPattern) {
        const { element: securityCoverage } = await updateAttribute(
          context,
          user,
          dataRel.element.from[RELATION_COVERED],
          ENTITY_TYPE_SECURITY_COVERAGE,
          [{ key: 'modified', value: [now()] }],
          { noEnrich: true },
        );
        await triggerEntityUpdateAutoEnrichment(context, user, securityCoverage as BasicStoreBase);
      }
    }
    // endregion
    return { element: { ...resolvedInput, ...dataRel.element }, event, isCreation: true };
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};
export const createRelation = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  opts: CreateRelationRawOpts = {},
) => {
  const data = await createRelationRaw(context, user, input, opts);
  return data.element;
};
type RuleContent = {
  field: string;
  content: {
    explanation: string[];
    dependencies: string[];
    data: any;
    hash: string;
  };
};
export const createInferredRelation = async (
  context: AuthContext,
  input: Record<string, any>,
  ruleContent: RuleContent,
  opts: CreateRelationRawOpts = {},
) => {
  const args = {
    ...opts,
    fromRule: ruleContent.field,
    bypassValidation: true, // We need to bypass validation here has we maybe not setup all require fields
  };

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
    [ruleContent.field]: [ruleContent.content],
  };
  const patch = createRuleDataPatch(instance);
  const inputRelation = { ...instance, ...patch };
  logApp.info('Create inferred relation', inputRelation);
  return createRelationRaw(context, RULE_MANAGER_USER, inputRelation, args);
};
/* v8 ignore next */
export const createRelations = async (
  context: AuthContext,
  user: AuthUser,
  inputs: Record<string, any>[],
  opts: CreateRelationRawOpts = {},
) => {
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

export const getExistingEntities = async (
  context: AuthContext,
  user: AuthUser,
  input: any,
  type: string,
) => {
  const participantIds = getInputIds(type, input);
  const existingByIdsPromise = internalFindByIds(context, SYSTEM_USER, participantIds, { type }) as Promise<BasicStoreBase[]>;
  let existingByHashedPromise;
  if (isStixCyberObservableHashedObservable(type)) {
    existingByHashedPromise = listEntitiesByHashes(context, user, type, input.hashes);
  }
  const [existingByIds, existingByHashed] = await BluePromise.all([existingByIdsPromise, existingByHashedPromise]);
  const existingEntities: any[] = [];
  existingEntities.push(...R.uniqBy((e) => e.internal_id, [...existingByIds, ...(existingByHashed ?? [])]));
  return existingEntities;
};
type CreateEntityRawOpts = PatchAttributeOpts & CreateEventOpts & {
  fromRule?: string;
  fromRuleDeletion?: boolean;
  bypassValidation?: boolean;
};
const createEntityRaw = async (
  context: AuthContext,
  user: AuthUser,
  rawInput: Record<string, any>,
  type: string,
  opts: CreateEntityRawOpts = {},
) => {
  // region confidence control
  const input = { ...rawInput };
  const { confidenceLevelToApply } = controlCreateInputWithUserConfidence(user, input as ObjectWithConfidence, type);
  input.confidence = confidenceLevelToApply; // confidence of new entity will be capped to user's confidence
  // authorized_members renaming
  if (input.authorized_members?.length > 0) {
    input.restricted_members = input.authorized_members;
  }
  delete input.authorized_members; // always remove authorized_members input, even if empty
  // endregion

  // validate user access to create the entity in draft
  const draftId = getDraftContext(context, user);
  const draft = draftId ? await findDraftById(context, user, draftId) : null;
  if (!validateUserAccessOperation(user, input, AccessOperation.EDIT, draft)) {
    throw ForbiddenAccess();
  }
  // validate authorized members access (when creating a new entity with authorized members)
  if (input.restricted_members?.length > 0) {
    if (!validateUserAccessOperation(user, input, AccessOperation.MANAGE_ACCESS, draft)) {
      throw ForbiddenAccess();
    }
    if (schemaAttributesDefinition.getAttribute(type, authorizedMembersActivationDate.name)) {
      input.authorized_members_activation_date = now();
    }
  }
  // region - Pre-Check
  const entitySetting = await getEntitySettingFromCache(context, type) as BasicStoreEntityEntitySetting;
  const { fromRule } = opts;
  // We need to check existing dependencies
  let resolvedInput = await inputResolveRefs(context, user, input, type, entitySetting);
  // Generate all the possibles ids
  // For marking def, we need to force the standard_id
  const participantIds = getInputIds(type, resolvedInput, fromRule);
  // Create the element
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResources(participantIds, { draftId: getDraftContext(context, user) });
    // Generate the internal id if needed
    const standardId = resolvedInput.standard_id || generateStandardId(type, resolvedInput);
    // Check if the entity exists, must be done with SYSTEM USER to really find it.
    const existingEntities = [];
    const finderIds = [...participantIds, ...(context.previousStandard ? [context.previousStandard] : [])];
    const existingByIdsPromise = internalFindByIds(context, SYSTEM_USER, finderIds, { type }) as Promise<BasicStoreObject[]>;
    // Hash are per definition keys.
    // When creating a hash, we can check all hashes to update or merge the result
    // Generating multiple standard ids could be a solution but to complex to implements
    // For now, we will look for any observables that have any hashes of this input.
    let existingByHashedPromise;
    if (isStixCyberObservableHashedObservable(type)) {
      existingByHashedPromise = listEntitiesByHashes(context, user, type, input.hashes);
      resolvedInput.update = true;
      if (resolvedInput.hashes) {
        const otherStandardIds = generateHashedObservableStandardIds({
          entity_type: type,
          ...resolvedInput,
        }).filter((id) => id !== standardId);
        resolvedInput.x_opencti_stix_ids = R.uniq([
          ...(resolvedInput.x_opencti_stix_ids ?? []),
          ...otherStandardIds,
        ]);
      }
    }
    // Resolve the existing entity
    const [existingByIds, existingByHashed] = await BluePromise.all([existingByIdsPromise, existingByHashedPromise]);
    existingEntities.push(...R.uniqBy((e) => e.internal_id, [...existingByIds, ...(existingByHashed ?? [])]));
    // region - Pre-Check
    if (existingEntities.length === 0) { // We do not use default values on upsert.
      resolvedInput = fillDefaultValues(user, resolvedInput, entitySetting);
      resolvedInput = await inputResolveRefs(context, user, resolvedInput, type, entitySetting);
    }
    await validateEntityAndRelationCreation(context, user, resolvedInput, type, entitySetting, opts);
    // endregion
    // If existing entities have been found and type is a STIX Core Object
    let dataMessage;
    if (existingEntities.length > 0) {
      // We need to filter what we found with the user rights
      const filteredEntities = await userFilterStoreElements(context, user, existingEntities) as BasicStoreEntity[];
      const entityIds = R.map((i) => i.standard_id, filteredEntities);
      // If nothing accessible for this user, throw ForbiddenAccess
      if (filteredEntities.length === 0) {
        const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
        const rfiSetting = await getEntitySettingFromCache(context, ENTITY_TYPE_CONTAINER_CASE_RFI) as BasicStoreEntityEntitySetting;
        const isRequestAccessConfigured = isRequestAccessEnabled(settings, rfiSetting);
        if (isRequestAccessConfigured === true && !getDraftContext(context, user)) {
          const entitiesThatRequiresAccess = await canRequestAccess(context, user, existingEntities);
          if (entitiesThatRequiresAccess.length > 0) {
            throw AccessRequiredError('Restricted entity already exists, you can request access', { entityIds: entitiesThatRequiresAccess.map((value) => value.internal_id) });
          }
          throw UnsupportedError('Restricted entity already exists', { doc_code: 'RESTRICTED_ELEMENT' });
        } else {
          throw UnsupportedError('Restricted entity already exists', { doc_code: 'RESTRICTED_ELEMENT' });
        }
      }
      // If inferred entity
      if (fromRule) {
        // Entity reference must be uniq to be upserted
        if (filteredEntities.length > 1) {
          throw UnsupportedError('Cant upsert inferred entity. Too many entities resolved', { input, entityIds, doc_code: 'MULTIPLE_REFERENCES_FOUND' });
        }
        // If upsert come from a rule, do a specific upsert.
        return await upsertEntityRule(context, user, filteredEntities[0], input, { ...opts, fromRule, locks: participantIds });
      }
      if (filteredEntities.length === 1) {
        const upsertEntityOpts = { ...opts, locks: participantIds, bypassIndividualUpdate: true, elementAlreadyResolved: true };
        const element = await storeLoadByIdWithRefs(context, user, filteredEntities[0].internal_id, { type });
        if (!element) {
          throw FunctionalError('Cant find element to resolve', { id: filteredEntities[0].internal_id });
        }
        return upsertElement(context, user, element, type, resolvedInput, upsertEntityOpts);
      }
      // If creation is not by a reference
      // We can in best effort try to merge a common stix_id
      const existingByStandard = R.find((e) => e.standard_id === standardId, filteredEntities);
      if (existingByStandard && !isStixCyberObservableHashedObservable(type)) {
        // Sometimes multiple entities can match
        // Looking for aliasA, aliasB, find in different entities for example
        // In this case, we try to find if one match the standard id
        // If a STIX ID has been passed in the creation
        if (resolvedInput.stix_id) {
          // Find the entity corresponding to this STIX ID
          const stixIdFinder = (e: BasicStoreBase) => e.standard_id === resolvedInput.stix_id || (e.x_opencti_stix_ids ?? []).includes(resolvedInput.stix_id);
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
        const concurrentEntities = R.filter((e) => e.standard_id !== standardId, filteredEntities) as Record<string, any>[];
        // We can upsert element except the aliases that are part of other entities
        const key = resolveAliasesField(type).name;
        const concurrentAliases = R.flatten(R.map((c) => [c[key], c.name], concurrentEntities));
        const normedAliases = R.uniq(concurrentAliases.map((c) => normalizeName(c)));
        const filteredAliases = R.filter((i) => !normedAliases.includes(normalizeName(i)), resolvedInput[key] || []);
        // We need also to filter eventual STIX IDs present in other entities
        const concurrentStixIds = R.flatten(R.map((c) => [c.x_opencti_stix_ids, c.standard_id], concurrentEntities));
        const normedStixIds = R.uniq(concurrentStixIds);
        const filteredStixIds = R.filter(
          (i) => isNotEmptyField(i) && !normedStixIds.includes(i) && i !== existingByStandard.standard_id,
          [...(resolvedInput.x_opencti_stix_ids ?? []), resolvedInput.stix_id],
        );
        const finalEntity = { ...resolvedInput, [key]: filteredAliases, x_opencti_stix_ids: filteredStixIds };
        return upsertElement(context, user, existingByStandard, type, finalEntity, { ...opts, locks: participantIds });
      }
      if (resolvedInput.update === true) {
        // The new one is new reference, merge all found entities
        // Target entity is existingByStandard by default or any other
        const target = R.find((e) => e.standard_id === standardId, filteredEntities) || filteredEntities[0];
        const sources = R.filter((e) => e.internal_id !== target.internal_id, filteredEntities);
        hashMergeValidation([target, ...sources]);
        await mergeEntities(context, user, target.internal_id, sources.map((s) => s.internal_id), { locks: participantIds });
        return upsertElement(context, user, target, type, resolvedInput, { ...opts, locks: participantIds });
      }
      if (resolvedInput.stix_id && !existingEntities.map((n) => getInstanceIds(n)).flat().includes(resolvedInput.stix_id)) {
        // Upsert others
        const target = filteredEntities[0];
        const resolvedStixIds = { ...target, x_opencti_stix_ids: [...(target.x_opencti_stix_ids ?? []), resolvedInput.stix_id] };
        return upsertElement(context, user, target, type, resolvedStixIds, { ...opts, locks: participantIds });
      }
      // Return the matching STIX IDs in others
      return { element: R.head(filteredEntities.filter((n) => getInstanceIds(n).includes(resolvedInput.stix_id))), event: null, isCreation: false };
    }
    // Create the object
    const dataEntity = await buildEntityData(context, user, resolvedInput, type, opts) as { element: Record<string, any>; relations: Record<string, any>[] };
    // If file directly attached
    if (!isEmptyField(resolvedInput.file)) {
      const { filename } = await resolvedInput.file;
      const isAutoExternal = entitySetting?.platform_entity_files_ref;
      const path = `import/${type}/${dataEntity.element[ID_INTERNAL]}`;
      const key = `${path}/${filename}`;
      const meta = isAutoExternal ? { external_reference_id: generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { url: `/storage/get/${key}` }) } : {};
      const file_markings = resolvedInput.objectMarking?.map(({ id }: { id: string }) => id);
      const { upload: file } = await uploadToStorage(context, user, path, input.file, { entity: dataEntity.element as BasicStoreBase, file_markings, meta });
      dataEntity.element = { ...dataEntity.element, x_opencti_files: [storeFileConverter(user, file)] };
      // Add external references from files if necessary
      if (isAutoExternal) {
        // Create external ref + link to current entity
        const createExternal = { source_name: file.name, url: `/storage/get/${file.id}`, fileId: file.id };
        const externalRef = await createEntity(context, user, createExternal, ENTITY_TYPE_EXTERNAL_REFERENCE);
        const newRefRel = buildInnerRelation(dataEntity.element, externalRef, RELATION_EXTERNAL_REFERENCE);
        dataEntity.relations.push(...newRefRel);
      }
    }
    if (opts.restore === true) {
      dataMessage = generateRestoreMessage(dataEntity.element);
    } else {
      dataMessage = generateCreateMessage(dataEntity.element);
    }

    // Index the created element
    lock.signal.throwIfAborted();
    await indexCreatedElement(context, user, dataEntity);
    // Push the input in the stream
    const createdElement = { ...resolvedInput, ...dataEntity.element };
    // In case we have created relation (like Marking for example) the input name is not the database name and the resolution might fail
    const inputFields = schemaRelationsRefDefinition.getRelationsRef(createdElement.entity_type);
    inputFields.forEach(({ name, databaseName }) => {
      createdElement[databaseName] = Array.isArray(createdElement[name]) ? createdElement[name].map(({ id }) => id) : createdElement[name];
    });

    const event = await storeCreateEntityEvent(context, user, createdElement as StoreObject, dataMessage, opts);
    // Return created element after waiting for it.
    return { element: createdElement, event, isCreation: true };
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const createEntity = async (
  context: AuthContext,
  user: AuthUser,
  input: Record<string, any>,
  type: string,
  opts: { complete?: boolean } & CreateEntityRawOpts = {},
) => {
  const isCompleteResult = opts.complete === true;
  // volumes of objects relationships must be controlled
  const data = await createEntityRaw(context, user, input, type, opts);
  // In case of creation, start an enrichment
  if (data.isCreation) {
    await triggerCreateEntityAutoEnrichment(context, user, data.element);
  } else if (data.event !== null) { // upsert
    await triggerEntityUpdateAutoEnrichment(context, user, data.element);
  }
  return isCompleteResult ? data : data.element;
};

export const createInferredEntity = async (
  context: AuthContext,
  input: Record<string, any>,
  ruleContent: RuleContent,
  type: string,
) => {
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

const draftInternalDeleteElement = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  draftElement: T,
) => {
  let lock;
  const participantIds = [draftElement.internal_id];
  try {
    // Try to get the lock in redis
    lock = await lockResources(participantIds, { draftId: getDraftContext(context, user) });

    await elMarkElementsAsDraftDelete(context, user, [draftElement]);
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }

  return { element: draftElement, event: {} };
};
type InternalDeleteElementByIdOpts = LoadByIdsWithDependeciesOpts & EventOpts & {
  references?: string[];
  commitMessage?: string;
  forceDelete?: boolean;
  forceRefresh?: boolean;
};
export const internalDeleteElementById = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  type: string,
  opts: InternalDeleteElementByIdOpts = {},
) => {
  let lock;
  let event;
  const element = await storeLoadByIdWithRefs<T>(context, user, id, { ...opts, type, includeDeletedInDraft: true });

  if (!element) {
    throw AlreadyDeletedError({ id });
  }

  const draftId = getDraftContext(context, user);
  const draft = draftId ? await findDraftById(context, user, draftId) : null;
  if (!validateUserAccessOperation(user, element, AccessOperation.DELETE, draft)) {
    throw ForbiddenAccess();
  }

  if (draftId) {
    return draftInternalDeleteElement<T>(context, user, element);
  }
  // region confidence control
  controlUserConfidenceAgainstElement(user, element);
  // region restrict delete control
  controlUserRestrictDeleteAgainstElement(user, element);
  // when deleting stix ref, we must check confidence on from side (this count has modifying this element itself)
  if (isStixRefRelationship(element.entity_type)) {
    const relationEelment = element as StoreRelation;
    controlUserConfidenceAgainstElement(user, relationEelment.from as ObjectWithConfidence);
  }
  // endregion
  // Prevent individual deletion if linked to a user
  if (element.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL) {
    const individualElement = element as BasicStoreEntity;
    await verifyCanDeleteIndividual(context, user, individualElement);
  }
  // Prevent organization deletion if platform orga or has members
  if (element.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
    const organizationElement = element as StoreEntityOrganization;
    await verifyCanDeleteOrganization(context, user, organizationElement);
  }
  // Check inference operation
  checkIfInferenceOperationIsValid(user, element);
  // Apply deletion
  const participantIds = [element.internal_id];
  try {
    // Try to get the lock in redis
    lock = await lockResources(participantIds);
    if (isStixRefRelationship(element.entity_type)) {
      const relationElement = element as StoreRelation;
      let referencesPromises;
      if (opts.references) {
        referencesPromises = internalFindByIds(context, user, opts.references, { type: ENTITY_TYPE_EXTERNAL_REFERENCE }) as Promise<BasicStoreBase[]>;
      }
      const references = referencesPromises ? await BluePromise.all(referencesPromises) : [];
      if ((opts.references ?? []).length > 0 && references.length !== (opts.references ?? []).length) {
        throw FunctionalError('Cant find element references for commit', {
          id: relationElement.fromId,
          references: opts.references,
        });
      }
      const targetElement = { ...relationElement.to, i_relation: relationElement };
      const previous = await storeLoadByIdWithRefs(context, user, relationElement.fromId) as Record<string, any>;
      const instance = structuredClone(previous);
      const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(instance.entity_type, relationElement.entity_type);
      let inputs: EditInput[] = [];
      if (key) {
        if (isSingleRelationsRef(instance.entity_type, element.entity_type)) {
          inputs = [{ key, value: [] }];
          instance[key] = undefined; // Generate the new version of the from
        } else {
          inputs = [{ key, value: [targetElement], operation: EditOperation.Remove }];
          // To prevent to many patch operations, removed key must be put at the end
          const withoutElementDeleted = (previous[key] ?? []).filter((e: any) => e.internal_id !== targetElement.internal_id);
          previous[key] = [...withoutElementDeleted, targetElement];
          // Generate the new version of the from
          instance[key] = withoutElementDeleted;
        }
      }
      const message = await generateUpdateMessage(context, user, instance.entity_type, inputs);
      const isContainCommitReferences = opts.references && opts.references.length > 0;
      const commit = isContainCommitReferences ? {
        message: opts.commitMessage,
        external_references: references.map((ref) => convertExternalReferenceToStix(ref as StoreEntity)),
      } : undefined;
      await elDeleteElements(context, user, [element]);
      // Publish event in the stream
      const eventPromise = storeUpdateEvent(context, user, previous as StoreObject, instance as StoreObject, message, [], { ...opts, commit: commit as unknown as any });
      const taskPromise = createContainerSharingTask(context, ACTION_TYPE_UNSHARE, element);
      const [, updateEvent] = await BluePromise.all([taskPromise, eventPromise]);
      event = updateEvent;
      (element as StoreRelation).from = instance as BasicStoreBase; // dynamically update the from to have an up to date relation
    } else {
      // Start by deleting external files
      const isTrashableElement = !isInferredIndex(element._index)
        && (isStixCoreObject(element.entity_type) || isStixCoreRelationship(element.entity_type) || isStixSightingRelationship(element.entity_type));
      const forceDelete = !!opts.forceDelete || !isTrashableElement;
      const isTrashEnabled = conf.get('app:trash:enabled');
      if (isTrashEnabled && !forceDelete) {
        // mark indexed files as removed to exclude them from search
        await elUpdateRemovedFiles(element, true);
      } else {
        // if trash is disabled globally or for this element, delete permanently
        await deleteAllObjectFiles(context, user, element);
      }
      // Delete all linked elements
      const forceRefresh = opts.forceRefresh ?? true;
      await elDeleteElements(context, user, [element], { forceDelete, forceRefresh });
      // Publish event in the stream
      event = await storeDeleteEvent(context, user, element, opts);
    }
    // Temporary stored the deleted elements to prevent concurrent problem at creation
    await redisAddDeletions(participantIds, getDraftContext(context, user));
  } catch (err: any) {
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
export const deleteElementById = async <T extends StoreObject>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  type: string | undefined | null,
  opts = {},
) => {
  if (R.isNil(type)) {
    /* v8 ignore next */
    throw FunctionalError('You need to specify a type when deleting an entity');
  }
  const { element: deleted } = await internalDeleteElementById<T>(context, user, id, type, opts);
  return deleted;
};
export const deleteInferredRuleElement = async (
  rule: string,
  instance: Record<string, any>,
  deletedDependencies: string[],
  opts = {},
) => {
  const context = executionContext(rule, RULE_MANAGER_USER);
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
        await internalDeleteElementById(context, RULE_MANAGER_USER, instance.id, instance.entity_type, opts);
        return true;
      }
      // If not we need to clean the rule and keep the element for other rules.
      logApp.info('Cleanup inferred element', { rule, id: instance.id });
      const input = { [completeRuleName]: null };
      const upsertOpts = { fromRule, fromRuleDeletion: true };
      await upsertRelationRule(context, RULE_MANAGER_USER, instance, input, upsertOpts);
    } else {
      logApp.info('Upsert inferred element', { rule, id: instance.id });
      // Rule still have other explanation, update the rule
      const input = { [completeRuleName]: rebuildRuleContent };
      const ruleOpts = { fromRule, fromRuleDeletion: true };
      await upsertRelationRule(context, RULE_MANAGER_USER, instance, input, ruleOpts);
    }
  } catch (err: any) {
    if (err.name === ALREADY_DELETED_ERROR) {
      logApp.info(err);
    } else {
      logApp.error('Error handling inference', { cause: err });
    }
  }
  return false;
};
export const deleteRelationsByFromAndTo = async (
  context: AuthContext,
  user: AuthUser,
  fromId: string | null | undefined,
  toId: string | null | undefined,
  relationshipType: string,
  scopeType: string | null | undefined,
  opts = {},
) => {
  //* v8 ignore if */
  if (R.isNil(scopeType) || R.isNil(fromId) || R.isNil(toId)) {
    throw FunctionalError('You need to specify a scope type and both IDs when deleting a relation with from and to', {
      type: scopeType,
      from: fromId,
      to: toId,
    });
  }
  const fromThing = await internalLoadById(context, user, fromId, opts) as Record<string, any>;
  // Check mandatory attribute
  const entitySetting = await getEntitySettingFromCache(context, fromThing.entity_type) as BasicStoreEntityEntitySetting;
  const attributesMandatory = await getMandatoryAttributesForSetting(context, user, entitySetting);
  if (attributesMandatory.length > 0) {
    const attribute = attributesMandatory.find((attr) => attr === schemaRelationsRefDefinition.convertDatabaseNameToInputName(fromThing.entity_type, relationshipType));
    if (attribute && fromThing[buildRefRelationKey(relationshipType)].length === 1) {
      throw ValidationError('This attribute is mandatory', attribute, { attribute });
    }
  }
  const toThing = await internalLoadById(context, user, toId, opts);// check if user has "edit" access on from and to
  const draftId = getDraftContext(context, user);
  const draft = draftId ? await findDraftById(context, user, draftId) : null;
  const canEditFrom = validateUserAccessOperation(user, fromThing, AccessOperation.EDIT, draft);
  const canEditTo = validateUserAccessOperation(user, toThing, AccessOperation.EDIT, draft);

  if (!canEditFrom || !canEditTo) {
    throw ForbiddenAccess();
  }
  // Looks like the caller doesn't give the correct from, to currently
  const relationsCallback = async (relationsToDelete: BasicStoreBase[]) => {
    for (let i = 0; i < relationsToDelete.length; i += 1) {
      const r = relationsToDelete[i];
      await deleteElementById(context, user, r.internal_id, r.entity_type, opts);
    }
  };
  const relationsToDelete = await fullRelationsList(context, user, relationshipType, {
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    baseData: true,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['fromId'], values: [fromThing.internal_id] },
        { key: ['toId'], values: [toThing.internal_id] },
      ],
      filterGroups: [],
    },
    callback: relationsCallback,
  });
  return { from: fromThing, to: toThing, deletions: relationsToDelete };
};
// endregion
