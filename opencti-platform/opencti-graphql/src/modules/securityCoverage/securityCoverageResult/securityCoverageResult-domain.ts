import { BUS_TOPICS, logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { deleteElementById } from '../../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { ACTION_TYPE_ADD_RELATED_COVERED_ENTITIES, createListTask } from '../../../domain/backgroundTask-common';
import { createQueryTask } from '../../../domain/backgroundTask';
import {
  type EditInput,
  type FilterGroup,
  FilterMode,
  type SecurityCoverageResultAddInput,
  type SecurityCoverageResultEditInput,
  type SecurityCoverageSelectedEntitiesInput,
} from '../../../generated/graphql';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_OBJECTS } from '../../../schema/general';
import { extractIdsFromStoreObject, isNotEmptyField } from '../../../database/utils';
import { emptyFilterGroup, isFilterGroupNotEmpty } from '../../../utils/filtering/filtering-utils';
import {
  ID_SUBFILTER,
  IDS_FILTER,
  INSTANCE_REGARDING_OF,
  INSTANCE_REGARDING_OF_DIRECTION_FORCED,
  INSTANCE_REGARDING_OF_DIRECTION_REVERSE,
  RELATION_TYPE_SUBFILTER,
  TYPE_FILTER,
} from '../../../utils/filtering/filtering-constants';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import { isStixDomainObjectContainer } from '../../../schema/stixDomainObject';
import { RELATION_TARGETS, RELATION_USES } from '../../../schema/stixCoreRelationship';
import { ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED, type BasicStoreEntitySecurityCoverage } from '../securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, RELATION_RESULT_OF, type BasicStoreEntitySecurityCoverageResult } from './securityCoverageResult-types';
import { HAS_COVERED_TARGETS_TYPE, internalCreateSecurityCoverageResult } from './securityCoverageResult-utils';
import { isFromConnectorWork } from '../../../utils/connector-work';
import { stixDomainObjectEditField } from '../../../domain/stixDomainObject';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';

/**
 * Find a security coverage results by its ID.
 *
 * @param context
 * @param user User making the request.
 * @param resultOfId ID of the security coverage result.
 * @returns Security coverage result.
 */
export const findById = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageId: string,
): Promise<BasicStoreEntitySecurityCoverageResult> => {
  return storeLoadById<BasicStoreEntitySecurityCoverageResult>(
    context,
    user,
    securityCoverageId,
    ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  );
};

/**
 * Find all security coverage results using pagination.
 *
 * @param context
 * @param user User making the request.
 * @param args Options to customize the query.
 * @returns Security coverage result.
 */
export const findSecurityCoverageResultPaginated = (
  context: AuthContext,
  user: AuthUser,
  args: EntityOptions<BasicStoreEntitySecurityCoverageResult>,
) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverageResult>(
    context,
    user,
    [ENTITY_TYPE_SECURITY_COVERAGE_RESULT],
    args,
  );
};

/**
 * Add a security coverage result.
 *
 * @param context
 * @param user User making the request.
 * @param  securityCoverageResultInput Data of the security coverage result.
 * @returns Created result.
 */
export const addSecurityCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResultInput: SecurityCoverageResultAddInput,
): Promise<BasicStoreEntitySecurityCoverageResult> => {
  const securityCoverage = await storeLoadById<BasicStoreEntitySecurityCoverage>(
    context,
    user,
    securityCoverageResultInput.resultOf,
    ENTITY_TYPE_SECURITY_COVERAGE,
  );
  if (!securityCoverage) {
    throw FunctionalError('Security coverage not found', { securityCoverageResultInput });
  }

  const {
    add_related_entities,
    ...input
  } = securityCoverageResultInput;

  const coveredEntityId = securityCoverage[RELATION_COVERED];
  if (add_related_entities) {
    await checkRelatedEntitiesCanBeCovered(context, user, coveredEntityId, add_related_entities);
  }

  if (!securityCoverageResultInput.name) {
    input.name = `Result of ${securityCoverage.name}`;
  }
  const noEnrichOnUpdate = await isFromConnectorWork(context, user);
  const result = await internalCreateSecurityCoverageResult(context, user, input, noEnrichOnUpdate);

  if (add_related_entities) {
    await createHasCoveredRelTask(context, user, result.id, coveredEntityId, add_related_entities);
  }

  return notify(
    BUS_TOPICS[ENTITY_TYPE_SECURITY_COVERAGE_RESULT].ADDED_TOPIC,
    result,
    user,
  );
};

/**
 * Whether a field of a security coverage result holds a list of values.
 *
 * @param key Name of the field.
 * @returns True for multiple attributes (coverage_information) and multiple refs (labels, markings).
 */
const isMultipleField = (key: string) => {
  return schemaAttributesDefinition.isMultipleAttribute(ENTITY_TYPE_SECURITY_COVERAGE_RESULT, key)
    || (schemaRelationsRefDefinition.getRelationRef(ENTITY_TYPE_SECURITY_COVERAGE_RESULT, key)?.multiple ?? false);
};

/**
 * Find the entity covered by the security coverage of a result.
 *
 * @param context
 * @param user User making the request.
 * @param securityCoverageResult Security coverage result.
 * @returns ID of the covered entity.
 */
const findCoveredEntityId = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResult: BasicStoreEntitySecurityCoverageResult,
): Promise<string> => {
  const securityCoverageId = securityCoverageResult[RELATION_RESULT_OF];
  const securityCoverage = await storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, securityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  if (!securityCoverage) {
    throw FunctionalError('Security coverage not found', { securityCoverageId });
  }
  return securityCoverage[RELATION_COVERED];
};

/**
 * Update the attributes of a security coverage result, and optionally
 * add new has-covered relationships to it.
 *
 * Existing has-covered relationships are never removed here: the background
 * task only creates relationships for the selected entities.
 *
 * @param context
 * @param user User making the request.
 * @param id ID of the security coverage result.
 * @param securityCoverageResultInput Attributes to update and entities to add.
 * @returns Updated result.
 */
export const editSecurityCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  securityCoverageResultInput: SecurityCoverageResultEditInput,
): Promise<BasicStoreEntitySecurityCoverageResult> => {
  const securityCoverageResult = await findById(context, user, id);
  if (!securityCoverageResult) {
    throw FunctionalError('Security coverage result not found', { id });
  }

  const {
    add_related_entities,
    ...attributes
  } = securityCoverageResultInput;

  const coveredEntityId = add_related_entities ? await findCoveredEntityId(context, user, securityCoverageResult) : undefined;
  if (add_related_entities && coveredEntityId) {
    await checkRelatedEntitiesCanBeCovered(context, user, coveredEntityId, add_related_entities);
  }

  const editInputs: EditInput[] = Object.entries(attributes)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => {
      // A null list means an empty list: [null] would be stored as a null element.
      if (value === null && isMultipleField(key)) {
        return { key, value: [] };
      }
      return { key, value: Array.isArray(value) ? value : [value] };
    });

  const result = editInputs.length > 0
    ? await stixDomainObjectEditField(context, user, id, editInputs)
    : securityCoverageResult;

  if (add_related_entities && coveredEntityId) {
    await createHasCoveredRelTask(context, user, id, coveredEntityId, add_related_entities);
  }

  return result;
};

/**
 * Delete a security coverage result by id.
 *
 * @param context
 * @param user User making the request.
 * @param id ID of the security coverage result.
 * @returns ID of deleted result.
 */
export const deleteSecurityCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
) => {
  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_SECURITY_COVERAGE_RESULT);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, id, user);
  return deleted.id;
};

/**
 * Filters matching the entities a security coverage result can cover:
 * the objects of a container, or what any other entity targets or uses.
 *
 * @param context
 * @param user User making the request.
 * @param coveredEntityId ID of the entity covered by the security coverage.
 * @returns Filters matching the coverable entities.
 */
const buildCoverableEntitiesFilters = async (
  context: AuthContext,
  user: AuthUser,
  coveredEntityId: string,
): Promise<FilterGroup['filters']> => {
  const coveredEntity = await storeLoadById<BasicStoreEntity>(context, user, coveredEntityId, ABSTRACT_STIX_CORE_OBJECT);
  if (!coveredEntity) {
    throw FunctionalError('Covered entity not found', { coveredEntityId });
  }
  const linkedToCoveredEntity = isStixDomainObjectContainer(coveredEntity.entity_type)
    ? { key: [INPUT_OBJECTS], values: [coveredEntity.internal_id] }
    : {
        key: [INSTANCE_REGARDING_OF],
        values: [
          { key: ID_SUBFILTER, values: [coveredEntity.internal_id] },
          { key: RELATION_TYPE_SUBFILTER, values: [RELATION_TARGETS, RELATION_USES] },
          { key: INSTANCE_REGARDING_OF_DIRECTION_FORCED, values: [true] },
          { key: INSTANCE_REGARDING_OF_DIRECTION_REVERSE, values: [false] },
        ],
      };
  return [linkedToCoveredEntity, { key: [TYPE_FILTER], values: HAS_COVERED_TARGETS_TYPE }];
};

/**
 * Reject the selected entities a security coverage result cannot cover.
 * Filters need no check: createHasCoveredRelTask() keeps only coverable entities.
 *
 * @param context
 * @param user User making the request.
 * @param coveredEntityId ID of the entity covered by the security coverage.
 * @param relatedEntities Entities to cover, received in add_related_entities.
 */
export const checkRelatedEntitiesCanBeCovered = async (
  context: AuthContext,
  user: AuthUser,
  coveredEntityId: string,
  relatedEntities: SecurityCoverageSelectedEntitiesInput,
) => {
  const selectedIds = relatedEntities.selected_ids ?? [];
  if (selectedIds.length === 0) {
    return;
  }
  const coverableFilters = await buildCoverableEntitiesFilters(context, user, coveredEntityId);
  const filters = { mode: FilterMode.And, filters: [...coverableFilters, { key: [IDS_FILTER], values: selectedIds }], filterGroups: [] };
  const coverableEntities = await fullEntitiesList<BasicStoreEntity>(context, user, HAS_COVERED_TARGETS_TYPE, { filters });
  const coverableIds = new Set(coverableEntities.flatMap(extractIdsFromStoreObject));
  const rejectedIds = selectedIds.filter((selectedId) => !coverableIds.has(selectedId));
  if (rejectedIds.length > 0) {
    throw FunctionalError('Entities to cover must be linked to the covered entity', { coveredEntityId, rejectedIds });
  }
};

/**
 * Create a background task that will create has-covered relationships between
 * a security coverage result and its covered entities.
 *
 * If `selection.selected_ids` is provided and non-empty, a LIST task is created
 * targeting exactly those ids. Otherwise a QUERY task is created using
 * `selection.filters` / `selection.search` / `selection.excluded_ids`, letting the
 * background task itself resolve the matching entities.
 *
 * The selection must target something: either explicit ids, or a non-empty filter
 * group, or a search term. Otherwise the task would apply to every entity of the
 * platform, so an error is raised instead. Filters are restricted to the entities
 * the result can cover; selected ids are checked by checkRelatedEntitiesCanBeCovered().
 *
 * @param context
 * @param user User making the request.
 * @param securityCoverageResultId ID of the security coverage result to populate.
 * @param coveredEntityId ID of the entity covered by the security coverage.
 * @param selection Entity selection (selected_ids, or filters/search/excluded_ids).
 * @returns The created background task.
 */
export const createHasCoveredRelTask = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResultId: string,
  coveredEntityId: string,
  selection: SecurityCoverageSelectedEntitiesInput,
) => {
  const description = `Create has-covered relationships for SCR ${securityCoverageResultId}`;
  const actions = [{
    type: ACTION_TYPE_ADD_RELATED_COVERED_ENTITIES,
    id: securityCoverageResultId,
    relationships_config: selection.relationships_config ?? undefined,
  }];

  const selectedIds = selection.selected_ids ?? [];
  if (selectedIds.length > 0) {
    logApp.info(
      `[SECURITY-COVERAGE] addSecurityCoverage: Manual creation, ${selectedIds.length} explicit entities selected for has-covered relationships`,
      { selectedIds },
    );
    return createListTask(context, user, {
      description,
      scope: 'KNOWLEDGE',
      ids: selectedIds,
      actions,
      orderMode: 'asc',
    });
  }

  const filterGroup: FilterGroup = isNotEmptyField(selection.filters)
    ? JSON.parse(selection.filters as string)
    : emptyFilterGroup;
  const search = isNotEmptyField(selection.search) ? selection.search as string : undefined;
  if (!isFilterGroupNotEmpty(filterGroup)) {
    throw FunctionalError(
      'Cannot create has-covered relationships without any entity selection, please provide ids, filters or a search term.',
      { securityCoverageResultId },
    );
  }
  const coverableFilters = await buildCoverableEntitiesFilters(context, user, coveredEntityId);

  logApp.info(
    '[SECURITY-COVERAGE] addSecurityCoverage: Manual creation, resolving has-covered relationships targets from filters/search/exclusions',
    { filters: filterGroup, search, excluded_ids: selection.excluded_ids },
  );
  return createQueryTask(context, user, {
    description,
    scope: 'KNOWLEDGE',
    actions,
    filters: JSON.stringify({ mode: FilterMode.And, filters: coverableFilters, filterGroups: [filterGroup] }),
    search,
    excluded_ids: selection.excluded_ids ?? [],
  });
};
