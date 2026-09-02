import { BUS_TOPICS, logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { deleteElementById } from '../../../database/middleware';
import { pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { ACTION_TYPE_ADD_RELATED_COVERED_ENTITIES, createListTask } from '../../../domain/backgroundTask-common';
import { createQueryTask } from '../../../domain/backgroundTask';
import { type FilterGroup, type SecurityCoverageResultAddInput, type SecurityCoverageSelectedEntitiesInput } from '../../../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import { isNotEmptyField } from '../../../database/utils';
import { emptyFilterGroup, isFilterGroupNotEmpty } from '../../../utils/filtering/filtering-utils';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ENTITY_TYPE_SECURITY_COVERAGE, type BasicStoreEntitySecurityCoverage } from '../securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, type BasicStoreEntitySecurityCoverageResult } from './securityCoverageResult-types';
import { internalCreateSecurityCoverageResult } from './securityCoverageResult-utils';

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

  const input = {
    ...securityCoverageResultInput,
  };
  if (!securityCoverageResultInput.name) {
    input.name = `Result of ${securityCoverage.name}`;
  }
  const result = await internalCreateSecurityCoverageResult(context, user, input);
  return notify(
    BUS_TOPICS[ENTITY_TYPE_SECURITY_COVERAGE_RESULT].ADDED_TOPIC,
    result,
    user,
  );
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
 * platform, so an error is raised instead.
 *
 * @param context
 * @param user User making the request.
 * @param securityCoverageResultId ID of the security coverage result to populate.
 * @param selection Entity selection (selected_ids, or filters/search/excluded_ids).
 * @returns The created background task.
 */
export const createHasCoveredRelTask = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResultId: string,
  selection: SecurityCoverageSelectedEntitiesInput,
) => {
  const description = `Create has-covered relationships for SCR ${securityCoverageResultId}`;
  const actions = [{ type: ACTION_TYPE_ADD_RELATED_COVERED_ENTITIES, id: securityCoverageResultId }];

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
  if (!isFilterGroupNotEmpty(filterGroup) && !search) {
    throw FunctionalError(
      'Cannot create has-covered relationships without any entity selection, please provide ids, filters or a search term.',
      { securityCoverageResultId },
    );
  }

  logApp.info(
    '[SECURITY-COVERAGE] addSecurityCoverage: Manual creation, resolving has-covered relationships targets from filters/search/exclusions',
    { filters: filterGroup, search, excluded_ids: selection.excluded_ids },
  );
  return createQueryTask(context, user, {
    description,
    scope: 'KNOWLEDGE',
    actions,
    filters: JSON.stringify(filterGroup),
    search,
    excluded_ids: selection.excluded_ids ?? [],
  });
};
