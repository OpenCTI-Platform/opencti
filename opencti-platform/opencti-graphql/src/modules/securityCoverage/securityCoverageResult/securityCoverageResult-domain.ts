import { BUS_TOPICS } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { createEntity, deleteElementById } from '../../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { FilterMode, FilterOperator, type SecurityCoverageResultAddInput } from '../../../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ENTITY_TYPE_SECURITY_COVERAGE, type BasicStoreEntitySecurityCoverage } from '../securityCoverage-types';
import {
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  type BasicStoreEntitySecurityCoverageResult,
  type StoreEntitySecurityCoverageResult,
} from './securityCoverageResult-types';

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
export const pageSecurityCoverageResultPaginated = (
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
 * Find all security coverage results for a security coverage.
 *
 * @param context
 * @param user User making the request.
 * @param resultOfId ID of the security coverage.
 * @returns List of security coverage results.
 */
export const listSecurityCoverageResultsByResultOf = async (
  context: AuthContext,
  user: AuthUser,
  resultOfId: string,
) => {
  return fullEntitiesList<BasicStoreEntitySecurityCoverageResult>(
    context,
    user,
    [ENTITY_TYPE_SECURITY_COVERAGE_RESULT],
    {
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          {
            mode: FilterMode.Or,
            operator: FilterOperator.Eq,
            key: [INPUT_RESULT_OF],
            values: [resultOfId],
          },
        ],
      },
    },
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
  const result: BasicStoreEntitySecurityCoverageResult = await createEntity(
    context,
    user,
    input,
    ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  );
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
 * Delete all security coverage results for a security coverage.
 *
 * @param context
 * @param user User making the request.
 * @param resultOfId ID of the security coverage.
 * @returns List of IDs deleted results.
 */
export const deleteSecurityCoverageResultsByResultOf = async (
  context: AuthContext,
  user: AuthUser,
  resultOfId: string,
) => {
  const deletedIds: string[] = [];
  const results = await listSecurityCoverageResultsByResultOf(
    context,
    user,
    resultOfId,
  );
  for (const result of results) {
    const deleted = await deleteElementById<StoreEntitySecurityCoverageResult>(
      context,
      user,
      result.id,
      ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
    );
    deletedIds.push(deleted.standard_id);
  }
  return deletedIds;
};
