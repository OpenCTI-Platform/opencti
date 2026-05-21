import { deleteElementById } from '../../../database/middleware';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';
import {
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  type BasicStoreEntitySecurityCoverageResult,
  type StoreEntitySecurityCoverageResult,
} from './securityCoverageResult-types';

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
    deletedIds.push(deleted.id);
  }
  return deletedIds;
};
