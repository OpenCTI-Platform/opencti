import { FunctionalError } from '../../../config/errors';
import { FilterMode, type StixCoreRelationshipAddInput } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';
import { findSecurityCoverageResultPaginated } from './securityCoverageResult-domain';
import type { StoreEntitySecurityCoverageResult } from './securityCoverageResult-types';

/**
 * Compute the average coverage information of an array of securityCoverageResult.
 *
 * @param results Array of results to compute the average coverage.
 * @returns Average coverage information.
 */
export const getAverageCoverageInformation = async (results: StoreEntitySecurityCoverageResult[]) => {
  const mapOfScores = new Map<string, number[]>();
  results.forEach(({ coverage_information }) => {
    (coverage_information ?? []).forEach(({ coverage_name, coverage_score }) => {
      if (mapOfScores.has(coverage_name)) {
        mapOfScores.get(coverage_name)!.push(coverage_score);
      } else {
        mapOfScores.set(coverage_name, [coverage_score]);
      }
    });
  });
  return Array.from(mapOfScores, ([coverage_name, scores]) => ({
    coverage_name,
    coverage_score: Math.round(scores.reduce((sum, num) => sum + num, 0) / scores.length),
  }));
};

/**
 * Get the most recent date of "coverage_last_result" of an array of securityCoverageResult.
 *
 * @param results Array of results to get the most recent "coverage_last_result".
 * @returns Most recent date.
 */
export const getMostRecentLastCoverageResult = async (results: StoreEntitySecurityCoverageResult[]) => {
  const allDates = results.flatMap(({ coverage_last_result }) => coverage_last_result || []);
  if (allDates.length === 0) return undefined;
  return new Date(Math.max(...allDates.map((d) => new Date(d).getTime())));
};

/**
 * Checks if the relationship fromId should be changed.
 * If the rel is 'has-covered' with a fromId of a securityCoverage,
 * Then changes fromId to the id of the associated securityCoverageResult.
 *
 * @param relInput Relationship input to check.
 * @returns True if the fromId of the input should be changed.
 */
export const shouldHandleHasCoveredRel = (relInput: StixCoreRelationshipAddInput) => {
  return relInput.coverage_external_uri && relInput.fromId.startsWith('security-coverage--');
};

/**
 * Replaces securityCoverage fromId to ID of associated securityCoverageResult.
 *
 * @param context To make the request to engine.
 * @param user To make the request to engine.
 * @param relInput Relationship input to manipulate.
 * @returns Transformed input.
 */
export const transformHasCoveredFromId = async (
  context: AuthContext,
  user: AuthUser,
  relInput: StixCoreRelationshipAddInput,
) => {
  const { edges } = await findSecurityCoverageResultPaginated(context, user, {
    filters: {
      filterGroups: [],
      mode: FilterMode.Or,
      filters: [{
        key: ['external_uri'],
        values: [relInput.coverage_external_uri],
      }],
    },
  });
  if (edges.length !== 1) {
    throw FunctionalError('Cannot find SecurityCoverageResult for this has-covered relationship');
  }
  return {
    ...relInput,
    fromId: edges[0].node.standard_id,
  };
};
