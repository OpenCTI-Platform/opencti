import { logApp } from '../../../config/conf';
import { createEntity } from '../../../database/middleware';
import type { SecurityCoverageResultAddInput } from '../../../generated/graphql';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../schema/stixCyberObservable';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../schema/stixDomainObject';
import { ENTITY_TYPE_VULNERABILITY } from '../../vulnerability/vulnerability-types';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ENTITY_TYPE_INDICATOR } from '../../indicator/indicator-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, type BasicStoreEntitySecurityCoverageResult, type StoreEntitySecurityCoverageResult } from './securityCoverageResult-types';

export const HAS_COVERED_TARGETS_TYPE = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_VULNERABILITY,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_TYPE_INDICATOR,
];

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
 * Internal function to create a security coverage result.
 *
 * /!\ This function is not directly available through the API.
 * The API one is making extra checks, this one exists to avoid duplicating code.
 *
 * @param context
 * @param user user making the request.
 * @param securityCoverageResultInput Input to create the security coverage result.
 */
export const internalCreateSecurityCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResultInput: SecurityCoverageResultAddInput,
) => {
  const result: BasicStoreEntitySecurityCoverageResult = await createEntity(
    context,
    user,
    securityCoverageResultInput,
    ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  );
  logApp.info(`[SECURITY-COVERAGE-RESULT][${securityCoverageResultInput.resultOf}] SCR created: ${result.standard_id}`);
  return result;
};
