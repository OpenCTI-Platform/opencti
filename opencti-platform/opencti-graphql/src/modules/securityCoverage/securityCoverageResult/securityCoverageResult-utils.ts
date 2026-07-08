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
    console.log(coverage_information);
    (coverage_information ?? []).forEach(({ coverage_name, coverage_score }) => {
      if (mapOfScores.has(coverage_name)) {
        mapOfScores.get(coverage_name)!.push(coverage_score);
      } else {
        mapOfScores.set(coverage_name, [coverage_score]);
      }
    });
  });
  console.log(mapOfScores);
  return Array.from(mapOfScores, ([coverage_name, scores]) => ({
    coverage_name,
    coverage_score: scores.reduce((sum, num) => sum + num, 0) / scores.length,
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
