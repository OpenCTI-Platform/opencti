import { describe, expect, it } from 'vitest';
import { getAverageCoverageInformation, getMostRecentLastCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-utils';
import type { StoreEntitySecurityCoverageResult } from '../../../../src/modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';

describe('Function getMostRecentLastCoverageResult()', () => {
  it('should result undefined if array is empty', async () => {
    expect(await getMostRecentLastCoverageResult([])).toBeUndefined();
  });

  it('should result undefined if no result contains last_result date', async () => {
    const results = [
      { name: 'result 1' },
      { name: 'result 2' },
      { name: 'result 3' },
    ] as StoreEntitySecurityCoverageResult[];
    expect(await getMostRecentLastCoverageResult(results)).toBeUndefined();
  });

  it('should return the only last_result date', async () => {
    const results = [
      { name: 'result 1' },
      { name: 'result 2', coverage_last_result: '2026-07-07T15:16:08.223Z' },
      { name: 'result 3' },
    ] as StoreEntitySecurityCoverageResult[];
    expect(await getMostRecentLastCoverageResult(results)).toEqual(new Date('2026-07-07T15:16:08.223Z'));
  });

  it('should return the most recent last_result date', async () => {
    const results = [
      { name: 'result 1', coverage_last_result: '2026-07-07T15:16:08.223Z' },
      { name: 'result 2', coverage_last_result: '2026-07-06T15:16:08.223Z' },
      { name: 'result 3', coverage_last_result: '2026-07-05T15:16:08.223Z' },
    ] as StoreEntitySecurityCoverageResult[];
    expect(await getMostRecentLastCoverageResult(results)).toEqual(new Date('2026-07-07T15:16:08.223Z'));
  });
});

describe('Function getAverageCoverageInformation()', () => {
  it('should an empty array if no results', async () => {
    expect(await getAverageCoverageInformation([])).toEqual([]);
  });

  it('should an empty array if no coverage info', async () => {
    const results = [
      { name: 'result 1' },
      { name: 'result 2' },
      { name: 'result 3' },
    ] as StoreEntitySecurityCoverageResult[];
    expect(await getAverageCoverageInformation(results)).toEqual([]);
  });

  it('should return the only coverage_information', async () => {
    const results = [
      { name: 'result 1' },
      { coverage_information: [{ coverage_name: 'vulnerability', coverage_score: 40 }] },
      { name: 'result 3' },
    ] as StoreEntitySecurityCoverageResult[];
    expect(await getAverageCoverageInformation(results))
      .toEqual([{ coverage_name: 'vulnerability', coverage_score: 40 }]);
  });

  it('should return the average coverage_information', async () => {
    const results = [
      { coverage_information: [{ coverage_name: 'vulnerability', coverage_score: 60 }, { coverage_name: 'detection', coverage_score: 15 }] },
      { coverage_information: [{ coverage_name: 'vulnerability', coverage_score: 40 }, { coverage_name: 'detection', coverage_score: 20 }] },
      { name: 'result 3' },
    ] as StoreEntitySecurityCoverageResult[];
    expect(await getAverageCoverageInformation(results)).toEqual([
      { coverage_name: 'vulnerability', coverage_score: 50 },
      { coverage_name: 'detection', coverage_score: 18 },
    ]);
  });
});
