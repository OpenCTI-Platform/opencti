import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import { FilterMode } from '../../../../src/generated/graphql';
import { filterBundleElements, isBundleElementMatchFilters } from '../../../../src/modules/playbook/playbook-utils';
import { testContext } from '../../../utils/testQuery';
import type { StixObject } from '../../../../src/types/stix-2-1-common';

describe('Playbook utils unit tests', () => {
  const matchingFilter = JSON.stringify({
    filterGroups: [],
    filters: [],
    mode: FilterMode.And,
  });
  const nonMatchingFilter = JSON.stringify({
    filterGroups: [],
    filters: [],
    mode: FilterMode.Or,
  });

  const stixElement1 = { id: 'malware--345243' } as unknown as StixObject;
  const stixElement2 = { id: 'campaign--2348746' } as unknown as StixObject;
  const stixElements = [stixElement1, stixElement2];

  beforeEach(() => {
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup')
      .mockImplementation(async (_, __, ___, filterGroup) => {
        return filterGroup?.mode === FilterMode.And;
      });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Function: isBundleElementMatchFilters()', () => {
    it('should return true if matching filter', async () => {
      const result = await isBundleElementMatchFilters(
        testContext,
        stixElement1,
        matchingFilter,
      );
      expect(result).toBe(true);
    });

    it('should return false if non matching filter', async () => {
      const result = await isBundleElementMatchFilters(
        testContext,
        stixElement1,
        nonMatchingFilter,
      );
      expect(result).toBe(false);
    });

    it('should return true if no filters given', async () => {
      const result = await isBundleElementMatchFilters(
        testContext,
        stixElement1,
        '',
      );
      expect(result).toBe(true);
    });
  });

  describe('Function: filterBundleElements()', () => {
    it('should return full bundle if no filters', async () => {
      const result = await filterBundleElements(
        testContext,
        stixElements,
        '',
      );
      expect(result.length).toBe(2);
    });

    it('should return full bundle if matching filters', async () => {
      const result = await filterBundleElements(
        testContext,
        stixElements,
        matchingFilter,
      );
      expect(result.length).toBe(2);
    });

    it('should return empty bundle if non matching filters', async () => {
      const result = await filterBundleElements(
        testContext,
        stixElements,
        nonMatchingFilter,
      );
      expect(result.length).toBe(0);
    });
  });
});
