import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { forgetDeletedPirsStreamMatchability, isPirMatchableOnStream, PIR_NOT_MATCHABLE_WARNING_INTERVAL } from '../../../src/manager/pirManager';
import type { ParsedPir } from '../../../src/modules/pir/pir-types';
import { PirType } from '../../../src/generated/graphql';
import { testContext } from '../../utils/testQuery';
import { logApp } from '../../../src/config/conf';
import { checkSavedFilterGroupForStixMatch } from '../../../src/utils/filtering/filtering-stix/stix-filtering';

// The custom field testers are read from the cache, not available in unit tests: no custom field is defined.
vi.mock('../../../src/modules/customField/custom-field-stix-utils', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/modules/customField/custom-field-stix-utils')>(),
  getCustomFieldsStixFilterTesters: async () => ({}),
}));

// Spy on the filters check, to count the checks and to make it fail with another error than an invalid filter.
vi.mock('../../../src/utils/filtering/filtering-stix/stix-filtering', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../src/utils/filtering/filtering-stix/stix-filtering')>();
  return { ...original, checkSavedFilterGroupForStixMatch: vi.fn(original.checkSavedFilterGroupForStixMatch) };
});

const buildPir = (pirId: string, criterionFilterKey: string, pirFilterKey = 'confidence') => ({
  id: pirId,
  pir_type: PirType.ThreatLandscape,
  pir_filters: {
    mode: 'and',
    filters: [{ key: [pirFilterKey], values: ['50'], operator: 'gte', mode: 'or' }],
    filterGroups: [],
  },
  pir_criteria: [{
    weight: 1,
    filters: {
      mode: 'and',
      filters: [
        { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
        { key: [criterionFilterKey], values: ['location-id'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  }],
} as unknown as ParsedPir);

describe('Pir manager', () => {
  describe('Function isPirMatchableOnStream()', () => {
    let warnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
      vi.mocked(checkSavedFilterGroupForStixMatch).mockClear();
    });

    afterEach(() => {
      warnSpy.mockRestore();
      vi.useRealTimers();
      forgetDeletedPirsStreamMatchability([]);
    });

    it('should accept a Pir built like the UI does', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('pir-ui', 'toId'))).toBe(true);
      expect(warnSpy).not.toHaveBeenCalled();
    });

    it('should accept a Pir with a filter on a deleted custom field, as stix matching does', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('pir-deleted-cf', 'x_opencti_cf_deleted'))).toBe(true);
    });

    it('should reject a Pir with a criterion filter key not supported in stix matching, and log the key without the values', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('pir-criterion', 'regardingOf'))).toBe(false);
      expect(warnSpy).toHaveBeenCalledTimes(1);
      const [message, meta] = warnSpy.mock.calls[0] as [string, { cause: { message: string; extensions: Record<string, unknown> }; pirId: string; filtersLocation: string }];
      expect(message).toEqual('[OPENCTI-MODULE] Pir filters cannot be evaluated on stream events, Pir skipped');
      expect(meta.pirId).toEqual('pir-criterion');
      expect(meta.filtersLocation).toEqual('pir_criteria[0]');
      expect(meta.cause.message).toEqual('Stix filtering is not compatible with the provided filter key');
      expect(meta.cause.extensions).toEqual({ code: 'UNSUPPORTED_ERROR', data: { key: '["regardingOf"]' } });
    });

    it('should reject a Pir with a Pir filter key not supported in stix matching', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('pir-filters', 'toId', 'regardingOf'))).toBe(false);
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0][1]).toMatchObject({ pirId: 'pir-filters', filtersLocation: 'pir_filters' });
    });

    it('should check the filters of a Pir only once', async () => {
      const pir = buildPir('pir-checked-once', 'toId');
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(true);
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(true);
      // Once for the Pir filters, once for its single criterion
      expect(checkSavedFilterGroupForStixMatch).toHaveBeenCalledTimes(2);
    });

    it('should check the filters of a Pir again once the Pir has been forgotten', async () => {
      const pir = buildPir('pir-forgotten', 'toId');
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(true);
      forgetDeletedPirsStreamMatchability(['pir-forgotten']);
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(true);
      expect(checkSavedFilterGroupForStixMatch).toHaveBeenCalledTimes(2);
      forgetDeletedPirsStreamMatchability(['another-pir']);
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(true);
      expect(checkSavedFilterGroupForStixMatch).toHaveBeenCalledTimes(4);
    });

    it('should warn again about a skipped Pir only after the warning interval', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const pir = buildPir('pir-warned', 'regardingOf');
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(false);
      vi.advanceTimersByTime(PIR_NOT_MATCHABLE_WARNING_INTERVAL - 1);
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(false);
      expect(warnSpy).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(1);
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(false);
      expect(warnSpy).toHaveBeenCalledTimes(2);
    });

    it('should throw an error that is not about an invalid filter, and check the Pir again next time', async () => {
      const pir = buildPir('pir-other-error', 'toId');
      vi.mocked(checkSavedFilterGroupForStixMatch).mockRejectedValueOnce(new Error('Cache not available'));
      await expect(isPirMatchableOnStream(testContext, pir)).rejects.toThrow('Cache not available');
      expect(warnSpy).not.toHaveBeenCalled();
      expect(await isPirMatchableOnStream(testContext, pir)).toBe(true);
    });
  });
});
