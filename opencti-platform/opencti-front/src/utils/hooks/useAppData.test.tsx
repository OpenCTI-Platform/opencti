import { describe, expect, it } from 'vitest';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import { useComputeLinkFn } from './useAppData';
import { SchemaType } from './useAuth';

describe('Hook: useComputeLinkFn', () => {
  describe('Function: computeLink()', () => {
    it('should compute SecurityCoverageResult URL correctly', () => {
      const { hook } = testRenderHook(
        () => useComputeLinkFn(),
        {
          userContext: createMockUserContext({
            schema: {
              scrs: [],
              sdos: [],
              smos: [],
              scos: [],
            } as unknown as SchemaType,
          }),
        },
      );
      const computeLink = hook.result.current;
      const url = computeLink({
        entity_type: 'Security-Coverage-Result',
        id: 'scr-id',
        resultOf: {
          id: 'sc-id',
        },
      });
      expect(url).toEqual('/dashboard/analyses/security_coverages/sc-id/result');
    });
  });
});
