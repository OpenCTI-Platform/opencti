import { describe, it, expect } from 'vitest';
import { useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
import { createMockUserContext, testRenderHook } from './test-render';
import filterKeysSchema from './FilterUtilsConstants';

describe('Filters utils', () => {
  describe('useBuildFilterKeysMapFromEntityType', () => {
    it('should list filter definitions by given entity types attributes', () => {
      const stixCoreObjectKey = 'Stix-Core-Object';
      const entityTypes = [stixCoreObjectKey];
      const { hook } = testRenderHook(
        () => useBuildFilterKeysMapFromEntityType(entityTypes),
        {
          userContext: createMockUserContext({
            schema: {
              scos: [{ id: '', label: '' }],
              sdos: [{ id: '', label: '' }],
              smos: [{ id: '', label: '' }],
              scrs: [{ id: '', label: '' }],
              schemaRelationsTypesMapping: new Map<string, readonly string[]>(),
              schemaRelationsRefTypesMapping: new Map<string, readonly { name: string, toTypes: string[] }[]>(),
              filterKeysSchema,
            },
          }),
        },
      );
      expect(hook.result.current).toStrictEqual(filterKeysSchema.get(stixCoreObjectKey));
    });
  });
});
