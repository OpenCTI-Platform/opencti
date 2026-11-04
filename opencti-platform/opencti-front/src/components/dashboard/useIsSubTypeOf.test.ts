import { describe, expect, it } from 'vitest';
import type { FilterDefinition } from '../../utils/hooks/useAuth';
import { createMockUserContext, testRenderHook } from '../../utils/tests/test-render';
import { buildIsSubTypeOf, useIsSubTypeOf } from './useIsSubTypeOf';

const entityTypeFilter = (subEntityTypes: string[]) => new Map([
  ['entity_type', { filterKey: 'entity_type', type: 'string', subEntityTypes } as unknown as FilterDefinition],
  ['name', { filterKey: 'name', type: 'string', subEntityTypes } as unknown as FilterDefinition],
]);

// Shape of the filter keys schema served by the back (opencti-graphql/src/domain/filterKeysSchema.ts):
// an abstract type keeps the `entity_type` filter, listing itself and all its descendants;
// a concrete type has no `entity_type` filter.
const filterKeysSchema = new Map<string, Map<string, FilterDefinition>>([
  ['Identity', entityTypeFilter(['Identity', 'Sector', 'Organization', 'Individual', 'System', 'SecurityPlatform'])],
  ['Location', entityTypeFilter(['Location', 'Region', 'Country', 'City', 'Administrative-Area', 'Position'])],
  ['Stix-Core-Object', entityTypeFilter(['Stix-Core-Object', 'Stix-Domain-Object', 'Identity', 'Sector', 'Malware', 'IPv4-Addr'])],
  ['Sector', new Map([['name', { filterKey: 'name', type: 'string', subEntityTypes: ['Sector'] } as unknown as FilterDefinition]])],
]);

describe('buildIsSubTypeOf', () => {
  const isSubTypeOf = buildIsSubTypeOf(filterKeysSchema);

  it('knows that a Sector is an Identity', () => {
    expect(isSubTypeOf('Sector', 'Identity')).toBe(true);
  });

  it('follows the whole hierarchy, not only the direct parent', () => {
    expect(isSubTypeOf('Sector', 'Stix-Core-Object')).toBe(true);
  });

  it('accepts a type as a sub type of itself', () => {
    expect(isSubTypeOf('Malware', 'Malware')).toBe(true);
  });

  it('rejects a type of another branch', () => {
    expect(isSubTypeOf('Sector', 'Location')).toBe(false);
    expect(isSubTypeOf('Identity', 'Sector')).toBe(false);
  });

  it('rejects an unknown type or parent', () => {
    expect(isSubTypeOf('Unknown-Type', 'Identity')).toBe(false);
    expect(isSubTypeOf('Sector', 'Unknown-Parent')).toBe(false);
  });

  it('falls back to exact match without a filter keys schema', () => {
    const exactMatch = buildIsSubTypeOf(undefined);
    expect(exactMatch('Sector', 'Identity')).toBe(false);
    expect(exactMatch('Sector', 'Sector')).toBe(true);
  });
});

describe('useIsSubTypeOf', () => {
  it('reads the hierarchy from the schema of the platform, already loaded: no query', () => {
    const userContext = createMockUserContext({ schema: { filterKeysSchema } });
    const { hook: { result }, relayEnv } = testRenderHook(() => useIsSubTypeOf(), { userContext });
    expect(result.current('Sector', 'Identity')).toBe(true);
    expect(result.current('Malware', 'Identity')).toBe(false);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });
});
