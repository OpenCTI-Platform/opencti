import { describe, expect, it } from 'vitest';
import { buildConnectionRoleFilter } from '../../../src/database/middleware-loader';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../src/schema/general';
import { FilterOperator } from '../../../src/generated/graphql';

describe('buildConnectionRoleFilter', () => {
  it('should filter on the exact role of a concrete relationship type', () => {
    expect(buildConnectionRoleFilter('uses', 'from')).toEqual({ key: 'role', values: ['uses_from'] });
  });
  it('should filter on the exact roles of several concrete relationship types', () => {
    expect(buildConnectionRoleFilter(['uses', 'targets'], 'to')).toEqual({ key: 'role', values: ['uses_to', 'targets_to'] });
  });
  it('should keep the role wildcard when a relationship type is abstract', () => {
    expect(buildConnectionRoleFilter(['uses', ABSTRACT_STIX_CORE_RELATIONSHIP], 'from'))
      .toEqual({ key: 'role', values: ['*_from'], operator: FilterOperator.Wildcard });
  });
  it('should keep the role wildcard when no relationship type is given', () => {
    expect(buildConnectionRoleFilter(undefined, 'to')).toEqual({ key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard });
    expect(buildConnectionRoleFilter([], 'to')).toEqual({ key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard });
  });
});
