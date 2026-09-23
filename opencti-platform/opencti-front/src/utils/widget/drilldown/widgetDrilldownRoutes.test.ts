import { describe, expect, it } from 'vitest';
import { resolveListRoute } from './widgetDrilldownRoutes';
import type { FilterGroup } from '../../filters/filtersHelpers-types';

const group = (filters: FilterGroup['filters']): FilterGroup => ({
  mode: 'and',
  filters,
  filterGroups: [],
});

describe('resolveListRoute', () => {
  it('returns the dedicated route for a single known entity type', () => {
    const filters = group([{ key: 'entity_type', values: ['Intrusion-Set'], operator: 'eq', mode: 'or' }]);
    expect(resolveListRoute('entities', filters)).toEqual({
      route: '/dashboard/threats/intrusion_sets',
      consumedEntityType: 'Intrusion-Set',
    });
  });

  it('treats a missing operator as eq', () => {
    const filters = group([{ key: 'entity_type', values: ['Malware'], mode: 'or' }]);
    expect(resolveListRoute('entities', filters)?.route).toEqual('/dashboard/arsenal/malwares');
  });

  it('falls back to the generic route for multiple entity types', () => {
    const filters = group([{ key: 'entity_type', values: ['Malware', 'Tool'], operator: 'eq', mode: 'or' }]);
    expect(resolveListRoute('entities', filters)).toEqual({
      route: '/dashboard/data/entities',
      consumedEntityType: null,
    });
  });

  it('falls back to the generic route for a negated entity type', () => {
    const filters = group([{ key: 'entity_type', values: ['Malware'], operator: 'not_eq', mode: 'or' }]);
    expect(resolveListRoute('entities', filters)?.consumedEntityType).toBeNull();
  });

  it('falls back to the generic route when the dedicated route is not a filterable list', () => {
    const filters = group([{ key: 'entity_type', values: ['User'], operator: 'eq', mode: 'or' }]);
    expect(resolveListRoute('entities', filters)).toEqual({
      route: '/dashboard/data/entities',
      consumedEntityType: null,
    });
  });

  it('ignores entity_type filters nested in sub-groups', () => {
    const filters: FilterGroup = {
      mode: 'and',
      filters: [],
      filterGroups: [group([{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }])],
    };
    expect(resolveListRoute('entities', filters)?.consumedEntityType).toBeNull();
  });

  it('returns the generic route per perspective when there is no entity_type filter', () => {
    expect(resolveListRoute('entities', null)?.route).toEqual('/dashboard/data/entities');
    expect(resolveListRoute('relationships', null)?.route).toEqual('/dashboard/data/relationships');
    expect(resolveListRoute('audits', null)?.route).toEqual('/dashboard/audits');
  });

  it('returns null for an unknown perspective', () => {
    expect(resolveListRoute('%future added value', null)).toBeNull();
  });
});
