import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useProvenanceTrackedFilters from './useProvenanceTrackedFilters';

const settings = vi.hoisted(() => ({ list: [] as { target_type: string; provenance_tracking: boolean; availableSettings: string[] }[] }));
vi.mock('../../../../utils/hooks/useEntitySettings', () => ({ default: () => settings.list }));

const CONFLICTS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'has_conflicts', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const setting = (target_type: string, provenance_tracking: boolean, available = true) => ({
  target_type,
  provenance_tracking,
  availableSettings: available ? ['provenance_tracking'] : [],
});

describe('useProvenanceTrackedFilters', () => {
  beforeEach(() => {
    settings.list = [];
  });

  it('keeps the filters as they are when every type is tracked', () => {
    settings.list = [setting('Malware', true), setting('stix-core-relationship', true)];
    const { result } = renderHook(() => useProvenanceTrackedFilters(CONFLICTS));
    expect(result.current).toBe(CONFLICTS);
  });

  it('excludes the types switched off, abstract types included, and ignores the types without the setting', () => {
    settings.list = [setting('Malware', true), setting('stix-core-relationship', false), setting('Attack-Pattern', false), setting('Report', false, false)];
    const { result } = renderHook(() => useProvenanceTrackedFilters(CONFLICTS));
    expect(result.current.filters).toEqual([
      ...CONFLICTS.filters,
      { key: 'entity_type', values: ['Attack-Pattern', 'stix-core-relationship'], operator: 'not_eq', mode: 'and' },
    ]);
  });
});
