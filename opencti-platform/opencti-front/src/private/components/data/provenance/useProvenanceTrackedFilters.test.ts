import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useProvenanceTrackedFilters from './useProvenanceTrackedFilters';

interface SettingMock {
  target_type: string;
  provenance_untracked_types: string[];
  availableSettings: string[];
}

const settings = vi.hoisted(() => ({ list: [] as SettingMock[] }));
vi.mock('../../../../utils/hooks/useEntitySettings', () => ({ default: () => settings.list }));

const CONFLICTS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'has_conflicts', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const setting = (target_type: string, untracked: string[], available = true): SettingMock => ({
  target_type,
  provenance_untracked_types: untracked,
  availableSettings: available ? ['provenance_tracking'] : [],
});

describe('useProvenanceTrackedFilters', () => {
  beforeEach(() => {
    settings.list = [];
  });

  it('keeps the filters as they are when every type is tracked', () => {
    settings.list = [setting('Malware', []), setting('stix-core-relationship', [])];
    const { result } = renderHook(() => useProvenanceTrackedFilters(CONFLICTS));
    expect(result.current).toBe(CONFLICTS);
  });

  it('excludes every untracked type, inheriting concrete types included, and ignores the types without the setting', () => {
    settings.list = [
      setting('Malware', []),
      setting('Attack-Pattern', ['Attack-Pattern']),
      setting('stix-core-relationship', ['targets', 'located-at']),
      setting('Report', ['Report'], false),
    ];
    const { result } = renderHook(() => useProvenanceTrackedFilters(CONFLICTS));
    expect(result.current.filters).toEqual([
      ...CONFLICTS.filters,
      { key: 'entity_type', values: ['Attack-Pattern', 'located-at', 'targets'], operator: 'not_eq', mode: 'and' },
    ]);
  });
});
