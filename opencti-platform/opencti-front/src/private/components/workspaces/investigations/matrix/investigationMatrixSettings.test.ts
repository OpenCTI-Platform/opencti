import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import {
  DEFAULT_INVESTIGATION_MATRIX_SETTINGS,
  matrixFiltersStorageKey,
  readMatrixFilters,
  useInvestigationMatrixFilters,
  useInvestigationMatrixSettings,
} from './investigationMatrixSettings';
import { DEFAULT_MATRIX_FILTERS } from './matrixFilters';

const PLATFORM = { value: 'platform-1', label: 'EDR', type: 'SecurityPlatform' };

describe('useInvestigationMatrixSettings', () => {
  it('starts from the defaults', () => {
    const { result } = renderHook(() => useInvestigationMatrixSettings('investigation-a'));
    expect(result.current[0]).toEqual(DEFAULT_INVESTIGATION_MATRIX_SETTINGS);
  });

  it('merges each change into the settings', () => {
    const { result } = renderHook(() => useInvestigationMatrixSettings('investigation-a'));
    act(() => result.current[1]({ heatmap: true }));
    act(() => result.current[1]({ killChain: 'mitre-attack', securityPlatforms: [PLATFORM] }));
    expect(result.current[0]).toEqual({ killChain: 'mitre-attack', onlyUsed: false, heatmap: true, securityPlatforms: [PLATFORM] });
  });

  it('gives another investigation the defaults, not the settings of the previous one', () => {
    const { result, rerender } = renderHook(({ id }) => useInvestigationMatrixSettings(id), { initialProps: { id: 'investigation-a' } });
    act(() => result.current[1]({ heatmap: true, onlyUsed: true, securityPlatforms: [PLATFORM] }));

    rerender({ id: 'investigation-b' });
    expect(result.current[0]).toEqual(DEFAULT_INVESTIGATION_MATRIX_SETTINGS);

    // A change on the new investigation starts from its defaults too.
    act(() => result.current[1]({ killChain: 'other-chain' }));
    expect(result.current[0]).toEqual({ ...DEFAULT_INVESTIGATION_MATRIX_SETTINGS, killChain: 'other-chain' });
  });
});

describe('useInvestigationMatrixFilters', () => {
  const store = (id: string, value: unknown) => localStorage.setItem(matrixFiltersStorageKey(id), typeof value === 'string' ? value : JSON.stringify(value));
  const stored = (id: string) => localStorage.getItem(matrixFiltersStorageKey(id));

  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('starts from the stored filters of the investigation and saves each change', () => {
    store('investigation-a', { disabledEntityTypes: ['Malware'], disabledRelationshipTypes: ['uses'], timeRange: ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z'] });
    const { result } = renderHook(() => useInvestigationMatrixFilters('investigation-a'));
    expect(result.current[0]).toEqual({
      disabledEntityTypes: ['Malware'],
      disabledRelationshipTypes: ['uses'],
      disabledMarkings: [],
      disabledCreators: [],
      timeRange: ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z'],
    });

    // Two changes before a render keep both.
    act(() => {
      result.current[1]({ disabledMarkings: ['marking-1'] });
      result.current[1]({ disabledCreators: ['author-1'] });
    });
    expect(result.current[0].disabledMarkings).toEqual(['marking-1']);
    expect(result.current[0].disabledCreators).toEqual(['author-1']);
    expect(JSON.parse(stored('investigation-a') as string)).toEqual(result.current[0]);
  });

  it('loads defaults from malformed or partial storage', () => {
    store('investigation-a', '{');
    expect(readMatrixFilters('investigation-a')).toEqual(DEFAULT_MATRIX_FILTERS);
    store('investigation-a', '[]');
    expect(readMatrixFilters('investigation-a')).toEqual(DEFAULT_MATRIX_FILTERS);
    store('investigation-a', 'null');
    expect(readMatrixFilters('investigation-a')).toEqual(DEFAULT_MATRIX_FILTERS);
    store('investigation-a', { disabledMarkings: 'x' });
    expect(readMatrixFilters('investigation-a')).toEqual(DEFAULT_MATRIX_FILTERS);
    store('investigation-a', { disabledEntityTypes: ['Malware', 3, null], disabledRelationshipTypes: ['uses', 'targets', 4], disabledCreators: { a: 1 } });
    expect(readMatrixFilters('investigation-a')).toEqual({ ...DEFAULT_MATRIX_FILTERS, disabledEntityTypes: ['Malware'], disabledRelationshipTypes: ['uses'] });

    // Equal bounds are a valid range.
    store('investigation-a', { timeRange: ['2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z'] });
    expect(readMatrixFilters('investigation-a').timeRange).toEqual(['2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z']);

    const invalidRanges = [
      ['bad'],
      'bad',
      ['bad', '2024-02-01T00:00:00.000Z'],
      ['2024-01-01T00:00:00.000Z', 'bad'],
      ['2024-01-01T00:00:00.000Z', 12],
      ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z', '2024-03-01T00:00:00.000Z'],
      ['2024-02-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z'],
    ];
    invalidRanges.forEach((timeRange) => {
      store('investigation-a', { timeRange });
      expect(readMatrixFilters('investigation-a')).toEqual(DEFAULT_MATRIX_FILTERS);
    });
    expect(readMatrixFilters('investigation-without-storage')).toEqual(DEFAULT_MATRIX_FILTERS);
  });

  it('falls back to the defaults and keeps working when storage throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('full');
    });
    const { result } = renderHook(() => useInvestigationMatrixFilters('investigation-a'));
    expect(result.current[0]).toEqual(DEFAULT_MATRIX_FILTERS);
    act(() => result.current[1]({ disabledEntityTypes: ['Malware'] }));
    expect(result.current[0].disabledEntityTypes).toEqual(['Malware']);
  });

  it('clears every filter and the stored copy', () => {
    store('investigation-a', { disabledEntityTypes: ['Malware'], timeRange: ['2024-01-01T00:00:00.000Z', '2024-02-01T00:00:00.000Z'] });
    const { result } = renderHook(() => useInvestigationMatrixFilters('investigation-a'));
    act(() => result.current[2]());
    expect(result.current[0]).toEqual(DEFAULT_MATRIX_FILTERS);
    expect(stored('investigation-a')).toBeNull();
  });
});
