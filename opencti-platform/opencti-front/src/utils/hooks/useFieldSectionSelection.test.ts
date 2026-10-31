import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import useFieldSectionSelection from './useFieldSectionSelection';

describe('Hook: useFieldSectionSelection', () => {
  it('selects the first section instead of every section of a field without a value', () => {
    const { result } = renderHook(() => useFieldSectionSelection(null));
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe(0);
  });

  it('does the same for a field holding an invalid date', () => {
    const { result } = renderHook(() => useFieldSectionSelection(new Date(NaN)));
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe(0);
  });

  it('keeps selecting every section of a field holding a date', () => {
    const { result } = renderHook(() => useFieldSectionSelection(new Date('2023-12-05T00:00:00Z')));
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe('all');
  });

  it('keeps any other selection', () => {
    const { result } = renderHook(() => useFieldSectionSelection(null));
    act(() => result.current.onSelectedSectionsChange(3));
    expect(result.current.selectedSections).toBe(3);
    act(() => result.current.onSelectedSectionsChange(null));
    expect(result.current.selectedSections).toBeNull();
  });
});
