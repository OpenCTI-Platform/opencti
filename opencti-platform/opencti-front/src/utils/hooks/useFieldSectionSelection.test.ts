import React from 'react';
import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { FieldRef } from '@mui/x-date-pickers/models';
import useFieldSectionSelection from './useFieldSectionSelection';

// The hook only reads the value of each section.
const renderWithSections = (...values: string[]) => {
  const rendered = renderHook(() => useFieldSectionSelection());
  rendered.result.current.fieldProps.fieldRef.current = {
    getSections: () => values.map((value) => ({ value })),
  } as unknown as FieldRef<Date | null>;
  return { ...rendered, values };
};

describe('Hook: useFieldSectionSelection', () => {
  it('selects the first section instead of every section of an empty field', () => {
    const { result } = renderWithSections('', '', '');
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe(0);
  });

  it('keeps selecting every section of a partly typed field', () => {
    const { result } = renderWithSections('2023', '12', '');
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe('all');
  });

  it('keeps selecting every section of a field holding a date', () => {
    const { result } = renderWithSections('2023', '12', '05');
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe('all');
  });

  it('selects the first section once a field with every section selected has been emptied', () => {
    // Ctrl+A then Backspace: the picker selects every section before the sections are emptied.
    const { result, rerender, values } = renderWithSections('2023', '12', '05');
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe('all');
    values.fill('');
    rerender();
    expect(result.current.selectedSections).toBe(0);
  });

  it('selects the first section once a partly typed field has been emptied, though its value did not change', () => {
    // A partly typed field already has a null value: emptying it renders the picker again only
    // through the selection the picker requests, every section again.
    const { result, values } = renderWithSections('2023', '12', '');
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe('all');
    act(() => {
      result.current.onSelectedSectionsChange('all');
      values.fill('');
    });
    expect(result.current.selectedSections).toBe(0);
  });

  it('selects the first section once a partly typed field has been emptied with Delete', () => {
    // Delete requests no selection: the hook renders the picker again by itself.
    const { result, values } = renderWithSections('2023', '12', '');
    act(() => result.current.onSelectedSectionsChange('all'));
    act(() => {
      result.current.fieldProps.onKeyDown({ key: 'Delete' } as React.KeyboardEvent);
      values.fill('');
    });
    expect(result.current.selectedSections).toBe(0);
  });

  it('calls the onKeyDown it is given', () => {
    const onKeyDown = vi.fn();
    const { result } = renderHook(() => useFieldSectionSelection(onKeyDown));
    const event = { key: 'Delete' } as React.KeyboardEvent;
    act(() => result.current.fieldProps.onKeyDown(event));
    expect(onKeyDown).toHaveBeenCalledWith(event);
  });

  it('keeps selecting every section while the field is not mounted', () => {
    const { result } = renderHook(() => useFieldSectionSelection());
    act(() => result.current.onSelectedSectionsChange('all'));
    expect(result.current.selectedSections).toBe('all');
  });

  it('keeps any other selection', () => {
    const { result } = renderWithSections('', '', '');
    act(() => result.current.onSelectedSectionsChange(3));
    expect(result.current.selectedSections).toBe(3);
    act(() => result.current.onSelectedSectionsChange(null));
    expect(result.current.selectedSections).toBeNull();
  });
});
