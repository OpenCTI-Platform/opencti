import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import useRuntimeSortGuard, { FALLBACK_SORT_FIELD, RUNTIME_ONLY_SORT_FIELDS } from './useRuntimeSortGuard';

describe('Hook: useRuntimeSortGuard', () => {
  let handleSort: ReturnType<typeof vi.fn<(field: string, orderAsc: boolean) => void>>;

  beforeEach(() => {
    handleSort = vi.fn<(field: string, orderAsc: boolean) => void>();
  });

  it('should call handleSort with fallback when runtime is disabled and sortBy is a runtime-only field (createdBy)', () => {
    renderHook(() => useRuntimeSortGuard(false, 'createdBy', handleSort));

    expect(handleSort).toHaveBeenCalledOnce();
    expect(handleSort).toHaveBeenCalledWith(FALLBACK_SORT_FIELD, false);
  });

  it('should call handleSort with fallback when runtime is disabled and sortBy is a runtime-only field (objectAssignee)', () => {
    renderHook(() => useRuntimeSortGuard(false, 'objectAssignee', handleSort));

    expect(handleSort).toHaveBeenCalledOnce();
    expect(handleSort).toHaveBeenCalledWith(FALLBACK_SORT_FIELD, false);
  });

  it('should NOT call handleSort when runtime is disabled but sortBy is a standard field', () => {
    renderHook(() => useRuntimeSortGuard(false, 'name', handleSort));

    expect(handleSort).not.toHaveBeenCalled();
  });

  it('should NOT call handleSort when runtime is disabled and sortBy is undefined', () => {
    renderHook(() => useRuntimeSortGuard(false, undefined, handleSort));

    expect(handleSort).not.toHaveBeenCalled();
  });

  it('should NOT call handleSort when runtime is enabled and sortBy is a runtime-only field', () => {
    renderHook(() => useRuntimeSortGuard(true, 'objectParticipant', handleSort));

    expect(handleSort).not.toHaveBeenCalled();
  });

  it('should call handleSort when isRuntimeSort switches from true to false with a runtime-only sortBy', () => {
    let isRuntimeSort = true;
    const sortBy = 'objectParticipant';

    const { rerender } = renderHook(() => useRuntimeSortGuard(isRuntimeSort, sortBy, handleSort));

    expect(handleSort).not.toHaveBeenCalled();

    act(() => {
      isRuntimeSort = false;
      rerender();
    });

    expect(handleSort).toHaveBeenCalledOnce();
    expect(handleSort).toHaveBeenCalledWith(FALLBACK_SORT_FIELD, false);
  });

  it('should contain the minimum fields required for the draft page to work on OpenSearch (createdBy, objectAssignee, objectParticipant)', () => {
    // These 3 fields are used as sort columns on the draft page.
    // They rely on ElasticSearch runtime mappings and MUST remain in this list
    // to prevent UnsupportedError on OpenSearch instances.
    expect(RUNTIME_ONLY_SORT_FIELDS).toContain('createdBy');
    expect(RUNTIME_ONLY_SORT_FIELDS).toContain('objectAssignee');
    expect(RUNTIME_ONLY_SORT_FIELDS).toContain('objectParticipant');
  });

  it('FALLBACK_SORT_FIELD should be created_at', () => {
    expect(FALLBACK_SORT_FIELD).toBe('created_at');
  });
});
