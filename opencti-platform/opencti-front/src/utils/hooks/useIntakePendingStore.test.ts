import { describe, expect, it } from 'vitest';
import { renderHook } from '@testing-library/react';
import useIntakePendingStore from './useIntakePendingStore';
import { PENDING_ENTITY_PREFIX } from './useDeferredCreation';

describe('useIntakePendingStore', () => {
  it('is always in deferred mode', () => {
    const { result } = renderHook(() => useIntakePendingStore());
    expect(result.current.isDeferredMode).toBe(true);
  });

  it('keeps registered objects under unique pending ids', () => {
    const { result } = renderHook(() => useIntakePendingStore());
    const label = { entityType: 'Label', input: { value: 'new-label', color: '#fff' } };
    const reference = { entityType: 'External-Reference', input: { source_name: 'src' } };

    const labelId = result.current.registerPending(label);
    const referenceId = result.current.registerPending(reference);

    expect(labelId.startsWith(PENDING_ENTITY_PREFIX)).toBe(true);
    expect(labelId).not.toBe(referenceId);
    expect(result.current.getPending(labelId)).toEqual(label);
    expect(result.current.getPending(referenceId)).toEqual(reference);
    expect(result.current.getPending('unknown')).toBeUndefined();
  });

  it('keeps the same store across renders', () => {
    const { result, rerender } = renderHook(() => useIntakePendingStore());
    const id = result.current.registerPending({ entityType: 'Label', input: { value: 'a' } });
    rerender();
    expect(result.current.getPending(id)).toBeDefined();
  });
});
