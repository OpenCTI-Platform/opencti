import { describe, it, expect, vi } from 'vitest';
import { applyValueChange, isChangeBlocked } from './filterEntityValueActions';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';

describe('isChangeBlocked', () => {
  it('blocks clearing the sole value when disabled, same as removing it', () => {
    expect(isChangeBlocked({ type: 'clear' }, ['relationship-type-id'], true)).toBe(true);
    expect(isChangeBlocked({ type: 'remove', value: 'relationship-type-id' }, ['relationship-type-id'], true)).toBe(true);
  });

  it('does not block clear when there are several values or the field is not disabled', () => {
    expect(isChangeBlocked({ type: 'clear' }, ['a', 'b'], true)).toBe(false);
    expect(isChangeBlocked({ type: 'clear' }, ['relationship-type-id'], false)).toBe(false);
  });
});

describe('applyValueChange on a sub-filter', () => {
  it('keeps the operator of a sub-filter when its values change', () => {
    const helpers = { handleChangeRepresentationFilter: vi.fn() } as unknown as handleFilterHelpers;
    const child = { key: 'coverage_name', operator: 'not_eq', values: ['detection'] };
    const filter = { id: 'f1', key: 'coverage_information', operator: 'eq', mode: 'and', values: [child] } as Filter;
    applyValueChange({ type: 'add', value: 'prevention' }, { helpers, filter, subKey: 'coverage_name' });
    expect(helpers.handleChangeRepresentationFilter).toHaveBeenCalledWith('f1', child, { key: 'coverage_name', operator: 'not_eq', values: ['detection', 'prevention'] });
  });
});
