import { describe, it, expect } from 'vitest';
import { isChangeBlocked } from './filterEntityValueActions';

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
