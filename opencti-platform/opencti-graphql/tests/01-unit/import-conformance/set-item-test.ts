import { describe, expect, it } from 'vitest';
import { setItem } from '../../../src/intake/stix-import/utils';

// pycti `container[key] = value` on a dict: an own key, "__proto__" included (a plain key in Python)
describe('setItem: pycti container[key] = value', () => {
  it('should write an own key, an existing one keeping its place', () => {
    const container: Record<string, unknown> = JSON.parse('{"a": 1, "b": 2}');
    setItem(container, 'a', 3);
    setItem(container, 'c', 4);
    expect(Object.entries(container)).toEqual([['a', 3], ['b', 2], ['c', 4]]);
  });

  it('should write "__proto__" as an own key, not as the prototype', () => {
    const container = JSON.parse('{"type": "text"}');
    setItem(container, '__proto__', { value: 'evil' });
    expect(Object.getPrototypeOf(container)).toBe(Object.prototype);
    expect(Object.keys(container)).toEqual(['type', '__proto__']);
    expect(Object.getOwnPropertyDescriptor(container, '__proto__')?.value).toEqual({ value: 'evil' });
  });
});
