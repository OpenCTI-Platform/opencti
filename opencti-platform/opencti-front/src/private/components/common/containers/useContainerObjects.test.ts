import { describe, expect, it } from 'vitest';
import { belongsToObjectList } from './useContainerObjects';

describe('belongsToObjectList', () => {
  it('keeps an object whose type is one of the list types', () => {
    expect(belongsToObjectList({ types: ['Stix-Cyber-Observable'] }, ['IPv4-Addr', 'Stix-Cyber-Observable'])).toBe(true);
  });

  it('leaves out an object of another type', () => {
    expect(belongsToObjectList({ types: ['Stix-Cyber-Observable'] }, ['Indicator', 'Stix-Domain-Object'])).toBe(false);
  });

  it('keeps any object when the list has no types', () => {
    expect(belongsToObjectList({}, ['Indicator'])).toBe(true);
    expect(belongsToObjectList(undefined, ['Indicator'])).toBe(true);
  });

  it('keeps the object when its types are unknown', () => {
    expect(belongsToObjectList({ types: ['Stix-Cyber-Observable'] }, undefined)).toBe(true);
  });
});
