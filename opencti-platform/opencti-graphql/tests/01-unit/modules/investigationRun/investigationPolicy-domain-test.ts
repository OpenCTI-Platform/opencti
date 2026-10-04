import { describe, expect, it } from 'vitest';
import { sanitizePackOptions } from '../../../../src/modules/investigationRun/investigationPolicy-domain';

describe('Case Autopilot pack options of a policy', () => {
  it('keeps short string choices, from an object or its JSON', () => {
    expect(sanitizePackOptions({ leads: 'off' })).toEqual({ leads: 'off' });
    expect(sanitizePackOptions('{"leads":"on"}')).toEqual({ leads: 'on' });
    expect(sanitizePackOptions({})).toBeNull();
    expect(sanitizePackOptions(null)).toBeNull();
    expect(sanitizePackOptions('')).toBeNull();
  });

  it('refuses what is not a map of short strings', () => {
    expect(() => sanitizePackOptions('not json')).toThrow('Pack options map an option to a value');
    expect(() => sanitizePackOptions(['leads'])).toThrow('Pack options map an option to a value');
    expect(() => sanitizePackOptions({ leads: 1 })).toThrow('Invalid pack option');
    expect(() => sanitizePackOptions({ leads: 'x'.repeat(500) })).toThrow('Invalid pack option');
    const many = Object.fromEntries(Array.from({ length: 100 }, (_, index) => [`option_${index}`, 'on']));
    expect(() => sanitizePackOptions(many)).toThrow('Too many pack options');
  });
});
