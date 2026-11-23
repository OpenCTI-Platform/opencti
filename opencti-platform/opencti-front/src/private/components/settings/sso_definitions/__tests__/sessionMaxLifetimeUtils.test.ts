import { describe, expect, it } from 'vitest';
import { formatSessionMaxLifetime } from '../sessionMaxLifetimeUtils';

// The labels are returned as is, to check which one is used
const t_i18n = (key: string) => key;

describe('formatSessionMaxLifetime', () => {
  it('should show no limit when the lifetime is not set', () => {
    expect(formatSessionMaxLifetime(0, t_i18n)).toBe('Unlimited');
  });

  it('should show the lifetime in the largest unit it is a whole number of', () => {
    expect(formatSessionMaxLifetime(12 * 60 * 60 * 1000, t_i18n)).toBe('12 hours');
    expect(formatSessionMaxLifetime(120000, t_i18n)).toBe('2 minutes');
    expect(formatSessionMaxLifetime(90000, t_i18n)).toBe('90 seconds');
    expect(formatSessionMaxLifetime(10000, t_i18n)).toBe('10 seconds');
  });

  it('should use the singular for a lifetime of one unit', () => {
    expect(formatSessionMaxLifetime(60 * 60 * 1000, t_i18n)).toBe('1 hour');
    expect(formatSessionMaxLifetime(60 * 1000, t_i18n)).toBe('1 minute');
    expect(formatSessionMaxLifetime(1000, t_i18n)).toBe('1 second');
  });

  it('should show a lifetime that is not a whole number of seconds exactly, in seconds', () => {
    expect(formatSessionMaxLifetime(1500, t_i18n)).toBe('1.5 seconds');
  });
});
