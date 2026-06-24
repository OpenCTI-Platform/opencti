import { describe, expect, it } from 'vitest';
import { sanitizePublicDashboardUriKey } from '../../../../src/modules/publicDashboard/publicDashboard-utils';

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe('sanitizePublicDashboardUriKey', () => {
  it('should convert a Latin name to a lowercase hyphenated slug', () => {
    expect(sanitizePublicDashboardUriKey('My Dashboard')).toBe('my-dashboard');
  });

  it('should fall back to a UUID v4 when the input contains only non-Latin characters', () => {
    // Japanese name — all characters are stripped by the ASCII-only regex
    const result = sanitizePublicDashboardUriKey('私のダッシュボード');
    expect(result).toMatch(UUID_V4_REGEX);
  });
});
