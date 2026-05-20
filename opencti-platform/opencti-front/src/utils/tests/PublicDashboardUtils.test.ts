import { describe, it, expect } from 'vitest';

import { generatePublicDashboardUriKey } from '@components/workspaces/dashboards/public_dashboards/public-dashboard-utils';

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe('generatePublicDashboardUriKey', () => {
  it('should convert a Latin name to a lowercase hyphenated slug', () => {
    expect(generatePublicDashboardUriKey('My Dashboard')).toBe('my-dashboard');
  });

  it('should fall back to a UUID v4 when the name contains only non-Latin characters', () => {
    // Japanese name — all characters are stripped by the ASCII-only regex
    const result = generatePublicDashboardUriKey('私のダッシュボード');
    expect(result).toMatch(UUID_V4_REGEX);
  });
});
