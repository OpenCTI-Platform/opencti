import { afterEach, describe, expect, it } from 'vitest';
import { getServedPublicManifest, sanitizePublicDashboardUriKey } from '../../../../src/modules/publicDashboard/publicDashboard-utils';
import { ENABLED_FEATURE_FLAGS, TIME_SERIES_BREAKDOWN_FEATURE_FLAG } from '../../../../src/config/conf';
import { fromB64, toB64 } from '../../../../src/utils/base64';

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

describe('getServedPublicManifest', () => {
  const previousEnabledFeatureFlags = [...ENABLED_FEATURE_FLAGS];
  const breakdown = { breakdownBy: 'objectLabel', breakdownLimit: 5, breakdownOrder: 'asc', breakdownOther: true };
  const manifest = toB64({
    widgets: {
      'widget-1': { type: 'vertical-bar', perspective: 'entities', parameters: { title: 'Reports', interval: 'week', ...breakdown } },
      'widget-2': { type: 'donut', perspective: 'entities', parameters: { title: 'Donut' } },
      'widget-3': { type: 'text' },
    },
    config: { refresh_interval: 0 },
  }) as string;

  afterEach(() => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousEnabledFeatureFlags);
  });

  it('should serve the stored manifest with the time series breakdown flag', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, TIME_SERIES_BREAKDOWN_FEATURE_FLAG);
    expect(getServedPublicManifest(manifest)).toBe(manifest);
  });

  it('should serve the widgets without their breakdown without the flag, keeping everything else', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    expect(fromB64(getServedPublicManifest(manifest) as string)).toEqual({
      widgets: {
        'widget-1': { type: 'vertical-bar', perspective: 'entities', parameters: { title: 'Reports', interval: 'week' } },
        'widget-2': { type: 'donut', perspective: 'entities', parameters: { title: 'Donut' } },
        'widget-3': { type: 'text' },
      },
      config: { refresh_interval: 0 },
    });
  });

  it('should serve a manifest without breakdown as it is stored, without the flag', () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    const withoutBreakdown = toB64({ widgets: { 'widget-2': { type: 'donut', parameters: { title: 'Donut' } } } }) as string;
    expect(getServedPublicManifest(withoutBreakdown)).toBe(withoutBreakdown);
    expect(getServedPublicManifest(null)).toBeNull();
  });
});
