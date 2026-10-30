import { afterEach, describe, expect, it } from 'vitest';
import { getBreakdownEntityTypes, getServedPublicManifest, sanitizePublicDashboardUriKey } from '../../../../src/modules/publicDashboard/publicDashboard-utils';
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

describe('getBreakdownEntityTypes', () => {
  const typeFilter = (values: string[], overrides: Record<string, unknown> = {}) => ({ key: ['entity_type'], values, operator: 'eq', mode: 'or', ...overrides });
  const notRevoked = { key: ['revoked'], values: ['false'], operator: 'eq', mode: 'or' };
  const group = (filters: unknown[], overrides: Record<string, unknown> = {}) => ({ mode: 'and', filters, filterGroups: [], ...overrides }) as any;

  it('should read the types of a top level type filter, whatever the form of its key', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report', 'Malware']), notRevoked]))).toEqual(['Report', 'Malware']);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { key: 'entity_type' })]))).toEqual(['Report']);
    // The relationship type of the relationships
    const targets = typeFilter(['targets'], { key: ['relationship_type'] });
    expect(getBreakdownEntityTypes(group([targets]), 'relationship_type')).toEqual(['targets']);
    expect(getBreakdownEntityTypes(group([targets]))).toEqual([]);
  });

  it('should not restrict the types of a group in "or" with several entries', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report']), notRevoked], { mode: 'or' }))).toEqual([]);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'])], { mode: 'or', filterGroups: [group([notRevoked])] }))).toEqual([]);
    // A single entry restricts the types whatever the mode of its group
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'])], { mode: 'or' }))).toEqual(['Report']);
  });

  it('should not restrict the types of a type filter excluding them', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { operator: 'not_eq' })]))).toEqual([]);
    // Without operator, a filter is an equality
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { operator: undefined })]))).toEqual(['Report']);
  });

  it('should only read several types in "and" as no restriction, a single one restricts the type', () => {
    // Elements of every type at once
    expect(getBreakdownEntityTypes(group([typeFilter(['Report', 'Malware'], { mode: 'and' })]))).toEqual([]);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { mode: 'and' })]))).toEqual(['Report']);
  });

  it('should read the stored filters missing a key', () => {
    expect(getBreakdownEntityTypes({ mode: 'and', filters: [typeFilter(['Report'])] } as any)).toEqual(['Report']);
    expect(getBreakdownEntityTypes({ mode: 'or', filters: [typeFilter(['Report'])] } as any)).toEqual(['Report']);
    expect(getBreakdownEntityTypes({ mode: 'and', filterGroups: [] } as any)).toEqual([]);
    expect(getBreakdownEntityTypes({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', mode: 'or' }] } as any)).toEqual([]);
    expect(getBreakdownEntityTypes(null)).toEqual([]);
  });
});
