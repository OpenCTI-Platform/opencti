import { describe, expect, it } from 'vitest';
import { DASHBOARD_NAME_MAX_LENGTH, dashboardImportSchema } from '../../../../src/modules/workspace/workspace-import-schema';
import { toB64 } from '../../../../src/utils/base64';

const widget = { id: 'widget1', type: 'number', dataSelection: [] };

describe('Dashboard configuration of a bundle (schema)', () => {
  it('accepts a name alone, and every field of an export', () => {
    expect(dashboardImportSchema.safeParse({ name: 'SOC overview' }).success).toBe(true);
    const full = { name: 'SOC overview', description: 'What the SOC watches', tags: ['soc'], refresh_interval: 300, manifest: toB64({ config: {}, widgets: { widget1: widget }, variables: [] }) };
    expect(dashboardImportSchema.parse(full)).toEqual(full);
  });

  it('trims the name as the platform does at indexing, and leaves a field that is null or absent to the dashboard', () => {
    // A dashboard is found by its name: the platform never stores one with spaces around it, so neither does the import look for one
    expect(dashboardImportSchema.parse({ name: '  SOC overview  ' }).name).toBe('SOC overview');
    expect(dashboardImportSchema.parse({ name: 'x' }).name).toBe('x');
    const nulls = dashboardImportSchema.parse({ name: 'SOC overview', description: null, tags: null, refresh_interval: null, manifest: null });
    expect(nulls).toEqual({ name: 'SOC overview', description: null, tags: null, refresh_interval: null, manifest: null });
  });

  it.each([
    ['no name', {}],
    ['an empty name', { name: '' }],
    ['a blank name', { name: '    ' }],
    ['a name over the limit', { name: 'a'.repeat(DASHBOARD_NAME_MAX_LENGTH + 1) }],
    ['a name that is not a string', { name: 42 }],
    ['an unknown key', { name: 'SOC overview', unknown: true }],
    // who can open a dashboard is not part of a bundle, as in the file export
    ['who can open the dashboard', { name: 'SOC overview', shared_with_all: 'view' }],
    ['members', { name: 'SOC overview', restricted_members: [{ id: 'ALL', access_right: 'view' }] }],
    ['a refresh interval that is not an integer', { name: 'SOC overview', refresh_interval: 1.5 }],
    ['a negative refresh interval', { name: 'SOC overview', refresh_interval: -1 }],
    ['tags that are not strings', { name: 'SOC overview', tags: [1] }],
    ['a manifest that is not base64 json', { name: 'SOC overview', manifest: 'not a manifest' }],
    ['a manifest that is not an object', { name: 'SOC overview', manifest: toB64([1]) }],
    ['a widget that is not an object', { name: 'SOC overview', manifest: toB64({ widgets: { widget1: 'text' } }) }],
    ['a widget without data selection', { name: 'SOC overview', manifest: toB64({ widgets: { widget1: { id: 'widget1', type: 'number' } } }) }],
    ['widgets that are a list', { name: 'SOC overview', manifest: toB64({ widgets: [widget] }) }],
    ['variables that are not a list', { name: 'SOC overview', manifest: toB64({ widgets: {}, variables: {} }) }],
  ])('refuses %s', (_label, configuration) => {
    expect(dashboardImportSchema.safeParse(configuration).success).toBe(false);
  });

  it('accepts a name of the limit, and a manifest with no widget', () => {
    expect(dashboardImportSchema.safeParse({ name: 'a'.repeat(DASHBOARD_NAME_MAX_LENGTH) }).success).toBe(true);
    expect(dashboardImportSchema.safeParse({ name: 'ab', manifest: toB64({ config: {} }) }).success).toBe(true);
    expect(dashboardImportSchema.safeParse({ name: 'ab', manifest: '' }).success).toBe(true);
  });
});
