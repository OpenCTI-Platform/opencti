import { describe, expect, it } from 'vitest';
import { checkDashboardConfigurationImport } from '../../../../src/modules/dashboard/dashboard-utils';

const NAME_ERROR = 'Invalid dashboard file. The dashboard configuration must have a name';

const buildDashboardFile = (configuration?: Record<string, unknown>) => ({
  type: 'dashboard',
  openCTI_version: '6.9.0',
  ...(configuration ? { configuration } : {}),
});

describe('checkDashboardConfigurationImport, dashboard name', () => {
  it('accepts a dashboard with a name', () => {
    expect(() => checkDashboardConfigurationImport('dashboard', buildDashboardFile({ name: 'My dashboard', manifest: '' }))).not.toThrowError();
  });

  it.each([
    ['no configuration', undefined],
    ['no name', { manifest: '' }],
    ['a null name', { name: null, manifest: '' }],
    ['an empty name', { name: '', manifest: '' }],
    ['a blank name', { name: '   ', manifest: '' }],
    ['a name that is not a string', { name: 42, manifest: '' }],
  ])('rejects a dashboard with %s', (_label, configuration) => {
    expect(() => checkDashboardConfigurationImport('dashboard', buildDashboardFile(configuration))).toThrowError(NAME_ERROR);
  });

  it('keeps the type check before the name check', () => {
    expect(() => checkDashboardConfigurationImport('dashboard', { type: 'widget', openCTI_version: '6.9.0' }))
      .toThrowError('Invalid type. Please import OpenCTI dashboard-type only');
  });

  it('does not require a name on a widget file', () => {
    expect(() => checkDashboardConfigurationImport('widget', { type: 'widget', openCTI_version: '6.9.0' })).not.toThrowError();
  });
});
