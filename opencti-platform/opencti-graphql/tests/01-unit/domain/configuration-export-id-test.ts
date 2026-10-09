import { describe, expect, it, vi } from 'vitest';
import { playbookExport } from '../../../src/modules/playbook/playbook-domain';
import { generateFormExportConfiguration } from '../../../src/modules/form/form-domain';
import { generateWorkspaceExportConfiguration } from '../../../src/modules/workspace/workspace-domain';
import { fintelTemplateExport } from '../../../src/modules/fintelTemplate/fintelTemplate-domain';
import * as workspaceUtils from '../../../src/modules/workspace/workspace-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

vi.mock('../../../src/modules/dashboard/dashboard-utils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/modules/dashboard/dashboard-utils')>();
  return { ...actual, convertDashboardManifestIds: vi.fn(async (_context, _user, manifest) => manifest) };
});

// The export_id is exported next to the configuration.
describe('Configuration export export_id', () => {
  it('should export the export_id of a playbook', async () => {
    const exported = JSON.parse(await playbookExport({ name: 'Playbook', export_id: 'playbook-export-id' } as never));
    expect(exported.export_id).toBe('playbook-export-id');
    expect(exported.configuration.export_id).toBeUndefined();
  });

  it('should export the export_id of a form', async () => {
    const exported = JSON.parse(await generateFormExportConfiguration({ name: 'Form', export_id: 'form-export-id' } as never));
    expect(exported.export_id).toBe('form-export-id');
    expect(exported.configuration.export_id).toBeUndefined();
  });

  it('should export the export_id of a dashboard', async () => {
    const dashboard = { type: 'dashboard', name: 'Dashboard', manifest: 'e30=', export_id: 'dashboard-export-id' };
    const exported = JSON.parse(await generateWorkspaceExportConfiguration(testContext, ADMIN_USER, dashboard as never));
    expect(exported.export_id).toBe('dashboard-export-id');
    expect(exported.configuration.export_id).toBeUndefined();
  });

  it('should export the export_id of a fintel template', async () => {
    vi.spyOn(workspaceUtils, 'convertWidgetsIds').mockResolvedValue(undefined);
    const template = { name: 'Template', settings_types: ['Report'], fintel_template_widgets: [], export_id: 'template-export-id' };
    const exported = JSON.parse(await fintelTemplateExport(testContext, ADMIN_USER, template as never));
    expect(exported.export_id).toBe('template-export-id');
    expect(exported.configuration.export_id).toBeUndefined();
  });
});
