import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createEntity } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { addCapability } from '../../../src/domain/grant';
import { addSettings } from '../../../src/domain/settings';
import { initFintelTemplates } from '../../../src/modules/fintelTemplate/fintelTemplate-domain';
import { initManagerConfigurations } from '../../../src/modules/managerConfiguration/managerConfiguration-domain';
import { initDefaultNotifiers } from '../../../src/modules/notifier/notifier-domain';
import { generateBuiltInExportId } from '../../../src/schema/identifier';
import { SYSTEM_USER } from '../../../src/utils/access';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(async (_context, _user, input, type) => ({ id: `${type}-id`, entity_type: type, ...input })),
}));
vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(async (_topic, element) => element),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

const context = { source: 'testing' } as any;
const createdInputs = (entityType: string) => vi.mocked(createEntity).mock.calls
  .filter(([, , , type]) => type === entityType)
  .map(([, , input]) => input as any);

describe('Built-in entities creation export_id', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create a capability with an export_id based on its name', async () => {
    await addCapability(context, SYSTEM_USER, { name: 'KNOWLEDGE_KNUPDATE', description: 'Create / Update knowledge' });
    expect(createdInputs('Capability')).toEqual([{
      name: 'KNOWLEDGE_KNUPDATE',
      description: 'Create / Update knowledge',
      export_id: generateBuiltInExportId('Capability', { name: 'KNOWLEDGE_KNUPDATE' }),
    }]);
  });

  it('should create the settings with the same export_id on every platform', async () => {
    await addSettings(context, SYSTEM_USER, { platform_title: 'OpenCTI' });
    expect(createdInputs('Settings')).toEqual([{ platform_title: 'OpenCTI', export_id: 'ee5aa991-1ed8-575f-908b-7bf19359e086' }]);
  });

  it('should create the default notifiers with an export_id based on their name', async () => {
    await initDefaultNotifiers(context);
    const notifiers = createdInputs('Notifier');
    expect(notifiers.map(({ name, export_id }) => [name, export_id])).toEqual([
      'Sample of Microsoft Teams message for live trigger',
      'Sample of Microsoft Teams message for digest trigger',
    ].map((name) => [name, generateBuiltInExportId('Notifier', { name })]));
  });

  it('should create the missing manager configurations with an export_id based on the manager', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([]);
    await initManagerConfigurations(context, SYSTEM_USER);
    const managerConfigurations = createdInputs('ManagerConfiguration');
    expect(managerConfigurations.map(({ manager_id, export_id }) => [manager_id, export_id])).toEqual([
      ['FILE_INDEX_MANAGER', generateBuiltInExportId('ManagerConfiguration', { manager_id: 'FILE_INDEX_MANAGER' })],
    ]);
  });

  it('should not recreate an existing manager configuration', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([{ manager_id: 'FILE_INDEX_MANAGER' }] as any);
    await initManagerConfigurations(context, SYSTEM_USER);
    expect(createdInputs('ManagerConfiguration')).toEqual([]);
  });

  it('should create the built-in fintel templates with an export_id based on their name and target type', async () => {
    await initFintelTemplates(context, SYSTEM_USER);
    const templates = createdInputs('FintelTemplate');
    expect(templates.map(({ name, settings_types, export_id }) => [name, settings_types[0], export_id])).toEqual([
      ['Executive Summary', 'Report'],
      ['Executive Summary', 'Grouping'],
      ['Incident Response Report', 'Case-Incident'],
      ['Executive Summary', 'Case-Incident'],
      ['Executive Summary', 'Case-Rfi'],
      ['Executive Summary', 'Case-Rft'],
    ].map(([name, target_type]) => [name, target_type, generateBuiltInExportId('FintelTemplate', { name, target_type })]));
  });
});
