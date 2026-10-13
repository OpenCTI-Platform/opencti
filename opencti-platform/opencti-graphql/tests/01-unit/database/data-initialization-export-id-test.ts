import { beforeEach, describe, expect, it, vi } from 'vitest';
import { initializeData } from '../../../src/database/data-initialization';
import { DEFAULT_EMAIL_TEMPLATE_INPUT } from '../../../src/database/default-email-template-input';
import { updateAttribute } from '../../../src/database/middleware';
import { addGroup, addRole } from '../../../src/domain/grant';
import { addAllowedMarkingDefinition } from '../../../src/domain/markingDefinition';
import { createStatus, createStatusTemplate } from '../../../src/domain/status';
import { addEmailTemplate } from '../../../src/modules/emailTemplate/emailTemplate-domain';
import { addVocabulary } from '../../../src/modules/vocabulary/vocabulary-domain';
import { createRetentionRule } from '../../../src/modules/retentionRules/retentionRules-domain';
import { generateBuiltInExportId } from '../../../src/schema/identifier';

vi.mock('../../../src/domain/settings', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  addSettings: vi.fn(),
}));
vi.mock('../../../src/modules/theme/theme-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  initDefaultTheme: vi.fn().mockResolvedValue({ id: 'dark-theme-id' }),
}));
vi.mock('../../../src/modules/entitySetting/entitySetting-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  initCreateEntitySettings: vi.fn(),
  findByType: vi.fn().mockResolvedValue({ id: 'rfi-entity-setting-id' }),
}));
vi.mock('../../../src/modules/managerConfiguration/managerConfiguration-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  initManagerConfigurations: vi.fn(),
}));
vi.mock('../../../src/modules/decayRule/decayRule-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  initDecayRules: vi.fn(),
}));
vi.mock('../../../src/domain/status', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  createStatusTemplate: vi.fn(async (_context, _user, input) => ({ id: `template-${input.name}`, ...input })),
  createStatus: vi.fn(async (_context, _user, type, input) => ({ id: `status-${type}-${input.template_id}`, ...input })),
}));
vi.mock('../../../src/domain/grant', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  addCapability: vi.fn(),
  addRole: vi.fn(async (_context, _user, input) => ({ id: `role-${input.name}` })),
  addGroup: vi.fn(async (_context, _user, input) => ({ id: `group-${input.name}` })),
}));
vi.mock('../../../src/domain/group', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  groupAddRelation: vi.fn(),
}));
vi.mock('../../../src/modules/vocabulary/vocabulary-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  addVocabulary: vi.fn(),
}));
vi.mock('../../../src/modules/emailTemplate/emailTemplate-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  addEmailTemplate: vi.fn(),
}));
vi.mock('../../../src/modules/retentionRules/retentionRules-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  createRetentionRule: vi.fn(),
}));
vi.mock('../../../src/domain/markingDefinition', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  addAllowedMarkingDefinition: vi.fn(),
}));
vi.mock('../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  updateAttribute: vi.fn(),
}));

const inputsOf = (fn: any, inputIndex: number): any[] => vi.mocked(fn).mock.calls.map((call: any[]) => call[inputIndex]);

describe('Data initialization export_id', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    await initializeData({ source: 'testing' } as any, true);
  });

  it('should create the built-in markings, statuses and retention rules without export_id', () => {
    // Their existing key is enough to find them on another platform, or they are not exported
    const markings = inputsOf(addAllowedMarkingDefinition, 2);
    const templates = inputsOf(createStatusTemplate, 2);
    const statuses = inputsOf(createStatus, 3);
    const retentionRules = inputsOf(createRetentionRule, 2);
    expect(markings).toHaveLength(9);
    expect(templates).toHaveLength(8);
    expect(statuses).toHaveLength(7);
    expect(retentionRules).toHaveLength(4);
    [...markings, ...templates, ...statuses, ...retentionRules].forEach((input) => {
      expect(input.export_id).toBeUndefined();
    });
  });

  it('should keep the request access workflow pointing to the built-in statuses', () => {
    expect(updateAttribute).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'rfi-entity-setting-id', 'EntitySetting', [
      {
        key: 'request_access_workflow',
        value: [{ approved_workflow_id: 'status-Case-Rfi-template-APPROVED', declined_workflow_id: 'status-Case-Rfi-template-DECLINED' }],
      },
    ]);
  });

  it('should create the built-in roles and groups with their export_id', () => {
    const roles = inputsOf(addRole, 2);
    expect(roles.map(({ name, export_id }) => [name, export_id])).toEqual(
      ['Default', 'Administrator', 'Connector'].map((name) => [name, generateBuiltInExportId('Role', { name })]),
    );
    const groups = inputsOf(addGroup, 2);
    expect(groups.map(({ name, export_id }) => [name, export_id])).toEqual(
      ['Default', 'Administrators', 'Connectors'].map((name) => [name, generateBuiltInExportId('Group', { name })]),
    );
    expect(groups.find((g) => g.name === 'Administrators').export_id).toEqual('d8281c40-c3c8-5cd8-910f-aa3259e92453');
  });

  it('should create the built-in email template with its export_id', () => {
    const [emailTemplate] = inputsOf(addEmailTemplate, 2);
    expect(emailTemplate).toEqual({
      ...DEFAULT_EMAIL_TEMPLATE_INPUT,
      export_id: generateBuiltInExportId('EmailTemplate', { name: DEFAULT_EMAIL_TEMPLATE_INPUT.name }),
    });
  });

  it('should create every built-in vocabulary with an export_id based on its category and trimmed name', () => {
    const vocabularies = inputsOf(addVocabulary, 2);
    expect(vocabularies.length).toBeGreaterThan(300);
    vocabularies.forEach(({ category, name, export_id }) => {
      expect(export_id, `${category} ${name}`).toEqual(generateBuiltInExportId('Vocabulary', { category, name: name.trim() }));
    });
    // Declared with a leading space, stored trimmed: same export_id as the migration computes from the stored name
    const ransomware = vocabularies.find((v) => v.category === 'malware_type_ov' && v.name === ' ransomware');
    expect(ransomware.export_id).toEqual(generateBuiltInExportId('Vocabulary', { category: 'malware_type_ov', name: 'ransomware' }));
  });

  it('should not create the marking definitions when not requested', async () => {
    vi.clearAllMocks();
    await initializeData({ source: 'testing' } as any, false);
    expect(addAllowedMarkingDefinition).not.toHaveBeenCalled();
  });
});
