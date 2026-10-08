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

  it('should create every built-in marking definition with its export_id', () => {
    const markings = inputsOf(addAllowedMarkingDefinition, 2);
    expect(markings.map((m) => m.definition)).toEqual([
      'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED',
      'PAP:CLEAR', 'PAP:GREEN', 'PAP:AMBER', 'PAP:RED',
    ]);
    markings.forEach(({ definition_type, definition, export_id }) => {
      expect(export_id, definition).toEqual(generateBuiltInExportId('Marking-Definition', { definition_type, definition }));
    });
    const amberStrict = markings.find((m) => m.definition === 'TLP:AMBER+STRICT');
    expect(amberStrict.export_id).toEqual('d58e35dd-f974-5690-8f79-20759a80b99c');
  });

  it('should create every built-in status template with its export_id', () => {
    const templates = inputsOf(createStatusTemplate, 2);
    expect(templates.map((t) => t.name)).toEqual(['NEW', 'IN_PROGRESS', 'PENDING', 'TO_BE_QUALIFIED', 'ANALYZED', 'CLOSED', 'DECLINED', 'APPROVED']);
    templates.forEach(({ name, export_id }) => {
      expect(export_id, name).toEqual(generateBuiltInExportId('StatusTemplate', { name }));
    });
  });

  it('should create every built-in status with an export_id based on its template name', () => {
    const statuses = vi.mocked(createStatus).mock.calls.map(([, , type, input]) => ({ type, ...input }) as any);
    expect(statuses.map(({ type, template_id, scope }) => [type, template_id, scope])).toEqual([
      ['Report', 'template-NEW', 'GLOBAL'],
      ['Report', 'template-IN_PROGRESS', 'GLOBAL'],
      ['Report', 'template-ANALYZED', 'GLOBAL'],
      ['Report', 'template-CLOSED', 'GLOBAL'],
      ['Case-Rfi', 'template-NEW', 'REQUEST_ACCESS'],
      ['Case-Rfi', 'template-DECLINED', 'REQUEST_ACCESS'],
      ['Case-Rfi', 'template-APPROVED', 'REQUEST_ACCESS'],
    ]);
    statuses.forEach(({ type, scope, template_id, export_id }) => {
      const template = template_id.replace('template-', '');
      expect(export_id, `${type} ${template}`).toEqual(generateBuiltInExportId('Status', { type, scope, template }));
    });
    expect(statuses[0].export_id).toEqual('c2be890f-6cc0-5822-9795-ea6eee54d8c6');
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

  it('should create the built-in email template and retention rules with their export_id', () => {
    const [emailTemplate] = inputsOf(addEmailTemplate, 2);
    expect(emailTemplate).toEqual({
      ...DEFAULT_EMAIL_TEMPLATE_INPUT,
      export_id: generateBuiltInExportId('EmailTemplate', { name: DEFAULT_EMAIL_TEMPLATE_INPUT.name }),
    });
    const retentionRules = inputsOf(createRetentionRule, 2);
    expect(retentionRules.map(({ scope, export_id }) => [scope, export_id])).toEqual(
      ['file', 'workbench', 'history', 'activity'].map((scope) => [scope, generateBuiltInExportId('RetentionRule', { scope })]),
    );
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
