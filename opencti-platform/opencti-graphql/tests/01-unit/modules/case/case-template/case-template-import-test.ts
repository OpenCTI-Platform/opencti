import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../../src/modules/case/case-template/case-template-domain', () => ({
  findCaseTemplatesByName: vi.fn(),
  findAllCaseTemplateTasks: vi.fn(),
  caseTemplateAdd: vi.fn(),
  caseTemplateEdit: vi.fn(),
  caseTemplateAddRelation: vi.fn(),
  caseTemplateDeleteRelation: vi.fn(),
}));
vi.mock('../../../../../src/modules/task/task-template/task-template-domain', () => ({ taskTemplateAdd: vi.fn(), taskTemplateEdit: vi.fn() }));

// Registers the Task-Template type, which the platform does at boot
import '../../../../../src/modules/task/task-template/task-template';
import { storeLoadById } from '../../../../../src/database/middleware-loader';
import { generateStandardId, normalizeName } from '../../../../../src/schema/identifier';
import {
  caseTemplateAdd,
  caseTemplateAddRelation,
  caseTemplateDeleteRelation,
  caseTemplateEdit,
  findCaseTemplatesByName,
  findAllCaseTemplateTasks,
} from '../../../../../src/modules/case/case-template/case-template-domain';
import { taskTemplateAdd, taskTemplateEdit } from '../../../../../src/modules/task/task-template/task-template-domain';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { importCaseTemplate } from '../../../../../src/modules/case/case-template/case-template-import';
import { caseTemplateImportSchema } from '../../../../../src/modules/case/case-template/case-template-import-schema';
import { TEMPLATE_TASK_RELATION, type BasicStoreEntityCaseTemplate } from '../../../../../src/modules/case/case-template/case-template-types';
import { type BasicStoreEntityTaskTemplate, ENTITY_TYPE_TASK_TEMPLATE } from '../../../../../src/modules/task/task-template/task-template-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };
const stored = { id: 'case-template-id', standard_id: 'case-template--random', name: 'Phishing triage', description: 'Triage of a phishing report' } as unknown as BasicStoreEntityCaseTemplate;
const blockTask = { id: 'block-task-id', name: 'Block sender', description: 'Block the sender domain' } as BasicStoreEntityTaskTemplate;
const notifyTask = { id: 'notify-task-id', name: 'Notify users' } as BasicStoreEntityTaskTemplate;
const configuration = {
  name: 'Phishing triage',
  description: 'Triage of a phishing report',
  tasks: [{ name: 'Block sender', description: 'Block the sender domain' }, { name: 'Notify users' }],
};

// The task templates of the platform, found by the standard id of their name, as the import finds them
const withTaskTemplates = (...templates: BasicStoreEntityTaskTemplate[]) => {
  vi.mocked(storeLoadById).mockImplementation((async (_ctx: unknown, _user: unknown, id: string) => {
    return templates.find(({ name }) => generateStandardId(ENTITY_TYPE_TASK_TEMPLATE, { name }) === id);
  }) as never);
};

// The case templates of the platform, found by their name whatever its case, as the domain does
const withCaseTemplates = (templates: BasicStoreEntityCaseTemplate[]) => {
  vi.mocked(findCaseTemplatesByName).mockImplementation((async (_ctx: unknown, _user: unknown, name: string) => {
    return templates.filter((template) => normalizeName(template.name) === normalizeName(name));
  }) as never);
};

beforeEach(() => {
  vi.resetAllMocks();
  withCaseTemplates([]);
  vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([]);
  vi.mocked(storeLoadById).mockResolvedValue(undefined as never);
  vi.mocked(taskTemplateAdd).mockImplementation((async (_ctx: unknown, _user: unknown, input: { name: string }) => ({ id: `new-${input.name}` })) as never);
});

describe('Case template import schema', () => {
  it('accepts a name with or without description and tasks, and trims the names', () => {
    expect(caseTemplateImportSchema.parse({ name: ' Phishing triage ' })).toEqual({ name: 'Phishing triage' });
    expect(caseTemplateImportSchema.parse(configuration)).toEqual(configuration);
    expect(caseTemplateImportSchema.parse({ name: 'AB', description: null, tasks: [] })).toEqual({ name: 'AB', description: null, tasks: [] });
    expect(caseTemplateImportSchema.parse({ name: 'AB', tasks: [{ name: ' Notify ' }] })).toEqual({ name: 'AB', tasks: [{ name: 'Notify' }] });
  });

  it.each([
    [{}],
    [{ name: '   ' }],
    [{ name: 'AB', tasks: [{ description: 'No name' }] }],
    [{ name: 'AB', tasks: [{ name: '  ' }] }],
    // Shorter than the platform accepts for a case template or a task template (CaseTemplateAddInput, TaskTemplateAddInput)
    [{ name: 'A' }],
    [{ name: 'AB', tasks: [{ name: 'N' }] }],
    [{ name: 'AB', tasks: ['Notify users'] }],
    [{ name: 'AB', tasks: [{ name: 'Notify', priority: 1 }] }],
    [{ name: 'AB', standard_id: 'case-template--x' }],
    [{ name: 'AB', tasks: [{ name: 'Notify' }, { name: 'NOTIFY' }] }],
  ])('refuses %j', (value) => {
    expect(caseTemplateImportSchema.safeParse(value).success).toBe(false);
  });

  it('says which rule the tasks break', () => {
    const result = caseTemplateImportSchema.safeParse({ name: 'AB', tasks: [{ name: 'Notify' }, { name: 'notify' }] });
    expect(result.error?.issues.map(({ path, message }) => [path.join('.'), message])).toEqual([['tasks', 'Task names must be unique']]);
  });
});

describe('importCaseTemplate', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await importCaseTemplate(context, user, { name: '', tasks: [{ description: 'x' }] }, overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('name: Case template name must be at least 2 characters');
    expect(result.reason).toContain('tasks.0.name');
    expect(findCaseTemplatesByName).not.toHaveBeenCalled();
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('a template that does not exist (%s)', (mode) => {
    it('creates its task templates that do not exist, then the template with them', async () => {
      expect(await importCaseTemplate(context, user, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
      expect(taskTemplateAdd).toHaveBeenNthCalledWith(1, context, user, { name: 'Block sender', description: 'Block the sender domain' });
      expect(taskTemplateAdd).toHaveBeenNthCalledWith(2, context, user, { name: 'Notify users', description: undefined });
      expect(caseTemplateAdd).toHaveBeenCalledWith(context, user, {
        name: 'Phishing triage',
        description: 'Triage of a phishing report',
        tasks: ['new-Block sender', 'new-Notify users'],
      });
    });

    it('creates a template with no task, since the platform requires the list', async () => {
      await importCaseTemplate(context, user, { name: 'Fraud investigation' }, { mode });
      expect(caseTemplateAdd).toHaveBeenCalledWith(context, user, { name: 'Fraud investigation', description: undefined, tasks: [] });
      expect(taskTemplateAdd).not.toHaveBeenCalled();
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importCaseTemplate(context, user, configuration, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(taskTemplateAdd).not.toHaveBeenCalled();
      expect(caseTemplateAdd).not.toHaveBeenCalled();
    });
  });

  it('finds a task template that exists by its name, and links it without creating it', async () => {
    withTaskTemplates(blockTask);
    await importCaseTemplate(context, user, { name: 'New template', tasks: [{ name: 'Block sender', description: 'Block the sender domain' }] }, overwrite);
    expect(taskTemplateAdd).not.toHaveBeenCalled();
    expect(taskTemplateEdit).not.toHaveBeenCalled();
    expect(caseTemplateAdd).toHaveBeenCalledWith(context, user, { name: 'New template', description: undefined, tasks: ['block-task-id'] });
  });

  describe('a template that exists', () => {
    beforeEach(() => {
      withCaseTemplates([stored]);
    });

    it('finds it by its name whatever its case, as its standard id is random', async () => {
      withCaseTemplates([{ ...stored, name: 'PHISHING TRIAGE' }]);
      expect(await importCaseTemplate(context, user, { name: 'phishing triage ' }, overwrite)).toMatchObject({ status: 'skipped', exists: true });
    });

    it('skips it when its description is the one of the configuration, or none, and its tasks are the same, whatever their order', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([notifyTask, blockTask]);
      withTaskTemplates(blockTask, notifyTask);
      expect(await importCaseTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', description: null, tasks: null }, overwrite)).toMatchObject({ status: 'skipped' });
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage' }, overwrite)).toMatchObject({ status: 'skipped' });
      expect(caseTemplateEdit).not.toHaveBeenCalled();
      expect(caseTemplateAddRelation).not.toHaveBeenCalled();
      expect(caseTemplateDeleteRelation).not.toHaveBeenCalled();
    });

    it('patches its description, and leaves its tasks when the configuration has none', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([blockTask]);
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', description: 'Another' }, overwrite)).toMatchObject({ status: 'overwritten', exists: true });
      expect(caseTemplateEdit).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'description', value: ['Another'] }]);
      expect(caseTemplateDeleteRelation).not.toHaveBeenCalled();
      // An empty description is a value
      await importCaseTemplate(context, user, { name: 'Phishing triage', description: '' }, overwrite);
      expect(caseTemplateEdit).toHaveBeenLastCalledWith(context, user, stored.id, [{ key: 'description', value: [''] }]);
    });

    it('replaces its tasks as a whole: creates and links the new ones, unlinks the ones the configuration drops without deleting them', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([blockTask]);
      withTaskTemplates(blockTask);
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', tasks: [{ name: 'Notify users' }] }, overwrite)).toMatchObject({ status: 'overwritten' });
      expect(taskTemplateAdd).toHaveBeenCalledWith(context, user, { name: 'Notify users', description: undefined });
      expect(caseTemplateAddRelation).toHaveBeenCalledWith(context, user, stored.id, { toId: 'new-Notify users', relationship_type: TEMPLATE_TASK_RELATION });
      expect(caseTemplateDeleteRelation).toHaveBeenCalledWith(context, user, stored.id, blockTask.id, TEMPLATE_TASK_RELATION);
    });

    it('links a task template that exists but that the template does not point to, without creating it', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([]);
      withTaskTemplates(notifyTask);
      await importCaseTemplate(context, user, { name: 'Phishing triage', tasks: [{ name: 'Notify users' }] }, overwrite);
      expect(taskTemplateAdd).not.toHaveBeenCalled();
      expect(caseTemplateAddRelation).toHaveBeenCalledWith(context, user, stored.id, { toId: notifyTask.id, relationship_type: TEMPLATE_TASK_RELATION });
    });

    it('clears the tasks with an empty list', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([blockTask, notifyTask]);
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', tasks: [] }, overwrite)).toMatchObject({ status: 'overwritten' });
      expect(caseTemplateDeleteRelation).toHaveBeenCalledTimes(2);
      expect(caseTemplateAddRelation).not.toHaveBeenCalled();
    });

    it('gives a task template that exists the description of the configuration, and keeps it when the configuration has none', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([blockTask]);
      withTaskTemplates(blockTask);
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', tasks: [{ name: 'Block sender', description: 'Block the domain and the sender' }] }, overwrite))
        .toMatchObject({ status: 'overwritten' });
      expect(taskTemplateEdit).toHaveBeenCalledWith(context, user, blockTask.id, [{ key: 'description', value: ['Block the domain and the sender'] }]);
      vi.mocked(taskTemplateEdit).mockClear();
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', tasks: [{ name: 'Block sender' }] }, overwrite)).toMatchObject({ status: 'skipped' });
      expect(taskTemplateEdit).not.toHaveBeenCalled();
    });

    it('writes nothing on a dry run', async () => {
      vi.mocked(findAllCaseTemplateTasks).mockResolvedValue([blockTask]);
      withTaskTemplates(blockTask);
      const dryRun = { mode: ConfigImportMode.Overwrite, dryRun: true };
      expect(await importCaseTemplate(context, user, { name: 'Phishing triage', description: 'Another', tasks: [{ name: 'Notify users' }] }, dryRun)).toMatchObject({ status: 'overwritten', exists: true });
      [caseTemplateEdit, caseTemplateAddRelation, caseTemplateDeleteRelation, taskTemplateAdd, taskTemplateEdit].forEach((write) => expect(write).not.toHaveBeenCalled());
    });

    it('refuses it in add mode', async () => {
      expect(await importCaseTemplate(context, user, configuration, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
      expect(caseTemplateEdit).not.toHaveBeenCalled();
    });
  });

  it('refuses a name that several templates have, as it cannot tell which one to overwrite', async () => {
    withCaseTemplates([stored, { ...stored, id: 'other-id', standard_id: 'case-template--other' }]);
    expect(await importCaseTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
    expect(await importCaseTemplate(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ code: 'ambiguous' });
    [caseTemplateAdd, caseTemplateEdit, caseTemplateAddRelation, taskTemplateAdd].forEach((write) => expect(write).not.toHaveBeenCalled());
  });

  it('has no copy: a case template is its name', async () => {
    withCaseTemplates([stored]);
    expect(await importCaseTemplate(context, user, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
    withCaseTemplates([]);
    expect(await importCaseTemplate(context, user, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: false });
    expect(caseTemplateAdd).not.toHaveBeenCalled();
  });
});
