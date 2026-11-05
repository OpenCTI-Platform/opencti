import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { caseTemplateAdd, caseTemplateDelete, findAllCaseTemplates, findAllCaseTemplateTasks } from '../../../../src/modules/case/case-template/case-template-domain';
import { importCaseTemplate } from '../../../../src/modules/case/case-template/case-template-import';
import { ENTITY_TYPE_TASK_TEMPLATE } from '../../../../src/modules/task/task-template/task-template-types';
import { findTaskTemplatePaginated, taskTemplateDelete } from '../../../../src/modules/task/task-template/task-template-domain';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { caseTemplatesFamily } from '../../../../src/modules/configPreset/registry/caseTemplates-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';
import { generateStandardId } from '../../../../src/schema/identifier';

const NAME = 'Config preset phishing triage';
const BLOCK = 'Config preset block sender';
const NOTIFY = 'Config preset notify users';
const mode = ConfigImportMode.Overwrite;
const templatesNamed = async (name: string) => (await findAllCaseTemplates(testContext, ADMIN_USER)).filter((template) => template.name === name);
const tasksOf = async (name: string) => {
  const [template] = await templatesNamed(name);
  return (await findAllCaseTemplateTasks(testContext, ADMIN_USER, template.id)).map((task) => task.name).sort();
};
const loadTask = (name: string) => storeLoadById(testContext, ADMIN_USER, generateStandardId(ENTITY_TYPE_TASK_TEMPLATE, { name }), ENTITY_TYPE_TASK_TEMPLATE);

describe('Case template import and export (configuration preset)', () => {
  afterAll(async () => {
    for (const template of await templatesNamed(NAME)) {
      await caseTemplateDelete(testContext, ADMIN_USER, template.id);
    }
    for (const name of [BLOCK, NOTIFY]) {
      const task = await loadTask(name);
      if (task) {
        await taskTemplateDelete(testContext, ADMIN_USER, task.id);
      }
    }
  });

  it('writes nothing on a dry run, and creates the task templates and the case template otherwise', async () => {
    const configuration = { name: NAME, description: 'Triage of a phishing report', tasks: [{ name: BLOCK, description: 'Block the sender domain' }, { name: NOTIFY }] };
    expect(await importCaseTemplate(testContext, ADMIN_USER, configuration, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await templatesNamed(NAME)).toHaveLength(0);
    expect(await loadTask(BLOCK)).toBeFalsy();
    expect(await importCaseTemplate(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await templatesNamed(NAME)).toHaveLength(1);
    expect((await templatesNamed(NAME))[0]).toMatchObject({ description: 'Triage of a phishing report' });
    expect(await tasksOf(NAME)).toEqual([BLOCK, NOTIFY]);
    expect(await loadTask(BLOCK)).toMatchObject({ name: BLOCK, description: 'Block the sender domain' });
  });

  it('never duplicates the template or its tasks, whatever the case of the names', async () => {
    const configuration = { name: NAME.toUpperCase(), description: 'Triage of a phishing report', tasks: [{ name: BLOCK.toUpperCase(), description: 'Block the sender domain' }, { name: NOTIFY }] };
    expect(await importCaseTemplate(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importCaseTemplate(testContext, ADMIN_USER, configuration, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    expect(await importCaseTemplate(testContext, ADMIN_USER, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported' });
    expect(await templatesNamed(NAME)).toHaveLength(1);
    expect(await tasksOf(NAME)).toEqual([BLOCK, NOTIFY]);
  });

  it('replaces the tasks as a whole without deleting the task template it drops, and patches the description', async () => {
    expect(await importCaseTemplate(testContext, ADMIN_USER, { name: NAME, tasks: [{ name: NOTIFY }] }, { mode, dryRun: true })).toMatchObject({ status: 'overwritten' });
    expect(await tasksOf(NAME)).toEqual([BLOCK, NOTIFY]);
    expect(await importCaseTemplate(testContext, ADMIN_USER, { name: NAME, description: 'Another description', tasks: [{ name: NOTIFY }] }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await tasksOf(NAME)).toEqual([NOTIFY]);
    expect((await templatesNamed(NAME))[0]).toMatchObject({ description: 'Another description' });
    // The task template that was dropped is still there
    expect(await loadTask(BLOCK)).toMatchObject({ name: BLOCK });
    // Absent tasks leave the tasks untouched, an empty list clears them
    expect(await importCaseTemplate(testContext, ADMIN_USER, { name: NAME }, { mode })).toMatchObject({ status: 'skipped' });
    expect(await tasksOf(NAME)).toEqual([NOTIFY]);
    expect(await importCaseTemplate(testContext, ADMIN_USER, { name: NAME, tasks: [] }, { mode })).toMatchObject({ status: 'overwritten' });
    expect(await tasksOf(NAME)).toEqual([]);
  });

  it('links a task template that exists, and gives it the description of the configuration', async () => {
    expect(await importCaseTemplate(testContext, ADMIN_USER, { name: NAME, tasks: [{ name: BLOCK, description: 'Block the domain' }] }, { mode })).toMatchObject({ status: 'overwritten' });
    expect(await tasksOf(NAME)).toEqual([BLOCK]);
    expect(await loadTask(BLOCK)).toMatchObject({ description: 'Block the domain' });
    const found = await findTaskTemplatePaginated(testContext, ADMIN_USER, { search: 'Config preset block sender' });
    expect(found.edges).toHaveLength(1);
  });

  it('refuses a name that several templates have, which the platform allows, and writes nothing', async () => {
    await caseTemplateAdd(testContext, ADMIN_USER, { name: NAME, description: 'A duplicate', tasks: [] });
    expect(await templatesNamed(NAME)).toHaveLength(2);
    expect(await importCaseTemplate(testContext, ADMIN_USER, { name: NAME, description: 'Not written', tasks: [] }, { mode })).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
    const duplicate = (await templatesNamed(NAME)).find((template) => template.description === 'A duplicate');
    await caseTemplateDelete(testContext, ADMIN_USER, duplicate!.id);
    expect(await templatesNamed(NAME)).toHaveLength(1);
    expect((await templatesNamed(NAME))[0]).toMatchObject({ description: 'Another description' });
  });

  it('lists, searches and resolves the case templates through the family, and exports their tasks by name', async () => {
    const [template] = await templatesNamed(NAME);
    const found = await caseTemplatesFamily.listItems(testContext, ADMIN_USER, { search: NAME });
    expect(found.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[template.standard_id, NAME, false]]);
    expect((await caseTemplatesFamily.listItems(testContext, ADMIN_USER, { ids: [] })).edges).toEqual([]);
    expect((await caseTemplatesFamily.resolveItems(testContext, ADMIN_USER, [template.standard_id], [template.standard_id])).map(({ id }) => id)).toEqual([]);
    const [item] = await caseTemplatesFamily.resolveItems(testContext, ADMIN_USER, [template.standard_id], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, caseTemplatesFamily, item);
    expect(file).toMatchObject({ type: 'taxonomy.caseTemplates', id: template.standard_id });
    expect(file.configuration).toEqual({ name: NAME, description: 'Another description', tasks: [{ name: BLOCK, description: 'Block the domain' }] });
  });

  it('imports an export back, whatever the platform it comes from, though the standard id of the template is not the same there', async () => {
    const [template] = await templatesNamed(NAME);
    const [item] = await caseTemplatesFamily.resolveItems(testContext, ADMIN_USER, [template.standard_id], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, caseTemplatesFamily, item);
    await caseTemplateDelete(testContext, ADMIN_USER, template.id);
    expect(await templatesNamed(NAME)).toHaveLength(0);
    expect(await importCaseTemplate(testContext, ADMIN_USER, file.configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    const [recreated] = await templatesNamed(NAME);
    expect(recreated.standard_id).not.toBe(template.standard_id);
    expect(await tasksOf(NAME)).toEqual([BLOCK]);
  });
});
