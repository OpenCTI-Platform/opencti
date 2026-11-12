import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as enterpriseEdition from '../../../../src/enterprise-edition/ee';
import { addEmailTemplate, deleteEmailTemplate, findEmailTemplatesByName } from '../../../../src/modules/emailTemplate/emailTemplate-domain';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { importEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-import';
import { emailTemplatesFamily } from '../../../../src/modules/configPreset/registry/emailTemplates-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';

// One word: the search is an OR of the words of the term
const NAME_A = 'ConfigPresetTemplateA';
const NAME_B = 'ConfigPresetTemplateB';
const NAME_DUPLICATE = 'ConfigPresetTemplateDuplicate';
const NAME_COPY_1 = `${NAME_A} (1)`;
const NAME_COPY_2 = `${NAME_A} (2)`;
const mode = ConfigImportMode.Overwrite;
const configuration = {
  name: NAME_A,
  description: 'First template',
  email_object: 'Welcome to OpenCTI',
  sender_email: 'CTI team',
  template_body: '<p>Hello $user.firstname — « Zürich » &amp; 日本語</p>',
};
const find = async (name: string) => (await findEmailTemplatesByName(testContext, ADMIN_USER, name));
const standardIdOf = async (name: string) => (await find(name))[0].standard_id;

describe('Email template import and export (configuration preset)', () => {
  beforeAll(() => {
    // The license is not what is tested here
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  afterAll(async () => {
    for (const name of [NAME_A, NAME_B, NAME_DUPLICATE, NAME_COPY_1, NAME_COPY_2]) {
      for (const template of await find(name)) {
        await deleteEmailTemplate(testContext, ADMIN_USER, template.id);
      }
    }
    vi.restoreAllMocks();
  });

  it('writes nothing on a dry run, and creates the template otherwise', async () => {
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await find(NAME_A)).toHaveLength(0);
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await find(NAME_A)).toHaveLength(1);
    expect((await find(NAME_A))[0]).toMatchObject(configuration);
  });

  it('finds the template by its name and never duplicates it', async () => {
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    // A description that is absent or null leaves the one of the template
    const { description, ...withoutDescription } = configuration;
    expect(await importEmailTemplate(testContext, ADMIN_USER, withoutDescription, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(await importEmailTemplate(testContext, ADMIN_USER, { ...configuration, description: null }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(await find(NAME_A)).toHaveLength(1);
    expect((await find(NAME_A))[0].description).toBe(description);
  });

  it('does not match a name that differs by its case: it is another template', async () => {
    const lower = NAME_A.toLowerCase();
    expect(await importEmailTemplate(testContext, ADMIN_USER, { ...configuration, name: lower }, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
  });

  it('refuses an existing template in add mode, and patches the fields that differ in overwrite mode', async () => {
    const changed = { ...configuration, email_object: 'Hello', template_body: '<p>Changed</p>' };
    expect(await importEmailTemplate(testContext, ADMIN_USER, changed, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    expect((await find(NAME_A))[0]).toMatchObject({ email_object: 'Welcome to OpenCTI' });
    expect(await importEmailTemplate(testContext, ADMIN_USER, changed, { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect((await find(NAME_A))[0]).toMatchObject({ email_object: 'Welcome to OpenCTI' });
    expect(await importEmailTemplate(testContext, ADMIN_USER, changed, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    // The other fields are untouched, and the template keeps its identity
    const [template] = await find(NAME_A);
    expect(template).toMatchObject({ email_object: 'Hello', template_body: '<p>Changed</p>', description: 'First template', sender_email: 'CTI team' });
    expect(await find(NAME_A)).toHaveLength(1);
  });

  it('keeps the standard id and the internal id of the template it overwrites', async () => {
    const [before] = await find(NAME_A);
    await importEmailTemplate(testContext, ADMIN_USER, { ...configuration, sender_email: 'Security' }, { mode });
    const [after] = await find(NAME_A);
    expect(after).toMatchObject({ id: before.id, standard_id: before.standard_id, sender_email: 'Security' });
  });

  it('refuses a name that several templates have, and writes nothing', async () => {
    const duplicate = { ...configuration, name: NAME_DUPLICATE };
    await addEmailTemplate(testContext, ADMIN_USER, duplicate, false);
    await addEmailTemplate(testContext, ADMIN_USER, { ...duplicate, template_body: '<p>Other</p>' }, false);
    expect(await importEmailTemplate(testContext, ADMIN_USER, duplicate, { mode })).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
    expect(await importEmailTemplate(testContext, ADMIN_USER, { ...duplicate, description: 'Changed' }, { mode })).toMatchObject({ status: 'failed', code: 'ambiguous' });
    expect(await find(NAME_DUPLICATE)).toHaveLength(2);
  });

  it('adds a copy under the first free name, and leaves the template it copies untouched', async () => {
    const [before] = await find(NAME_A);
    const copy = { mode: ConfigImportMode.Copy };
    const reservedNames = new Set<string>();
    const dryRun = { ...copy, dryRun: true, reservedNames };
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, dryRun)).toMatchObject({ status: 'created', exists: true, reason: `Added as "${NAME_COPY_1}"` });
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, dryRun)).toMatchObject({ status: 'created', reason: `Added as "${NAME_COPY_2}"` });
    expect(await find(NAME_COPY_1)).toHaveLength(0);
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, copy)).toMatchObject({ status: 'created', exists: true });
    expect(await importEmailTemplate(testContext, ADMIN_USER, configuration, copy)).toMatchObject({ status: 'created', reason: `Added as "${NAME_COPY_2}"` });
    expect(await find(NAME_COPY_1)).toHaveLength(1);
    expect(await find(NAME_COPY_2)).toHaveLength(1);
    expect((await find(NAME_COPY_1))[0]).toMatchObject({ ...configuration, name: NAME_COPY_1 });
    // The copy is another template: the original keeps its identity and its content
    expect(await find(NAME_A)).toHaveLength(1);
    expect((await find(NAME_A))[0]).toMatchObject({ id: before.id, standard_id: before.standard_id, sender_email: 'Security' });
    expect((await find(NAME_COPY_1))[0].id).not.toBe(before.id);
    // The copies match the search of the templates below: they go away
    for (const template of [...await find(NAME_COPY_1), ...await find(NAME_COPY_2)]) {
      await deleteEmailTemplate(testContext, ADMIN_USER, template.id);
    }
  });

  it('copies a name that several templates have, which an overwrite refuses', async () => {
    const copy = await importEmailTemplate(testContext, ADMIN_USER, { ...configuration, name: NAME_DUPLICATE }, { mode: ConfigImportMode.Copy, dryRun: true });
    expect(copy).toMatchObject({ status: 'created', exists: true, reason: `Added as "${NAME_DUPLICATE} (1)"` });
  });

  it('lists, searches and resolves the email templates through the family, by name', async () => {
    await importEmailTemplate(testContext, ADMIN_USER, { ...configuration, name: NAME_B }, { mode });
    const idA = await standardIdOf(NAME_A);
    const idB = await standardIdOf(NAME_B);
    const page = await emailTemplatesFamily.listItems(testContext, ADMIN_USER, { first: 10, search: 'ConfigPresetTemplateA ConfigPresetTemplateB' });
    expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[idA, NAME_A, false], [idB, NAME_B, false]]);
    expect((await emailTemplatesFamily.listItems(testContext, ADMIN_USER, { ids: [idB] })).edges.map(({ node }) => node.id)).toEqual([idB]);
    expect((await emailTemplatesFamily.listItems(testContext, ADMIN_USER, { ids: [] })).edges).toEqual([]);
    expect((await emailTemplatesFamily.resolveItems(testContext, ADMIN_USER, [idA, idB], [idA])).map(({ id }) => id)).toEqual([idB]);
    expect((await emailTemplatesFamily.resolveItems(testContext, ADMIN_USER, [], [])).map(({ id }) => id)).toEqual([]);
  });

  it('exports every template, the built-in one included', async () => {
    const items = await emailTemplatesFamily.resolveItems(testContext, ADMIN_USER, null, []);
    expect(items.map(({ label }) => label)).toContain('Built-In Template For Onboarding');
  });

  it('imports an export back, whatever the platform it comes from', async () => {
    const [item] = await emailTemplatesFamily.resolveItems(testContext, ADMIN_USER, [await standardIdOf(NAME_B)], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, emailTemplatesFamily, item);
    expect(file).toMatchObject({ type: 'securityAccess.emailTemplates', id: item.id, configuration: { ...configuration, name: NAME_B } });
    // Nothing of the platform leaks into the file
    expect(Object.keys(file.configuration).sort()).toEqual(['description', 'email_object', 'name', 'sender_email', 'template_body']);
    // Same platform: nothing to do
    expect(await importEmailTemplate(testContext, ADMIN_USER, file.configuration, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    // Another platform: the template is gone, the import creates it with its content
    await deleteEmailTemplate(testContext, ADMIN_USER, (await find(NAME_B))[0].id);
    expect(await importEmailTemplate(testContext, ADMIN_USER, file.configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect((await find(NAME_B))[0]).toMatchObject({ ...configuration, name: NAME_B });
  });
});
