import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { statusTemplateDelete } from '../../../../src/domain/status';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../../../src/schema/internalObject';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getStatusTemplateStandardId, importStatusTemplate } from '../../../../src/modules/statusTemplate/statusTemplate-import';
import type { BasicStoreEntityStatusTemplate } from '../../../../src/modules/statusTemplate/statusTemplate-types';
import { statusTemplatesFamily } from '../../../../src/modules/configPreset/registry/statusTemplates-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';

const CUSTOM = 'Config preset escalated';
const customId = getStatusTemplateStandardId(CUSTOM);
// A status template the platform creates itself
const DEFAULT = 'IN_PROGRESS';
const defaultId = getStatusTemplateStandardId(DEFAULT);
const mode = ConfigImportMode.Overwrite;
const load = (id: string) => storeLoadById<BasicStoreEntityStatusTemplate>(testContext, ADMIN_USER, id, ENTITY_TYPE_STATUS_TEMPLATE);

describe('Status template import and export (configuration preset)', () => {
  afterAll(async () => {
    const custom = await load(customId);
    if (custom) {
      await statusTemplateDelete(testContext, ADMIN_USER, custom.id);
    }
  });

  it('finds the template of a new instance by its name, and skips it when it has the same color', async () => {
    const stored = await load(defaultId);
    expect(stored).toMatchObject({ name: DEFAULT });
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: DEFAULT.toLowerCase(), color: stored!.color }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: DEFAULT, color: stored!.color }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: DEFAULT, color: stored!.color }, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported' });
  });

  it('writes nothing on a dry run, and creates the template otherwise', async () => {
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: CUSTOM, color: '#e91e63' }, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await load(customId)).toBeFalsy();
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: CUSTOM, color: '#e91e63' }, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await load(customId)).toMatchObject({ name: CUSTOM, color: '#e91e63', standard_id: customId });
  });

  it('never duplicates a template: the same name is skipped or has its color overwritten', async () => {
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: CUSTOM.toUpperCase(), color: '#e91e63' }, { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: CUSTOM, color: '#00ff00' }, { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await load(customId)).toMatchObject({ color: '#e91e63' });
    expect(await importStatusTemplate(testContext, ADMIN_USER, { name: CUSTOM, color: '#00ff00' }, { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await load(customId)).toMatchObject({ color: '#00ff00' });
    expect((await statusTemplatesFamily.resolveItems(testContext, ADMIN_USER, [customId], [])).map(({ id }) => id)).toEqual([customId]);
  });

  it('lists, counts, searches and resolves the templates through the family, the ones of the platform included', async () => {
    const page = await statusTemplatesFamily.listItems(testContext, ADMIN_USER, { first: 100 });
    expect(page.edges.map(({ node }) => node.id)).toEqual(expect.arrayContaining([defaultId, customId]));
    expect(page.pageInfo.globalCount).toBeGreaterThanOrEqual(2);
    const found = await statusTemplatesFamily.listItems(testContext, ADMIN_USER, { search: 'Config preset escalated' });
    expect(found.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([[customId, CUSTOM, false]]);
    expect((await statusTemplatesFamily.listItems(testContext, ADMIN_USER, { ids: [defaultId] })).edges.map(({ node }) => node.id)).toEqual([defaultId]);
    expect((await statusTemplatesFamily.listItems(testContext, ADMIN_USER, { ids: [] })).edges).toEqual([]);
    expect((await statusTemplatesFamily.resolveItems(testContext, ADMIN_USER, [defaultId, customId], [defaultId])).map(({ id }) => id)).toEqual([customId]);
    expect((await statusTemplatesFamily.resolveItems(testContext, ADMIN_USER, [], [])).map(({ id }) => id)).toEqual([]);
  });

  it('imports an export back, whatever the platform it comes from', async () => {
    const [item] = await statusTemplatesFamily.resolveItems(testContext, ADMIN_USER, [customId], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, statusTemplatesFamily, item);
    expect(file).toMatchObject({ type: 'taxonomy.statusTemplates', id: customId, configuration: { name: CUSTOM, color: '#00ff00' } });
    await statusTemplateDelete(testContext, ADMIN_USER, (await load(customId))!.id);
    expect(await load(customId)).toBeFalsy();
    expect(await importStatusTemplate(testContext, ADMIN_USER, file.configuration, { mode })).toMatchObject({ status: 'created', exists: false });
    expect(await load(customId)).toMatchObject({ name: CUSTOM, color: '#00ff00' });
  });
});
