import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { redisGetExclusionListStatus } from '../../../../src/database/redis';
import { wait } from '../../../../src/database/utils';
import { deleteExclusionList } from '../../../../src/modules/exclusionList/exclusionList-domain';
import { readExclusionListFile } from '../../../../src/modules/exclusionList/exclusionList-file';
import { importExclusionList } from '../../../../src/modules/exclusionList/exclusionList-import';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../../../../src/modules/exclusionList/exclusionList-types';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { exclusionListsFamily } from '../../../../src/modules/configPreset/registry/exclusionLists-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';

// Values that no other test of the platform uses: an enabled list is enforced when an indicator is created
const NAME = 'Config preset exclusion list';
const OTHER_NAME = 'Config preset retired exclusion list';
const VALUES = Buffer.from('config-preset-a.invalid\nconfig-preset-b.invalid\n');
const mode = ConfigImportMode.Overwrite;
const fileOf = (content: Buffer) => ({ read: async () => content });

const listsNamed = async (name: string) => {
  const lists = await fullEntitiesList<BasicStoreEntityExclusionList>(testContext, ADMIN_USER, [ENTITY_TYPE_EXCLUSION_LIST]);
  return lists.filter((list) => list.name === name);
};
const loadList = async (name: string) => (await listsNamed(name))[0];

describe('Exclusion list import and export (configuration preset)', () => {
  afterAll(async () => {
    for (const name of [NAME, OTHER_NAME]) {
      for (const list of await listsNamed(name)) {
        await deleteExclusionList(testContext, ADMIN_USER, list.id);
      }
    }
  });

  it('writes nothing on a dry run, and creates the list with its values file otherwise', async () => {
    const configuration = { name: NAME, description: 'Config preset test', exclusion_list_entity_types: ['Domain-Name'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(VALUES), { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await listsNamed(NAME)).toHaveLength(0);
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(VALUES), { mode })).toMatchObject({ status: 'created', exists: false });
    const list = await loadList(NAME);
    expect(list).toMatchObject({
      name: NAME,
      description: 'Config preset test',
      enabled: true,
      exclusion_list_entity_types: ['Domain-Name'],
      exclusion_list_file_size: VALUES.length,
      // The platform counts the newlines plus one
      exclusion_list_values_count: 3,
    });
    expect(await readExclusionListFile(list)).toEqual(VALUES);
  });

  it('finds the list by its name whatever its case, never duplicates it, and says it is up to date', async () => {
    const configuration = { name: NAME.toUpperCase(), description: 'Config preset test', enabled: true, exclusion_list_entity_types: ['Domain-Name'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(VALUES), { mode })).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await listsNamed(NAME)).toHaveLength(1);
  });

  it('refuses an existing list in add mode, without writing', async () => {
    const configuration = { name: NAME, description: 'Another', exclusion_list_entity_types: ['Domain-Name'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(Buffer.from('x.invalid\n')), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
    expect(await loadList(NAME)).toMatchObject({ description: 'Config preset test', exclusion_list_file_size: VALUES.length });
  });

  it('gives an existing list the description, the state, the types and the values of the configuration', async () => {
    const changed = Buffer.from('config-preset-c.invalid\n');
    const configuration = { name: NAME, description: 'Changed', enabled: false, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(changed), { mode, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await loadList(NAME)).toMatchObject({ description: 'Config preset test', enabled: true });
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(changed), { mode })).toMatchObject({ status: 'overwritten', exists: true });
    const list = await loadList(NAME);
    expect(list).toMatchObject({
      description: 'Changed',
      enabled: false,
      exclusion_list_entity_types: ['Domain-Name', 'Hostname'],
      exclusion_list_file_size: changed.length,
      exclusion_list_values_count: 2,
    });
    expect(await readExclusionListFile(list)).toEqual(changed);
    expect(await listsNamed(NAME)).toHaveLength(1);
  });

  it('replaces values that differ with the same size, which the size cannot tell', async () => {
    const same = Buffer.from('config-preset-d.invalid\n');
    expect(same.length).toBe((await loadList(NAME)).exclusion_list_file_size);
    const configuration = { name: NAME, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(same), { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect(await readExclusionListFile(await loadList(NAME))).toEqual(same);
    // The state and the description of the list are the ones of the platform: the configuration has none
    expect(await loadList(NAME)).toMatchObject({ description: 'Changed', enabled: false });
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(same), { mode })).toMatchObject({ status: 'skipped', code: 'unchanged' });
  });

  it('changes the description alone without touching the values of the list', async () => {
    const before = await loadList(NAME);
    const configuration = { name: NAME, description: 'Only the description', exclusion_list_entity_types: ['Domain-Name', 'Hostname'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(Buffer.from('config-preset-d.invalid\n')), { mode })).toMatchObject({ status: 'overwritten', exists: true });
    const after = await loadList(NAME);
    expect(after).toMatchObject({ description: 'Only the description', enabled: false, exclusion_list_file_size: before.exclusion_list_file_size, exclusion_list_values_count: before.exclusion_list_values_count });
    expect(await readExclusionListFile(after)).toEqual(await readExclusionListFile(before));
    // Back to the description the next tests expect
    await importExclusionList(testContext, ADMIN_USER, { ...configuration, description: 'Changed' }, fileOf(Buffer.from('config-preset-d.invalid\n')), { mode });
    expect(await loadList(NAME)).toMatchObject({ description: 'Changed' });
  });

  it('asks the exclusion list cache to rebuild when only the types of a list change', async () => {
    const values = Buffer.from('config-preset-d.invalid\n');
    const configuration = { name: NAME, exclusion_list_entity_types: ['Domain-Name'] };
    // The date of the request has the resolution of a second
    await wait(1100);
    const before = (await redisGetExclusionListStatus()).last_refresh_ask_date;
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(values), { mode })).toMatchObject({ status: 'overwritten', exists: true });
    expect((await loadList(NAME)).exclusion_list_entity_types).toEqual(['Domain-Name']);
    expect((await redisGetExclusionListStatus()).last_refresh_ask_date).not.toEqual(before);
    // Back to the types the next tests expect
    await importExclusionList(testContext, ADMIN_USER, { name: NAME, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] }, fileOf(values), { mode });
    expect((await loadList(NAME)).exclusion_list_entity_types).toEqual(['Domain-Name', 'Hostname']);
  });

  it('creates a list that is disabled in the configuration disabled, and does not refuse one that has no value', async () => {
    const configuration = { name: OTHER_NAME, enabled: false, exclusion_list_entity_types: ['Url'] };
    expect(await importExclusionList(testContext, ADMIN_USER, configuration, fileOf(Buffer.alloc(0)), { mode })).toMatchObject({ status: 'created' });
    const list = await loadList(OTHER_NAME);
    expect(list).toMatchObject({ enabled: false, exclusion_list_entity_types: ['Url'], exclusion_list_file_size: 0 });
    expect(list.description).toBeFalsy();
  });

  it('exports a list with its values as stored, and imports the export back, whatever the platform it comes from', async () => {
    const [item] = await exclusionListsFamily.resolveItems(testContext, ADMIN_USER, [(await loadList(NAME)).standard_id], []);
    const file = await exportConfigPresetItem(testContext, ADMIN_USER, exclusionListsFamily, item);
    expect(file).toMatchObject({
      type: 'customization.exclusionLists',
      id: item.id,
      configuration: { name: NAME, description: 'Changed', enabled: false, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] },
      attachment: `customization/exclusion_lists/${item.id}.txt`,
    });
    const values = await item.attachment!.read(testContext, ADMIN_USER);
    expect(values).toEqual(Buffer.from('config-preset-d.invalid\n'));
    // Another platform: the list does not exist there
    await deleteExclusionList(testContext, ADMIN_USER, (await loadList(NAME)).id);
    expect(await listsNamed(NAME)).toHaveLength(0);
    expect(await importExclusionList(testContext, ADMIN_USER, file.configuration, fileOf(values), { mode })).toMatchObject({ status: 'created', exists: false });
    const restored = await loadList(NAME);
    expect(restored).toMatchObject({ description: 'Changed', enabled: false, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] });
    expect(await readExclusionListFile(restored)).toEqual(values);
  });

  it('lists the lists of the platform by name, with their standard id as the id of the item', async () => {
    const page = await exclusionListsFamily.listItems(testContext, ADMIN_USER, { first: 50, search: 'Config preset' });
    const list = await loadList(NAME);
    const other = await loadList(OTHER_NAME);
    expect(page.edges.map(({ node }) => [node.id, node.label, node.translatable])).toEqual([
      [list.standard_id, NAME, false],
      [other.standard_id, OTHER_NAME, false],
    ]);
  });
});
