import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ConfigPresetImportItem } from '../../../../../src/generated/graphql';
import { buildConfigPresetImportTypes, findConfigPresetImportItems } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import { clearConfigPresetImportCache, getConfigPresetImportSnapshot, setConfigPresetImportIndex } from '../../../../../src/modules/configPreset/import/configPreset-import-cache';
import type { ConfigPresetBundle, ConfigPresetBundleItem, ConfigPresetComputedItem } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
const FILE_ID = 'import/file-id';

const labelItem = (index: number, conflict = false): ConfigPresetImportItem => ({
  key: `label--${index}`,
  label: `Label ${index}`,
  translatable: false,
  isDefault: false,
  exists: conflict,
  conflict,
  fields: [],
  credentials: [],
  serviceAccountRequired: false,
  dependsOn: [],
});

// What the preview keeps for the next pages: an entry of the cache for the file, with the index of the paged types
const keepIndex = async (items: ConfigPresetImportItem[]) => {
  await getConfigPresetImportSnapshot(user.id, FILE_ID, async () => Buffer.from('{}'));
  setConfigPresetImportIndex(user.id, FILE_ID, Promise.resolve(new Map([['labels', items]])));
};
const page = (args: Partial<Parameters<typeof findConfigPresetImportItems>[2]> = {}) => {
  return findConfigPresetImportItems(context, user, { file_id: FILE_ID, type: 'labels', ...args });
};
const keys = (connection: Awaited<ReturnType<typeof page>>) => connection.edges.map(({ node }) => node.key);

beforeEach(() => {
  clearConfigPresetImportCache();
});
afterEach(() => {
  clearConfigPresetImportCache();
});

describe('Config preset import: the pages of a type', () => {
  const items = Array.from({ length: 60 }, (_, index) => labelItem(index, index % 10 === 0));

  it('lists the items by page, with a cursor that follows the matching items', async () => {
    await keepIndex(items);
    const first = await page({ first: 25 });
    expect(keys(first)).toEqual(items.slice(0, 25).map(({ key }) => key));
    expect(first.pageInfo).toMatchObject({ globalCount: 60, hasNextPage: true, hasPreviousPage: false, endCursor: '25' });
    const second = await page({ first: 25, after: first.pageInfo.endCursor });
    expect(keys(second)).toEqual(items.slice(25, 50).map(({ key }) => key));
    const last = await page({ first: 25, after: second.pageInfo.endCursor });
    expect(keys(last)).toEqual(items.slice(50).map(({ key }) => key));
    expect(last.pageInfo).toMatchObject({ hasNextPage: false, hasPreviousPage: true });
  });

  it('takes a default page and never more than 200 items', async () => {
    await keepIndex(Array.from({ length: 500 }, (_, index) => labelItem(index)));
    expect(keys(await page())).toHaveLength(25);
    expect(keys(await page({ first: 10000 }))).toHaveLength(200);
  });

  it('searches the labels whatever their case, and counts the matches', async () => {
    await keepIndex(items);
    const found = await page({ search: ' LABEL 5', first: 100 });
    expect(keys(found)).toEqual(['label--5', 'label--50', 'label--51', 'label--52', 'label--53', 'label--54', 'label--55', 'label--56', 'label--57', 'label--58', 'label--59']);
    expect(found.pageInfo.globalCount).toBe(11);
  });

  it('keeps the items asked for, drops the ones excluded, and only the conflicts when asked', async () => {
    await keepIndex(items);
    expect(keys(await page({ ids: ['label--3', 'label--4', 'other'] }))).toEqual(['label--3', 'label--4']);
    expect(keys(await page({ excludedIds: ['label--0', 'label--1'], first: 3 }))).toEqual(['label--2', 'label--3', 'label--4']);
    const conflicts = await page({ conflictsOnly: true, first: 100 });
    expect(keys(conflicts)).toEqual(['label--0', 'label--10', 'label--20', 'label--30', 'label--40', 'label--50']);
    expect(conflicts.pageInfo.globalCount).toBe(6);
  });

  it('answers an empty page for a search that finds nothing', async () => {
    await keepIndex(items);
    const none = await page({ search: 'nothing like this' });
    expect(none.edges).toEqual([]);
    expect(none.pageInfo).toMatchObject({ globalCount: 0, hasNextPage: false, startCursor: '', endCursor: '' });
  });

  it('refuses a type that does not exist and a type that is not listed page by page', async () => {
    await keepIndex(items);
    await expect(page({ type: 'nothing' })).rejects.toThrow('Unknown configuration preset type');
    await expect(page({ type: 'messages' })).rejects.toThrow('The type is not listed page by page');
  });

  it('refuses a user who cannot import', async () => {
    await keepIndex(items);
    await expect(findConfigPresetImportItems(context, { id: 'user-id', capabilities: [] } as unknown as AuthUser, { file_id: FILE_ID, type: 'labels' })).rejects.toThrow();
  });
});

describe('Config preset import: the counts of a type', () => {
  const bundleItem = (id: string): ConfigPresetBundleItem => ({ type: 'labels', id, path: `taxonomy/labels/${id}.json`, configuration: {} });
  const bundle = { metadata: {}, items: [bundleItem('a'), bundleItem('b'), bundleItem('c')], dependencies: {}, ignored: [] } as unknown as ConfigPresetBundle;
  const computed = (conflict: boolean): ConfigPresetComputedItem => ({ label: 'label', translatable: false, exists: conflict, conflict, status: 'created' });

  it('gives the number of items and of conflicts of each type, which a type listed whole has the same as its items', () => {
    const types = buildConfigPresetImportTypes(bundle, bundle.items.map((item, index) => ({ item, computed: computed(index > 0) })), new Map([['labels', true]]));
    expect(types).toHaveLength(1);
    expect(types[0].items).toHaveLength(3);
    expect(types[0].itemsPageInfo).toMatchObject({ globalCount: 3, hasNextPage: false });
    expect(types[0].conflictsCount).toBe(2);
  });

  it('counts nothing for a type the platform cannot import', () => {
    const types = buildConfigPresetImportTypes(bundle, bundle.items.map((item) => ({ item, computed: computed(true) })), new Map([['labels', false]]));
    expect(types[0].items).toEqual([]);
    expect(types[0].itemsPageInfo.globalCount).toBe(0);
    expect(types[0].conflictsCount).toBe(0);
  });
});
