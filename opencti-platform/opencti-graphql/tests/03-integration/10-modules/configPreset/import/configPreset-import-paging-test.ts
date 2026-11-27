import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import gql from 'graphql-tag';
import { buildZip, itemFile, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { addLabel, findAllLabels, labelDelete } from '../../../../../src/domain/label';
import { getLabelStandardId } from '../../../../../src/modules/label/label-import';
import { CONFIG_PRESET_IMPORT_PAGED_FROM } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';

// A type with thousands of items is listed page by page: these tests check the pages and the counts on a bundle that is just above the
// limit of a page, which says nothing of the speed.

const PREFIX = 'cppaging';
const COUNT = CONFIG_PRESET_IMPORT_PAGED_FROM + 30;
const LABELS = Array.from({ length: COUNT }, (_, i) => `${PREFIX}${String(i).padStart(3, '0')}`);
// Labels of the bundle that already exist on the platform: the conflicts of the type
const EXISTING = LABELS.slice(0, 2);

const UPLOAD_MUTATION = gql`mutation ConfigPresetPagingUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const PREVIEW_QUERY = gql`
  query ConfigPresetPagingPreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) {
      types { key conflictsCount items { key expected { status } } itemsPageInfo { globalCount hasNextPage } }
    }
  }
`;
const ITEMS_QUERY = gql`
  query ConfigPresetPagingItems($file_id: ID!, $type: ID!, $first: Int, $after: ID, $search: String, $excludedIds: [ID!], $conflictsOnly: Boolean) {
    configPresetImportItems(file_id: $file_id, type: $type, first: $first, after: $after, search: $search, excludedIds: $excludedIds, conflictsOnly: $conflictsOnly) {
      pageInfo { globalCount hasNextPage endCursor }
      edges { node { key label conflict exists expected { status reason code } } }
    }
  }
`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetPagingImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status } }
  }
`;

const bundleFiles = () => ({
  ...validBundleFiles(),
  ...Object.fromEntries(LABELS.map((value) => [
    `taxonomy/labels/${getLabelStandardId(value)}.json`,
    itemFile('taxonomy.labels', getLabelStandardId(value), { value, color: '#336699' }),
  ])),
});

const upload = async (files: Record<string, string | Buffer> = bundleFiles(), name = 'bundle.zip') => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(await buildZip(files), name) } });
  zipReads();
  return result.data?.configPresetImportUpload.id as string;
};
const preview = (fileId: string) => queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } });
const items = (fileId: string, variables: Record<string, unknown> = {}) => {
  return queryAsAdmin({ query: ITEMS_QUERY, variables: { file_id: fileId, type: 'labels', ...variables } });
};
const keysOf = (response: Awaited<ReturnType<typeof items>>) => response.data?.configPresetImportItems.edges.map(({ node }: { node: { key: string } }) => node.key) as string[];
const typeOf = (response: Awaited<ReturnType<typeof preview>>, key: string) => {
  return response.data?.configPresetImportPreview.types.find((type: { key: string }) => type.key === key);
};

// How many times a zip of the import was downloaded from the storage since the last call
let storageReads: MockInstance<(command: unknown) => Promise<unknown>>;
const zipReads = () => {
  const count = storageReads.mock.calls.filter(([command]) => command instanceof GetObjectCommand && `${command.input.Key}`.startsWith('config_preset/import/')).length;
  storageReads.mockClear();
  return count;
};

describe('Config preset import: a type listed page by page', () => {
  beforeAll(async () => {
    storageReads = vi.spyOn(S3Client.prototype, 'send') as unknown as typeof storageReads;
    for (let i = 0; i < EXISTING.length; i += 1) {
      await addLabel(testContext, ADMIN_USER, { value: EXISTING[i], color: '#112233' });
    }
  });

  beforeEach(() => {
    zipReads();
  });

  afterAll(async () => {
    storageReads.mockRestore();
    const labels = await findAllLabels(testContext, ADMIN_USER, { filters: { mode: 'and', filters: [{ key: ['standard_id'], values: LABELS.map(getLabelStandardId) }], filterGroups: [] } });
    for (let i = 0; i < labels.length; i += 1) {
      await labelDelete(testContext, ADMIN_USER, labels[i].id);
    }
    await queryAsAdmin({ query: gql`mutation ConfigPresetPagingClear { configPresetImportSessionClear(delete_file: true) }` });
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
  }, 60_000);

  it('lists the first page of the type with its counts, and the other types whole', async () => {
    const fileId = await upload();
    const response = await preview(fileId);
    expect(response.errors).toBeUndefined();
    const labels = typeOf(response, 'labels');
    expect(labels.items.length).toBeLessThan(COUNT);
    expect(labels.itemsPageInfo).toEqual({ globalCount: COUNT, hasNextPage: true });
    // The conflicts are counted over every item, not over the page
    expect(labels.conflictsCount).toBe(EXISTING.length);
    const messages = typeOf(response, 'messages');
    expect(messages.itemsPageInfo.hasNextPage).toBe(false);
    expect(messages.itemsPageInfo.globalCount).toBe(messages.items.length);
  });

  it('gives every item once, page after page, without reading the zip again', async () => {
    const fileId = await upload();
    await preview(fileId);
    zipReads();
    const seen: string[] = [];
    let after: string | undefined;
    for (let pages = 0; pages < 20; pages += 1) {
      const response = await items(fileId, { first: 100, after });
      expect(response.errors).toBeUndefined();
      seen.push(...keysOf(response));
      if (!response.data?.configPresetImportItems.pageInfo.hasNextPage) break;
      after = response.data?.configPresetImportItems.pageInfo.endCursor;
    }
    expect(seen).toHaveLength(COUNT);
    expect(new Set(seen).size).toBe(COUNT);
    expect(zipReads()).toBe(0);
  });

  it('searches, keeps the conflicts, and drops the items excluded', async () => {
    const fileId = await upload();
    await preview(fileId);
    const searched = await items(fileId, { search: `${PREFIX}00`, first: 100 });
    expect(searched.data?.configPresetImportItems.pageInfo.globalCount).toBe(10);
    const conflicts = await items(fileId, { conflictsOnly: true, first: 100 });
    expect(conflicts.data?.configPresetImportItems.edges.map(({ node }: { node: { label: string; conflict: boolean } }) => [node.label, node.conflict]))
      .toEqual(EXISTING.map((value) => [value, true]));
    const excluded = await items(fileId, { excludedIds: [getLabelStandardId(LABELS[0])], first: 1 });
    expect(keysOf(excluded)).toEqual([getLabelStandardId(LABELS[1])]);
    expect(excluded.data?.configPresetImportItems.pageInfo.globalCount).toBe(COUNT - 1);
  });

  it('does not return the items of the type from a dry run, which sends the results of the other types and leaves these to the rows', async () => {
    const fileId = await upload();
    await preview(fileId);
    const dryRun = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections: [{ type: 'labels' }, { type: 'messages' }], dry_run: true } });
    expect(dryRun.errors).toBeUndefined();
    const results = dryRun.data?.configPresetImport.results as { type: string }[];
    expect(results.length).toBeGreaterThan(0);
    expect(results.every(({ type }) => type !== 'labels')).toBe(true);
    expect(results.some(({ type }) => type === 'messages')).toBe(true);
  });

  it('gives each item of a page what the import would do with it, in the preview and in the next pages, and none to the other types', async () => {
    const fileId = await upload();
    const response = await preview(fileId);
    const labels = typeOf(response, 'labels');
    const firstPage = labels.items as { key: string; expected: { status: string } | null }[];
    expect(firstPage.every(({ key, expected }) => expected?.status === (EXISTING.some((value) => getLabelStandardId(value) === key) ? 'OVERWRITTEN' : 'CREATED'))).toBe(true);
    const page = await items(fileId, { search: EXISTING[0], first: 5 });
    expect(page.data?.configPresetImportItems.edges[0].node.expected).toMatchObject({ status: 'OVERWRITTEN' });
    expect(typeOf(response, 'messages').items.every(({ expected }: { expected: unknown }) => expected === null)).toBe(true);
  });

  it('computes the pages by itself when the preview did not keep them, and keeps them for the next ones', async () => {
    const fileId = await upload();
    // No preview: what the next pages read does not exist yet
    const first = await items(fileId, { first: 5 });
    expect(first.errors).toBeUndefined();
    expect(keysOf(first)).toHaveLength(5);
    expect(zipReads()).toBe(1);
    const second = await items(fileId, { first: 5, after: first.data?.configPresetImportItems.pageInfo.endCursor });
    expect(keysOf(second)).toHaveLength(5);
    expect(zipReads()).toBe(0);
  });

  it('refuses the items of a type that is not listed page by page, and of a file that is gone', async () => {
    const fileId = await upload();
    await preview(fileId);
    expect((await items(fileId, { type: 'messages' })).errors).toBeDefined();
    // Another upload replaces the zip: the pages of the first one are not served from what was kept
    await upload({ ...validBundleFiles(), 'platform_settings/messages/banner.json': itemFile('platformSettings.messages', 'banner', { platform_banner_text: 'Other', platform_banner_level: 'RED' }) }, 'second.zip');
    expect((await items(fileId)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
  });
});
