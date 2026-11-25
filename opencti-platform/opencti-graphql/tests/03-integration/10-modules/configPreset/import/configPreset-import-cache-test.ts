import { afterAll, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { findAllLabels, labelDelete } from '../../../../../src/domain/label';
import { getLabelStandardId } from '../../../../../src/modules/label/label-import';

// What the preview and the dry runs of the wizard read again and again is kept by the backend: these tests check when the zip is read from the
// storage and when what was kept is forgotten, on a small bundle. They say nothing of the speed, which is not what an integration test measures.

const PREFIX = 'cpcachelabel';
const LABELS = Array.from({ length: 5 }, (_, i) => `${PREFIX}${i}`);
const LIST_ID = '3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b';
const LIST_TXT = `customization/exclusion_lists/${LIST_ID}.txt`;

const UPLOAD_MUTATION = gql`mutation ConfigPresetCacheUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const PREVIEW_QUERY = gql`
  query ConfigPresetCachePreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) { types { key items { key exists } } }
  }
`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetCacheImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) {
      results { type key status }
    }
  }
`;

const labelFiles = () => Object.fromEntries(LABELS.map((value) => [
  `taxonomy/labels/${getLabelStandardId(value)}.json`,
  itemFile('taxonomy.labels', getLabelStandardId(value), { value, color: '#336699' }),
]));
// Several families and labels, and an exclusion list with an attachment when asked for: what a bundle of a platform holds
const bundleFiles = (withAttachment = true) => ({
  ...validBundleFiles(),
  ...labelFiles(),
  ...(withAttachment ? exclusionListFiles() : {}),
});
const exclusionListFiles = () => ({
  [`customization/exclusion_lists/${LIST_ID}.json`]: JSON.stringify({
    openCTI_version: '0.0.1',
    type: 'customization.exclusionLists',
    id: LIST_ID,
    configuration: { name: 'Cache test DNS', exclusion_list_entity_types: ['IPv4-Addr'] },
    attachment: LIST_TXT,
  }),
  [LIST_TXT]: '8.8.8.8\n1.1.1.1\n',
});

const upload = async (files: Record<string, string | Buffer>, name = 'bundle.zip') => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(await buildZip(files), name) } });
  // What the upload reads back of its own file is not what is counted
  zipReads();
  return result.data?.configPresetImportUpload.id as string;
};
const preview = (fileId: string) => queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } });
const run = (fileId: string, selections: unknown[], dryRun: boolean) => queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
const countOf = (results: { status: string }[], status: string) => results.filter((result) => result.status === status).length;

// How many times a zip of the import was downloaded from the storage since the last call
let storageReads: MockInstance<(command: unknown) => Promise<unknown>>;
const zipReads = () => {
  const count = storageReads.mock.calls.filter(([command]) => command instanceof GetObjectCommand && `${command.input.Key}`.startsWith('config_preset/import/')).length;
  storageReads.mockClear();
  return count;
};

describe('Config preset import: the bundle kept for the wizard', () => {
  beforeAll(() => {
    storageReads = vi.spyOn(S3Client.prototype, 'send') as unknown as typeof storageReads;
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
    await queryAsAdmin({ query: gql`mutation ConfigPresetCacheClear { configPresetImportSessionClear(delete_file: true) }` });
    // A real import completes the bootstrap of a platform that is pending, and the other tests start from that state
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
  }, 60_000);

  it('reads the zip once for the preview and the dry runs that follow', async () => {
    const fileId = await upload(bundleFiles(false));
    const first = await preview(fileId);
    expect(first.errors).toBeUndefined();
    expect(zipReads()).toBe(1);
    const types = first.data?.configPresetImportPreview.types.map(({ key }: { key: string }) => key);
    expect(types).toEqual(expect.arrayContaining(['platform', 'branding', 'messages', 'labels']));

    // The preview again, the dry run of a selection, the dry run of another one: none of them reads the zip
    expect((await preview(fileId)).data).toEqual(first.data);
    const labels = await run(fileId, [{ type: 'labels' }], true);
    expect(labels.errors).toBeUndefined();
    expect(labels.data?.configPresetImport.results).toHaveLength(LABELS.length);
    expect(countOf(labels.data?.configPresetImport.results, 'CREATED')).toBe(LABELS.length);
    expect((await run(fileId, [{ type: 'messages' }], true)).errors).toBeUndefined();
    expect(zipReads()).toBe(0);
  });

  // An attachment is not part of what is kept: it is read from the zip when an importer asks for it
  it('reads the attachment of an item from the zip when it is computed, through what was kept', async () => {
    const fileId = await upload(bundleFiles());
    await preview(fileId);
    zipReads();
    const dryRun = await run(fileId, [{ type: 'exclusionLists' }], true);
    expect(dryRun.errors).toBeUndefined();
    expect(dryRun.data?.configPresetImport.results).toEqual([{ type: 'exclusionLists', key: LIST_ID, status: 'CREATED' }]);
    // The zip is opened for the attachment, once for the run
    expect(zipReads()).toBe(1);
  });

  it('forgets what was kept of the previous zip when another one is uploaded', async () => {
    // No attachment: nothing but what was kept could answer for this zip once it is deleted
    const first = await upload(bundleFiles(false), 'first.zip');
    expect((await preview(first)).errors).toBeUndefined();
    const second = await upload({ ...validBundleFiles(), 'platform_settings/messages/banner.json': itemFile('platformSettings.messages', 'banner', { platform_banner_text: 'Other', platform_banner_level: 'RED' }) }, 'second.zip');
    // The first zip is deleted: it is not previewed from the memory of the backend
    expect((await preview(first)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    zipReads();
    expect((await preview(second)).errors).toBeUndefined();
    expect(zipReads()).toBe(1);
  });

  it('forgets what was kept when the session is cleared with its zip', async () => {
    const fileId = await upload(bundleFiles(false));
    expect((await preview(fileId)).errors).toBeUndefined();
    await queryAsAdminWithSuccess({ query: gql`mutation ConfigPresetCacheStartOver { configPresetImportSessionClear(delete_file: true) }` });
    // The zip is deleted: the preview says so, it does not answer with what it kept
    expect((await preview(fileId)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
  });

  it('does not keep a zip that cannot be read', async () => {
    const fileId = await upload({ 'metadata.json': JSON.stringify({ openCTI_version: '999.0.0', generated_at: 'x' }) });
    expect((await preview(fileId)).errors?.[0].extensions?.data).toMatchObject({ reason: 'bundle_refused' });
    expect((await preview(fileId)).errors?.[0].extensions?.data).toMatchObject({ reason: 'bundle_refused' });
    // Read again each time: the failure was not kept
    expect(zipReads()).toBe(2);
  });

  it('reads the zip itself for the import, and no longer serves from memory the zip the import consumed', async () => {
    const fileId = await upload({ 'metadata.json': metadataFile(), ...labelFiles() });
    expect((await preview(fileId)).errors).toBeUndefined();
    zipReads();

    const real = await run(fileId, [{ type: 'labels' }], false);
    expect(real.errors).toBeUndefined();
    expect(countOf(real.data?.configPresetImport.results, 'CREATED')).toBe(LABELS.length);
    // The import did not use what the preview kept
    expect(zipReads()).toBe(1);

    // The zip is deleted once imported: the preview says so, it does not answer with what it kept
    expect((await preview(fileId)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
  }, 60_000);
});
