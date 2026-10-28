import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { Readable } from 'node:stream';
import { buildZip, CUSTOM_THEME_ID, validBundleFiles } from '../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { USER_EDITOR } from '../../../utils/testQuery';
import { downloadFile } from '../../../../src/database/raw-file-storage';

const UPLOAD_MUTATION = gql`
  mutation ConfigPresetImportTestUpload($file: Upload!) {
    configPresetImportUpload(file: $file) {
      id
      name
    }
  }
`;

const PREVIEW_QUERY = gql`
  query ConfigPresetImportTestPreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) {
      bundle_name
      openCTI_version
      generated_at
      ignored
      types {
        key
        label
        group { key }
        items {
          key
          label
          translatable
          isDefault
          exists
          fields { key value }
          dependsOn { type key }
        }
      }
    }
  }
`;

const EXPORT_MUTATION = gql`
  mutation ConfigPresetImportTestExport($selections: [ConfigPresetSelectionInput!]!) {
    configPresetExport(selections: $selections) {
      id
    }
  }
`;

const upload = async (content: Buffer, name = 'bundle.zip') => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, name) } });
  return result.data?.configPresetImportUpload.id as string;
};

const preview = (fileId: string) => queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } });
const readZip = async (fileId: string) => {
  const stream = (await downloadFile(fileId)) as Readable;
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
};

describe('Config preset import: upload and preview', () => {
  it('stores the zip under config_preset/import, byte for byte, and previews it', async () => {
    const zip = await buildZip(validBundleFiles());
    const fileId = await upload(zip);
    expect(fileId).toMatch(/^config_preset\/import\/[0-9a-f-]{36}\/bundle\.zip$/);
    expect((await readZip(fileId)).equals(zip)).toBe(true);

    const { data, errors } = await preview(fileId);
    expect(errors).toBeUndefined();
    const result = data?.configPresetImportPreview;
    expect(result.bundle_name).toEqual('Test bundle');
    expect(result.ignored).toEqual([]);
    expect(result.types.map((type: { key: string }) => type.key)).toEqual(['platform', 'branding', 'messages']);
    const platform = result.types[0].items[0];
    expect(platform).toMatchObject({ key: 'platform', exists: true, dependsOn: [{ type: 'branding', key: CUSTOM_THEME_ID }] });
    expect(platform.fields).toEqual([
      { key: 'platform_title', value: 'Imported title' },
      { key: 'platform_favicon', value: 'https://example.com/favicon.ico' },
    ]);
    expect(result.types[1].items).toHaveLength(1);
    expect(result.types[1].items[0]).toMatchObject({ key: CUSTOM_THEME_ID, label: 'Import test theme', exists: false, isDefault: true, translatable: false });
  });

  it('refuses a bundle at preview with the reason, and keeps the zip', async () => {
    const fileId = await upload(await buildZip({ ...validBundleFiles(), 'metadata.json': JSON.stringify({ openCTI_version: '999.0.0', generated_at: 'x' }) }));
    const { errors } = await preview(fileId);
    expect(errors?.[0].extensions?.data).toMatchObject({ reason: 'bundle_refused' });
    expect((await readZip(fileId)).length).toBeGreaterThan(0);
    const notAZip = await upload(Buffer.from('not a zip'), 'not-a-zip.zip');
    expect((await preview(notAZip)).errors?.[0].extensions?.data).toMatchObject({ reason: 'bundle_refused' });
  });

  it('keeps one pending upload per user: a new upload deletes the previous one', async () => {
    const first = await upload(await buildZip(validBundleFiles()), 'first.zip');
    const second = await upload(await buildZip(validBundleFiles()), 'second.zip');
    expect(second).not.toEqual(first);
    expect((await preview(first)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    expect((await preview(second)).errors).toBeUndefined();
  });

  it('answers file_missing for an unknown file and for a file outside config_preset/import', async () => {
    expect((await preview('config_preset/import/unknown/nothing.zip')).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    const exported = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'platform', items: ['platform'] }] } });
    const exportId = exported.data?.configPresetExport.id as string;
    expect(exportId).toMatch(/^config_preset\/export\//);
    expect((await preview(exportId)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    // Also written in another case
    expect((await preview(exportId.replace('config_preset/', 'Config_Preset/'))).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
  });

  it('reads a zip produced by the real export', async () => {
    const exported = await queryAsAdminWithSuccess({
      query: EXPORT_MUTATION,
      variables: { selections: [{ type: 'platform', items: ['platform'] }, { type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'] }] },
    });
    const zip = await readZip(exported.data?.configPresetExport.id);
    const fileId = await upload(zip, 'exported.zip');
    const { data, errors } = await preview(fileId);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImportPreview.types.map((type: { key: string }) => type.key)).toEqual(['platform']);
    // The hidden entity types have no importer
    expect(data?.configPresetImportPreview.ignored).toEqual(['data_model/hidden_entity_types.json']);
  });

  it('refuses the upload and the preview to a user without BYPASS', async () => {
    const fileId = await upload(await buildZip(validBundleFiles()));
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: PREVIEW_QUERY, variables: { file_id: fileId } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(Buffer.from('x'), 'x.zip') } });
  });
});
