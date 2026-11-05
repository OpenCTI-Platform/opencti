import { afterAll, afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';
import { buildZip } from '../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { getClientBase } from '../../../../src/database/redis';
import { deleteFile } from '../../../../src/database/file-storage';
import { downloadFile } from '../../../../src/database/raw-file-storage';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { allFilesForPaths } from '../../../../src/modules/internal/document/document-domain';
import { deleteExclusionList } from '../../../../src/modules/exclusionList/exclusionList-domain';
import { readExclusionListFile } from '../../../../src/modules/exclusionList/exclusionList-file';
import { importExclusionList } from '../../../../src/modules/exclusionList/exclusionList-import';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../../../../src/modules/exclusionList/exclusionList-types';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';

// The real export and the real import engine on the exclusion lists: the values travel as a file of the zip, next to the JSON of their list.
// Values that no other test of the platform uses: an enabled list is enforced when an indicator is created
const NAME = 'Config preset round trip list';
const OTHER_NAME = 'Config preset round trip disabled list';
const VALUES = Buffer.from('config-preset-round-trip-a.invalid\r\nconfig-preset-round-trip-b.invalid\n');

const UPLOAD_MUTATION = gql`mutation ExclusionListRoundTripUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const EXPORT_MUTATION = gql`mutation ExclusionListRoundTripExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ExclusionListRoundTripImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) {
      results { type key status code reason label }
    }
  }
`;

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const listsNamed = async (name: string) => {
  const lists = await fullEntitiesList<BasicStoreEntityExclusionList>(testContext, ADMIN_USER, [ENTITY_TYPE_EXCLUSION_LIST]);
  return lists.filter((list) => list.name === name);
};
const loadList = async (name: string) => (await listsNamed(name))[0];
const runImport = async (zip: Buffer, selections: unknown[], dryRun: boolean) => {
  const uploaded = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(zip, 'exclusion-lists.zip') } });
  const { data, errors } = await queryAsAdmin({
    query: IMPORT_MUTATION,
    variables: { file_id: uploaded.data?.configPresetImportUpload.id, selections, dry_run: dryRun },
  });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; code: string | null; reason: string | null; label: string }[];
};

describe('Exclusion lists: export and import of the real zip', () => {
  afterAll(async () => {
    for (const name of [NAME, OTHER_NAME]) {
      for (const list of await listsNamed(name)) {
        await deleteExclusionList(testContext, ADMIN_USER, list.id);
      }
    }
  });

  afterEach(async () => {
    await queryAsAdmin({ query: gql`mutation ExclusionListRoundTripClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('exports the lists with their values in the zip, and imports them on a platform that has none, then says they are up to date', async () => {
    const configuration = { name: NAME, description: 'Round trip', exclusion_list_entity_types: ['Domain-Name'] };
    await importExclusionList(testContext, ADMIN_USER, configuration, { read: async () => VALUES }, { mode: ConfigImportMode.Overwrite });
    await importExclusionList(testContext, ADMIN_USER, { name: OTHER_NAME, enabled: false, exclusion_list_entity_types: ['Url'] }, { read: async () => Buffer.alloc(0) }, { mode: ConfigImportMode.Overwrite });
    const lists = [await loadList(NAME), await loadList(OTHER_NAME)];
    const exported = await queryAsAdminWithSuccess({
      query: EXPORT_MUTATION,
      variables: { selections: [{ type: 'exclusionLists', items: lists.map((list) => list.standard_id) }] },
    });
    const exportId = exported.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });

    // Another platform: the lists do not exist there
    for (let i = 0; i < lists.length; i += 1) {
      await deleteExclusionList(testContext, ADMIN_USER, lists[i].id);
    }
    expect(await listsNamed(NAME)).toHaveLength(0);
    expect(await listsNamed(OTHER_NAME)).toHaveLength(0);

    const selections = [{ type: 'exclusionLists' }];
    const dry = await runImport(zip, selections, true);
    expect(dry.map(({ label, status }) => `${label}:${status}`).sort()).toEqual([`${NAME}:CREATED`, `${OTHER_NAME}:CREATED`].sort());
    expect(await listsNamed(NAME)).toHaveLength(0);

    const real = await runImport(zip, selections, false);
    expect(real.map(({ label, status }) => `${label}:${status}`).sort()).toEqual([`${NAME}:CREATED`, `${OTHER_NAME}:CREATED`].sort());
    const restored = await loadList(NAME);
    expect(restored).toMatchObject({ description: 'Round trip', enabled: true, exclusion_list_entity_types: ['Domain-Name'] });
    // The values are the ones that were stored, byte for byte, line breaks included
    expect(await readExclusionListFile(restored)).toEqual(VALUES);
    const restoredOther = await loadList(OTHER_NAME);
    expect(restoredOther).toMatchObject({ enabled: false, exclusion_list_entity_types: ['Url'], exclusion_list_file_size: 0 });

    const again = await runImport(zip, selections, false);
    expect(again.map(({ status, code }) => `${status}:${code}`)).toEqual(['SKIPPED:unchanged', 'SKIPPED:unchanged']);
    expect(await listsNamed(NAME)).toHaveLength(1);
  });

  it('refuses the item of a list whose values file is not in the zip, and writes nothing', async () => {
    const exportedList = await loadList(NAME);
    const exported = await queryAsAdminWithSuccess({
      query: EXPORT_MUTATION,
      variables: { selections: [{ type: 'exclusionLists', items: [exportedList.standard_id] }] },
    });
    const exportId = exported.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
    // The same zip without its .txt entry
    const directory = await unzipper.Open.buffer(zip);
    const entries: { path: string; buffer: () => Promise<Buffer> }[] = directory.files.filter(({ path }: { path: string }) => !path.endsWith('.txt'));
    const files: Record<string, Buffer> = {};
    for (let i = 0; i < entries.length; i += 1) {
      files[entries[i].path] = await entries[i].buffer();
    }
    await deleteExclusionList(testContext, ADMIN_USER, exportedList.id);
    const results = await runImport(await buildZip(files), [{ type: 'exclusionLists' }], false);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ status: 'FAILED', label: NAME });
    expect(results[0].reason).toContain('The file of the values of the exclusion list is missing from the bundle');
    expect(await listsNamed(NAME)).toHaveLength(0);
  });
});
