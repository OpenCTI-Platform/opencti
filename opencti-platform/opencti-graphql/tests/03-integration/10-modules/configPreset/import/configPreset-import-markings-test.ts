import { afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { addGroup } from '../../../../../src/domain/grant';
import { findById as findGroupById, groupAddRelation, groupAllowedMarkings, groupDelete } from '../../../../../src/domain/group';
import {
  addAllowedMarkingDefinition,
  findAllMarkings,
  findById as findMarkingById,
  markingDefinitionDelete,
  markingDefinitionEditField,
} from '../../../../../src/domain/markingDefinition';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { type BasicStoreEntityMarking, exportMarking } from '../../../../../src/modules/markingDefinition/marking-export';
import { markingStandardId } from '../../../../../src/modules/markingDefinition/marking-import';
import { groupStandardId } from '../../../../../src/modules/user/group-import';
import type { BasicStoreEntity } from '../../../../../src/types/store';

const UPLOAD_MUTATION = gql`mutation ConfigPresetMarkingsUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetMarkingsImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status reason } }
  }
`;
const EXPORT_MUTATION = gql`
  mutation ConfigPresetMarkingsExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }
`;

// Every marking and group this test writes has this prefix, so that it can be deleted afterwards
const PREFIX = 'CONFIG-PRESET';
const DEFINITION = `${PREFIX}:SOC`;
const GROUP_NAME = 'Config preset marking group';

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const markingConfiguration = (overrides: Record<string, unknown> = {}) => ({
  definition_type: PREFIX,
  definition: DEFINITION,
  x_opencti_color: '#123456',
  x_opencti_order: 7,
  ...overrides,
});
const markingsBundle = (configuration: { definition_type: string; definition: string }) => {
  const id = markingStandardId(configuration.definition_type, configuration.definition);
  return { 'metadata.json': metadataFile(), [`security_access/markings/${id}.json`]: itemFile('securityAccess.markings', id, configuration) };
};
const uploadZip = async (content: Buffer) => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const importData = async (fileId: string, selections: unknown[], dryRun = false) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; reason: string | null }[];
};
const exportZip = async (selections: unknown[]) => {
  const result = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections } });
  const exportId = result.data?.configPresetExport.id as string;
  const zip = await readStream(await downloadFile(exportId));
  await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
  return zip;
};
const configurationOf = async () => {
  const marking = await findMarkingById(testContext, ADMIN_USER, markingStandardId(PREFIX, DEFINITION)) as BasicStoreEntityMarking;
  return exportMarking(marking);
};
const deleteTestEntities = async () => {
  const group = await findGroupById(testContext, ADMIN_USER, groupStandardId(GROUP_NAME));
  if (group) {
    await groupDelete(testContext, ADMIN_USER, group.id);
  }
  const markings = (await findAllMarkings(testContext, ADMIN_USER, {}) as BasicStoreEntityMarking[]).filter(({ definition_type }) => definition_type === PREFIX);
  for (let i = 0; i < markings.length; i += 1) {
    await markingDefinitionDelete(testContext, ADMIN_USER, markings[i].id);
  }
};

describe('Config preset import: markings', () => {
  afterEach(async () => {
    await deleteTestEntities();
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetMarkingsClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('imports back the zip of the real export: the marking is created with its color and order, under the standard id of its definition', async () => {
    const marking = await addAllowedMarkingDefinition(testContext, ADMIN_USER, markingConfiguration());
    const zip = await exportZip([{ type: 'markings', items: [marking.standard_id] }]);
    await markingDefinitionDelete(testContext, ADMIN_USER, marking.id);

    const results = await importData(await uploadZip(zip), [{ type: 'markings' }]);
    // The reason depends on the groups of the test platform that get the new markings automatically
    expect(results).toMatchObject([{ type: 'markings', key: marking.standard_id, status: 'CREATED' }]);
    expect(await configurationOf()).toEqual(markingConfiguration());
  });

  it('writes nothing on a dry run, then overwrites the color and the order of the marking', async () => {
    await addAllowedMarkingDefinition(testContext, ADMIN_USER, markingConfiguration());
    const fileId = await uploadZip(await buildZip(markingsBundle(markingConfiguration({ x_opencti_color: '#654321', x_opencti_order: 9 }))));
    const dry = await importData(fileId, [{ type: 'markings' }], true);
    expect(dry).toEqual([{ type: 'markings', key: markingStandardId(PREFIX, DEFINITION), status: 'OVERWRITTEN', reason: 'The order of the marking changes' }]);
    expect((await configurationOf()).x_opencti_order).toEqual(7);

    expect(await importData(fileId, [{ type: 'markings' }])).toEqual(dry);
    expect(await configurationOf()).toEqual(markingConfiguration({ x_opencti_color: '#654321', x_opencti_order: 9 }));
  });

  it('exports a built-in marking and imports it back over the local one', async () => {
    const tlpRedId = markingStandardId('TLP', 'TLP:RED');
    const original = await findMarkingById(testContext, ADMIN_USER, tlpRedId) as BasicStoreEntityMarking;
    const zip = await exportZip([{ type: 'markings', items: [tlpRedId] }]);
    try {
      await markingDefinitionEditField(testContext, ADMIN_USER, original.id, [{ key: 'x_opencti_color', value: ['#000001'] }]);
      const results = await importData(await uploadZip(zip), [{ type: 'markings' }]);
      expect(results).toEqual([{ type: 'markings', key: tlpRedId, status: 'OVERWRITTEN', reason: null }]);
      const imported = await findMarkingById(testContext, ADMIN_USER, tlpRedId) as BasicStoreEntityMarking;
      expect(exportMarking(imported)).toEqual(exportMarking(original));
    } finally {
      // Restored only when the import did not: an edit, even an identical one, would change the count of updates in syncCountHelper
      const current = await findMarkingById(testContext, ADMIN_USER, tlpRedId) as BasicStoreEntityMarking;
      if (current.x_opencti_color !== original.x_opencti_color) {
        await markingDefinitionEditField(testContext, ADMIN_USER, original.id, [{ key: 'x_opencti_color', value: [original.x_opencti_color] }]);
      }
    }
  });

  it('creates the marking a group depends on first, then the group with it', async () => {
    const marking = await addAllowedMarkingDefinition(testContext, ADMIN_USER, markingConfiguration());
    const { id: groupId } = await addGroup(testContext, ADMIN_USER, { name: GROUP_NAME });
    await groupAddRelation(testContext, ADMIN_USER, groupId, { toId: marking.id, relationship_type: 'accesses-to' });
    // Only the group is selected: its marking comes with it
    const zip = await exportZip([{ type: 'groups', items: [groupStandardId(GROUP_NAME)] }]);
    await deleteTestEntities();

    const results = await importData(await uploadZip(zip), [{ type: 'groups' }]);
    expect(results.map(({ type, status }) => [type, status])).toEqual([['markings', 'CREATED'], ['groups', 'CREATED']]);
    const group = await findGroupById(testContext, ADMIN_USER, groupStandardId(GROUP_NAME)) as BasicStoreEntity;
    const allowed = await groupAllowedMarkings(testContext, ADMIN_USER, group.id) as BasicStoreEntity[];
    expect(allowed.map(({ standard_id }) => standard_id)).toEqual([markingStandardId(PREFIX, DEFINITION)]);
  });
});
