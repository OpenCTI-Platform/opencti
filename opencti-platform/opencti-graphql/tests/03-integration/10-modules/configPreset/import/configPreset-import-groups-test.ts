import { afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { addGroup, addRole } from '../../../../../src/domain/grant';
import { findById as findGroupById, groupAddRelation, groupDelete } from '../../../../../src/domain/group';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { fullEntitiesList, fullEntitiesThroughRelationsToList } from '../../../../../src/database/middleware-loader';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../../../../../src/schema/internalObject';
import { RELATION_HAS_ROLE } from '../../../../../src/schema/internalRelationship';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN } from '../../../../../src/schema/identifier';
import { roleDelete } from '../../../../../src/modules/user/user-domain';
import { type BasicStoreEntityGroup, getGroupConfigPresetConfiguration } from '../../../../../src/modules/user/configPreset/group-export';
import type { BasicStoreEntityRole } from '../../../../../src/modules/user/configPreset/role-export';
import { groupStandardId } from '../../../../../src/modules/user/configPreset/group-import';
import { roleStandardId } from '../../../../../src/modules/user/configPreset/role-import';
import type { BasicStoreEntity } from '../../../../../src/types/store';

const UPLOAD_MUTATION = gql`mutation ConfigPresetGroupsUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetGroupsImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status reason } }
  }
`;
const EXPORT_MUTATION = gql`
  mutation ConfigPresetGroupsExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }
`;

// Every role and group this test writes has this prefix, so that it can be deleted afterwards
const PREFIX = 'Config preset';
const GROUP_NAME = `${PREFIX} group`;
const ROLE_NAME = `${PREFIX} group role`;

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
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
const tlpGreen = { standard_id: MARKING_TLP_GREEN, definition_type: 'TLP', definition: 'TLP:GREEN' };
const groupConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: GROUP_NAME,
  description: 'Imported group',
  default_assignation: false,
  auto_integration_assignation: [],
  no_creators: false,
  restrict_delete: false,
  auto_new_marking: false,
  group_confidence_level: { max_confidence: 70, overrides: [{ entity_type: 'Report', max_confidence: 40 }] },
  default_hidden_types: ['Channel'],
  default_dashboard: null,
  roles: [{ standard_id: roleStandardId(ROLE_NAME), name: ROLE_NAME }],
  allowed_markings: [tlpGreen],
  default_marking: [{ entity_type: 'GLOBAL', values: [tlpGreen] }],
  max_shareable_markings: [{ type: 'TLP', value: tlpGreen }],
  ...overrides,
});
// A group, without the role it depends on in the bundle
const groupBundle = (configuration: { name: string }) => ({
  'metadata.json': metadataFile(),
  'security_access/groups/group.json': itemFile('securityAccess.groups', groupStandardId(configuration.name), configuration),
});
const testEntities = async (type: string) => {
  return (await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [type])).filter((entity) => entity.name.startsWith(PREFIX));
};
const configurationOf = async (name: string) => {
  const group = await findGroupById(testContext, ADMIN_USER, groupStandardId(name)) as BasicStoreEntityGroup;
  const roles = await fullEntitiesThroughRelationsToList<BasicStoreEntityRole>(testContext, ADMIN_USER, group.id, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE);
  return getGroupConfigPresetConfiguration(testContext, ADMIN_USER, group, roles);
};

describe('Config preset import: groups', () => {
  afterEach(async () => {
    const groups = await testEntities(ENTITY_TYPE_GROUP);
    for (let i = 0; i < groups.length; i += 1) {
      await groupDelete(testContext, ADMIN_USER, groups[i].id);
    }
    const roles = await testEntities(ENTITY_TYPE_ROLE);
    for (let i = 0; i < roles.length; i += 1) {
      await roleDelete(testContext, ADMIN_USER, roles[i].id);
    }
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetGroupsClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('imports back the zip of the real export: the role it depends on first, then the group with its markings', async () => {
    const role = await addRole(testContext, ADMIN_USER, { name: ROLE_NAME, capabilities: ['KNOWLEDGE'] });
    const { id: groupId } = await addGroup(testContext, ADMIN_USER, { name: GROUP_NAME, default_hidden_types: ['Channel'] });
    await groupAddRelation(testContext, ADMIN_USER, groupId, { toId: role.id, relationship_type: RELATION_HAS_ROLE });
    await groupAddRelation(testContext, ADMIN_USER, groupId, { toId: MARKING_TLP_GREEN, relationship_type: 'accesses-to' });
    const exported = await configurationOf(GROUP_NAME);
    // Only the group is selected: its role comes with it
    const result = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'groups', items: [groupStandardId(GROUP_NAME)] }] } });
    const exportId = result.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
    await groupDelete(testContext, ADMIN_USER, groupId);
    await roleDelete(testContext, ADMIN_USER, role.id);

    const results = await importData(await uploadZip(zip), [{ type: 'groups' }]);
    expect(results).toEqual([
      { type: 'roles', key: roleStandardId(ROLE_NAME), status: 'CREATED', reason: null },
      { type: 'groups', key: groupStandardId(GROUP_NAME), status: 'CREATED', reason: null },
    ]);
    expect(await configurationOf(GROUP_NAME)).toEqual(exported);
    expect(exported.allowed_markings).toEqual([tlpGreen]);
  });

  it('overwrites a group: its fields, its roles and its markings are replaced as a whole', async () => {
    await addRole(testContext, ADMIN_USER, { name: ROLE_NAME, capabilities: ['KNOWLEDGE'] });
    const other = await addRole(testContext, ADMIN_USER, { name: `${PREFIX} other role`, capabilities: ['KNOWLEDGE'] });
    const group = await addGroup(testContext, ADMIN_USER, { name: GROUP_NAME, description: 'Before' });
    await groupAddRelation(testContext, ADMIN_USER, group.id, { toId: other.id, relationship_type: RELATION_HAS_ROLE });
    await groupAddRelation(testContext, ADMIN_USER, group.id, { toId: MARKING_TLP_AMBER, relationship_type: 'accesses-to' });
    const fileId = await uploadZip(await buildZip(groupBundle(groupConfiguration())));
    const dry = await importData(fileId, [{ type: 'groups' }], true);
    expect(dry).toEqual([{ type: 'groups', key: groupStandardId(GROUP_NAME), status: 'OVERWRITTEN', reason: null }]);
    expect((await configurationOf(GROUP_NAME)).description).toEqual('Before');

    expect(await importData(fileId, [{ type: 'groups' }])).toEqual(dry);
    expect(await configurationOf(GROUP_NAME)).toEqual(groupConfiguration());
  });

  it('imports a group without the markings and the dashboard this platform does not have, and says so', async () => {
    await addRole(testContext, ADMIN_USER, { name: ROLE_NAME, capabilities: ['KNOWLEDGE'] });
    const unknown = { standard_id: 'marking-definition--00000000-0000-4000-8000-000000000000', definition_type: 'PAP', definition: 'PAP:UNKNOWN' };
    const configuration = groupConfiguration({
      allowed_markings: [tlpGreen, unknown],
      max_shareable_markings: [{ type: 'PAP', value: unknown }],
      default_dashboard: { standard_id: 'workspace--00000000-0000-4000-8000-000000000000', name: 'Missing dashboard' },
    });
    const results = await importData(await uploadZip(await buildZip(groupBundle(configuration))), [{ type: 'groups' }]);
    expect(results).toEqual([{
      type: 'groups',
      key: groupStandardId(GROUP_NAME),
      status: 'CREATED',
      reason: 'Markings not found: PAP:UNKNOWN\nDefault dashboard not found: Missing dashboard',
    }]);
    expect(await configurationOf(GROUP_NAME)).toMatchObject({ allowed_markings: [tlpGreen], max_shareable_markings: [], default_dashboard: null });
  });

  it('fails a group whose role is neither on the platform nor in the bundle', async () => {
    const results = await importData(await uploadZip(await buildZip(groupBundle(groupConfiguration()))), [{ type: 'groups' }]);
    expect(results).toEqual([{ type: 'groups', key: groupStandardId(GROUP_NAME), status: 'FAILED', reason: `Roles could not be imported: ${ROLE_NAME}` }]);
    expect(await testEntities(ENTITY_TYPE_GROUP)).toHaveLength(0);
  });
});
