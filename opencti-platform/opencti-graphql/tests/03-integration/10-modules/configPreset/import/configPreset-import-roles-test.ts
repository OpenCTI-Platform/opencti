import { afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { addRole } from '../../../../../src/domain/grant';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { fullEntitiesList } from '../../../../../src/database/middleware-loader';
import { ENTITY_TYPE_ROLE } from '../../../../../src/schema/internalObject';
import { findRoleById, roleDelete } from '../../../../../src/modules/user/user-domain';
import { type BasicStoreEntityRole, getRoleConfigPresetConfiguration } from '../../../../../src/modules/user/configPreset/role-export';
import { importRole, roleStandardId } from '../../../../../src/modules/user/configPreset/role-import';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { BYPASS, ROLE_ADMINISTRATOR } from '../../../../../src/utils/access';

const UPLOAD_MUTATION = gql`mutation ConfigPresetRolesUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetRolesImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status reason } }
  }
`;
const EXPORT_MUTATION = gql`
  mutation ConfigPresetRolesExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }
`;

// Every role this test writes has this prefix, so that it can be deleted afterwards
const ROLE_NAME = 'Config preset role';

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const roleConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: ROLE_NAME,
  description: 'Imported role',
  can_manage_sensitive_config: false,
  capabilities: ['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'],
  capabilities_in_draft: ['KNOWLEDGE_KNUPDATE'],
  ...overrides,
});
const rolesBundle = (...configurations: { name: string }[]) => ({
  'metadata.json': metadataFile(),
  ...Object.fromEntries(configurations.map((configuration) => {
    const id = roleStandardId(configuration.name);
    return [`security_access/roles/${id}.json`, itemFile('securityAccess.roles', id, configuration)];
  })),
});
const uploadZip = async (content: Buffer) => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const upload = async (files: Record<string, string>) => uploadZip(await buildZip(files));
const importData = async (fileId: string, selections: unknown[], dryRun = false) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; reason: string | null }[];
};
const testRoles = async () => {
  const roles = await fullEntitiesList<BasicStoreEntityRole>(testContext, ADMIN_USER, [ENTITY_TYPE_ROLE]);
  return roles.filter((role) => role.name.startsWith(ROLE_NAME));
};
const configurationOf = async (name: string) => {
  const role = await findRoleById(testContext, ADMIN_USER, roleStandardId(name)) as BasicStoreEntityRole;
  return getRoleConfigPresetConfiguration(testContext, ADMIN_USER, role);
};

describe('Config preset import: roles', () => {
  afterEach(async () => {
    const roles = await testRoles();
    for (let i = 0; i < roles.length; i += 1) {
      await roleDelete(testContext, ADMIN_USER, roles[i].id);
    }
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetRolesClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('imports back the zip of the real export: the role is created with its capabilities, under the standard id of its name', async () => {
    const role = await addRole(testContext, ADMIN_USER, { name: ROLE_NAME, description: 'Round trip', capabilities: ['KNOWLEDGE', 'EXPLORE'], capabilitiesInDraft: ['KNOWLEDGE'] });
    const exported = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'roles', items: [role.standard_id] }] } });
    const exportId = exported.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
    await roleDelete(testContext, ADMIN_USER, role.id);

    const results = await importData(await uploadZip(zip), [{ type: 'roles' }]);
    expect(results).toEqual([{ type: 'roles', key: role.standard_id, status: 'CREATED', reason: null }]);
    expect(await configurationOf(ROLE_NAME)).toEqual({
      name: ROLE_NAME,
      description: 'Round trip',
      can_manage_sensitive_config: false,
      capabilities: ['EXPLORE', 'KNOWLEDGE'],
      capabilities_in_draft: ['KNOWLEDGE'],
    });
  });

  it('writes nothing on a dry run, then overwrites the role, replacing its capabilities as a whole', async () => {
    await addRole(testContext, ADMIN_USER, { name: ROLE_NAME, description: 'Before', capabilities: ['EXPLORE', 'KNOWLEDGE'], capabilitiesInDraft: [] });
    const fileId = await upload(rolesBundle(roleConfiguration()));
    const dry = await importData(fileId, [{ type: 'roles' }], true);
    expect(dry).toEqual([{ type: 'roles', key: roleStandardId(ROLE_NAME), status: 'OVERWRITTEN', reason: null }]);
    expect((await configurationOf(ROLE_NAME)).capabilities).toEqual(['EXPLORE', 'KNOWLEDGE']);

    expect(await importData(fileId, [{ type: 'roles' }])).toEqual(dry);
    expect(await configurationOf(ROLE_NAME)).toEqual(roleConfiguration());
    expect(await testRoles()).toHaveLength(1);
  });

  it('copies a role that exists under the first free name, and leaves the existing one as it is', async () => {
    await addRole(testContext, ADMIN_USER, { name: ROLE_NAME, description: 'Before', capabilities: ['EXPLORE'], capabilitiesInDraft: [] });
    const key = roleStandardId(ROLE_NAME);
    const results = await importData(await upload(rolesBundle(roleConfiguration())), [{ type: 'roles', item_modes: [{ key, mode: 'COPY' }] }]);
    expect(results).toEqual([{ type: 'roles', key, status: 'CREATED', reason: `Added as "${ROLE_NAME} (1)"` }]);
    expect((await configurationOf(ROLE_NAME)).capabilities).toEqual(['EXPLORE']);
    expect(await configurationOf(`${ROLE_NAME} (1)`)).toEqual(roleConfiguration({ name: `${ROLE_NAME} (1)` }));
  });

  it('fails a role whose bundle id is not the standard id of its name', async () => {
    const configuration = roleConfiguration();
    const files = { 'metadata.json': metadataFile(), 'security_access/roles/role.json': itemFile('securityAccess.roles', roleStandardId('Another role'), configuration) };
    const results = await importData(await upload(files), [{ type: 'roles' }]);
    expect(results).toEqual([{ type: 'roles', key: roleStandardId('Another role'), status: 'FAILED', reason: 'The standard id of the role does not match its name' }]);
    expect(await testRoles()).toHaveLength(0);
  });

  it('never removes the bypass capability from the Administrator role', async () => {
    const original = await configurationOf(ROLE_ADMINISTRATOR);
    try {
      const configuration = { ...original, capabilities: ['KNOWLEDGE'] };
      const results = await importData(await upload(rolesBundle(configuration)), [{ type: 'roles' }]);
      expect(results).toEqual([{ type: 'roles', key: roleStandardId(ROLE_ADMINISTRATOR), status: 'OVERWRITTEN', reason: 'The Administrator role keeps the bypass capability' }]);
      expect((await configurationOf(ROLE_ADMINISTRATOR)).capabilities).toEqual([BYPASS, 'KNOWLEDGE'].sort());
    } finally {
      await importRole(testContext, ADMIN_USER, original, { mode: ConfigImportMode.Overwrite });
    }
  });
});
