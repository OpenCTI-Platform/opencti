import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess, unSetOrganization } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, PLATFORM_ORGANIZATION, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { getSettings, setPlatformBootstrapStatus, settingsEditField } from '../../../../../src/domain/settings';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { isEnterpriseEdition } from '../../../../../src/enterprise-edition/ee';
import { exportPolicies } from '../../../../../src/modules/settings/settings-export';
import { importPolicies } from '../../../../../src/modules/settings/settings-import';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const UPLOAD_MUTATION = gql`mutation ConfigPresetPoliciesUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetPoliciesImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status reason } }
  }
`;
const EXPORT_MUTATION = gql`
  mutation ConfigPresetPoliciesExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }
`;

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
const importData = async (fileId: string, dryRun = false) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections: [{ type: 'policies' }], dry_run: dryRun } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; reason: string | null }[];
};
const readPolicies = async () => (await exportPolicies(testContext, ADMIN_USER)) as Record<string, unknown>;
const editSettings = async (input: { key: string; value: unknown[] }[]) => settingsEditField(testContext, ADMIN_USER, (await getSettings(testContext)).id, input);

const PASSWORD_POLICY = {
  password_policy_min_length: 12,
  password_policy_max_length: 64,
  password_policy_min_symbols: 1,
  password_policy_min_numbers: 2,
  password_policy_min_words: 0,
  password_policy_min_lowercase: 1,
  password_policy_min_uppercase: 1,
  password_policy_validity_days: 0,
};
const toInput = (values: Record<string, unknown>) => Object.entries(values).map(([key, value]) => ({ key, value: [value] }));

describe('Config preset import: policies', () => {
  let before: Awaited<ReturnType<typeof readPolicies>>;

  beforeEach(async () => {
    before = await readPolicies();
  });

  afterEach(async () => {
    // The policies of the test platform as they were; the main organization is left as it is when none was set
    await importPolicies(testContext, ADMIN_USER, before, { mode: ConfigImportMode.Overwrite });
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetPoliciesClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('imports back the zip of the real export: the password policy and the visibility of the users', async () => {
    await editSettings(toInput({ ...PASSWORD_POLICY, view_all_users: true }));
    const exported = await readPolicies();
    const result = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'policies' }] } });
    const exportId = result.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
    // The platform has other policies before the import
    await editSettings(toInput({ password_policy_min_length: 4, view_all_users: false }));

    const fileId = await uploadZip(zip);
    const dry = await importData(fileId, true);
    expect(dry).toEqual([{ type: 'policies', key: 'policies', status: 'OVERWRITTEN', reason: 'Users can view the users of other organizations' }]);
    expect((await readPolicies()).password_policy_min_length).toEqual(4);
    expect(await importData(fileId)).toEqual(dry);
    expect(await readPolicies()).toEqual(exported);
  });

  it('leaves out and reports a main organization that this platform cannot set, and never creates it', async () => {
    const configuration = { ...PASSWORD_POLICY, view_all_users: false, platform_organization: { standard_id: 'identity--00000000-0000-4000-8000-000000000000', name: 'Unknown organization' } };
    const files = { 'metadata.json': metadataFile(), 'security_access/policies.json': itemFile('securityAccess.policies', 'policies', configuration) };
    const results = await importData(await uploadZip(await buildZip(files)));
    const reason = (await isEnterpriseEdition(testContext)) ? 'Main organization not found: Unknown organization' : 'The main organization requires the Enterprise Edition';
    expect(results).toEqual([{ type: 'policies', key: 'policies', status: 'OVERWRITTEN', reason }]);
    expect(await readPolicies()).toMatchObject({ password_policy_min_length: 12, platform_organization: before.platform_organization });
  });

  it('sets a main organization of this platform under the Enterprise Edition, then finds the policies up to date', async () => {
    const organization = { standard_id: PLATFORM_ORGANIZATION.id, name: PLATFORM_ORGANIZATION.name };
    const configuration = { ...PASSWORD_POLICY, view_all_users: false, platform_organization: organization };
    const fileId = await uploadZip(await buildZip({ 'metadata.json': metadataFile(), 'security_access/policies.json': itemFile('securityAccess.policies', 'policies', configuration) }));
    if (!(await isEnterpriseEdition(testContext))) {
      expect(await importData(fileId)).toMatchObject([{ status: 'OVERWRITTEN', reason: 'The main organization requires the Enterprise Edition' }]);
      return;
    }
    try {
      expect(await importData(fileId)).toEqual([{ type: 'policies', key: 'policies', status: 'OVERWRITTEN', reason: `Sets the main organization: ${PLATFORM_ORGANIZATION.name}` }]);
      expect((await readPolicies()).platform_organization).toEqual(organization);
      expect(await importPolicies(testContext, ADMIN_USER, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    } finally {
      await unSetOrganization();
    }
  });
});
