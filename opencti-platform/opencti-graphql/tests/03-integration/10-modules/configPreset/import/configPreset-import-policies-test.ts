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
import { updateLocalAuth } from '../../../../../src/domain/setting-auth';
import { storeLoadById } from '../../../../../src/database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../../../../src/modules/user/user-types';

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
const exportZip = async () => {
  const result = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'policies' }] } });
  const exportId = result.data?.configPresetExport.id as string;
  const zip = await readStream(await downloadFile(exportId));
  await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
  return zip;
};
const policiesZip = (configuration: Record<string, unknown>) => buildZip({
  'metadata.json': metadataFile(),
  'security_access/policies.json': itemFile('securityAccess.policies', 'policies', configuration),
});

// The password history count, as the local authentication settings set it (the tests run with every feature flag on)
const setHistoryCount = async (count: number) => {
  const settingsId = (await getSettings(testContext)).id as string;
  return updateLocalAuth(testContext, ADMIN_USER, settingsId, { enabled: true, password_policy_history_count: count });
};
const USER_ADD_MUTATION = gql`mutation ConfigPresetPoliciesUserAdd($input: UserAddInput!) { userAdd(input: $input) { id } }`;
const USER_EDIT_MUTATION = gql`
  mutation ConfigPresetPoliciesUserEdit($id: ID!, $input: [EditInput]!) { userEdit(id: $id) { fieldPatch(input: $input) { id } } }
`;
const USER_DELETE_MUTATION = gql`mutation ConfigPresetPoliciesUserDelete($id: ID!) { userEdit(id: $id) { delete } }`;
// Passwords that satisfy PASSWORD_POLICY, whatever policy a previous test left
const historyPassword = (n: number) => `Preset-History-${n}${n}!`;
const createUserWithHistory = async (suffix: string, changes: number) => {
  const created = await queryAsAdminWithSuccess({
    query: USER_ADD_MUTATION,
    variables: { input: { name: `Config preset history ${suffix}`, user_email: `config_preset_history_${suffix}@mail.com`, password: historyPassword(1) } },
  });
  const id = created.data?.userAdd.id as string;
  for (let n = 2; n <= changes + 1; n += 1) {
    await queryAsAdminWithSuccess({ query: USER_EDIT_MUTATION, variables: { id, input: [{ key: 'password', value: [historyPassword(n)] }] } });
  }
  return id;
};
const readHistory = async (userId: string) => {
  const user = await storeLoadById(testContext, ADMIN_USER, userId, ENTITY_TYPE_USER) as unknown as { password_history?: string[] };
  return user.password_history ?? [];
};

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
    const zip = await exportZip();
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

  describe('password history count', () => {
    let userId: string | undefined;

    afterEach(async () => {
      // The count of the test platform comes back with the policies (outer afterEach); the user goes
      if (userId) {
        await queryAsAdminWithSuccess({ query: USER_DELETE_MUTATION, variables: { id: userId } });
        userId = undefined;
      }
    });

    it('carries the count of the real export, and trims the stored histories when it goes down, only once applied', async () => {
      await setHistoryCount(2);
      const zip = await exportZip();
      expect((await readPolicies()).password_policy_history_count).toEqual(2);
      // The platform keeps more passwords before the import: 4 changes under N = 5 keep N - 1 = 4 hashes
      await setHistoryCount(5);
      userId = await createUserWithHistory('trim', 4);
      expect(await readHistory(userId)).toHaveLength(4);

      const fileId = await uploadZip(zip);
      const dry = await importData(fileId, true);
      expect(dry).toEqual([{ type: 'policies', key: 'policies', status: 'OVERWRITTEN', reason: 'Fewer recent passwords are kept: users can reuse the oldest ones' }]);
      // A dry run writes nothing
      expect((await readPolicies()).password_policy_history_count).toEqual(5);
      expect(await readHistory(userId)).toHaveLength(4);

      expect(await importData(fileId)).toEqual(dry);
      expect((await readPolicies()).password_policy_history_count).toEqual(2);
      expect(await readHistory(userId)).toHaveLength(1);
    });

    it('deletes every stored history when the count of the bundle is 0, and finds it up to date afterwards', async () => {
      await setHistoryCount(3);
      userId = await createUserWithHistory('clear', 2);
      expect(await readHistory(userId)).toHaveLength(2);
      const results = await importData(await uploadZip(await policiesZip({ password_policy_history_count: 0 })));
      expect(results).toEqual([{ type: 'policies', key: 'policies', status: 'OVERWRITTEN', reason: 'Recent passwords are no longer kept: users can reuse them' }]);
      expect((await readPolicies()).password_policy_history_count).toEqual(0);
      expect(await readHistory(userId)).toHaveLength(0);
      expect(await importPolicies(testContext, ADMIN_USER, { password_policy_history_count: 0 }, { mode: ConfigImportMode.Overwrite, dryRun: true }))
        .toMatchObject({ status: 'skipped', code: 'unchanged' });
    });

    it('refuses a count out of range and leaves the policies of the platform as they are', async () => {
      await setHistoryCount(3);
      const results = await importData(await uploadZip(await policiesZip({ ...PASSWORD_POLICY, password_policy_history_count: 25 })));
      expect(results).toMatchObject([{ type: 'policies', key: 'policies', status: 'FAILED' }]);
      expect(await readPolicies()).toMatchObject({ password_policy_history_count: 3, password_policy_min_length: before.password_policy_min_length });
    });
  });
});
