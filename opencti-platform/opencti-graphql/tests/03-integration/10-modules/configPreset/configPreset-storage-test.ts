import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';
import { ADMIN_USER, API_URI, generateBasicAuth, testContext, USER_EDITOR } from '../../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { basePath } from '../../../../src/config/conf';
import { deleteFile } from '../../../../src/database/file-storage';

const EXPORT_MUTATION = gql`
  mutation ConfigPresetStorageTest($selections: [ConfigPresetSelectionInput!]!, $bundle_name: String) {
    configPresetExport(selections: $selections, bundle_name: $bundle_name) {
      id
      name
    }
  }
`;

const SETTINGS_QUERY = gql`
  query ConfigPresetStorageTestSettings {
    settings {
      id
      platform_banner_text
      platform_login_message
      platform_consent_message
      platform_no_access_message
    }
  }
`;

const SETTINGS_EDIT_MUTATION = gql`
  mutation ConfigPresetStorageTestSettingsEdit($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

// A message that is not set is not exportable: these are set for the duration of the test
const MESSAGES_FIELDS = ['platform_banner_text', 'platform_login_message', 'platform_consent_message', 'platform_no_access_message'];

const EXPORT_VARIABLES = {
  selections: [
    { type: 'platform', items: ['platform'] },
    { type: 'messages', items: ['banner', 'login', 'consent', 'noAccess'] },
    { type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'] },
  ],
  bundle_name: 'Integration bundle',
};

const storageGet = (fileId: string, authorization: string) => fetch(`${API_URI}${basePath}/storage/get/${encodeURIComponent(fileId)}`, {
  headers: { authorization },
});

// USER_EDITOR has the knowledge capabilities, not BYPASS
const editorAuthorization = generateBasicAuth(USER_EDITOR.email, USER_EDITOR.password);

describe('Config preset bundle storage round trip', () => {
  let fileId: string;
  let fileName: string;
  let settingsId: string;
  let previousMessages: Record<string, string | null>;

  const patchMessages = async (values: Record<string, string | null>) => {
    const input = MESSAGES_FIELDS.map((key) => ({ key, value: [values[key]] }));
    await queryAsAdminWithSuccess({ query: SETTINGS_EDIT_MUTATION, variables: { id: settingsId, input } });
  };

  beforeAll(async () => {
    const { data: settingsData } = await queryAsAdminWithSuccess({ query: SETTINGS_QUERY, variables: {} });
    settingsId = settingsData.settings.id;
    previousMessages = Object.fromEntries(MESSAGES_FIELDS.map((key) => [key, settingsData.settings[key]]));
    await patchMessages(Object.fromEntries(MESSAGES_FIELDS.map((key) => [key, `${key} for the export`])));
    const { data } = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: EXPORT_VARIABLES });
    fileId = data.configPresetExport.id;
    fileName = data.configPresetExport.name;
  });

  afterAll(async () => {
    if (settingsId) {
      await patchMessages(previousMessages);
    }
    // config_preset/ is not a root cleaned by the test teardown
    if (fileId) {
      await deleteFile(testContext, ADMIN_USER, fileId);
    }
  });

  it('stores the bundle in its own folder under config_preset/export', () => {
    expect(fileId).toMatch(/^config_preset\/export\/[0-9a-f-]{36}\/opencti-config-\d{8}-\d{6}-.+\.zip$/);
    expect(fileId.endsWith(`/${fileName}`)).toBe(true);
  });

  it('serves the zip to an admin through /storage/get', async () => {
    const res = await storageGet(fileId, generateBasicAuth());
    expect(res.status).toBe(200);
    expect(res.headers.get('content-disposition')).toContain(fileName);
    const directory = await unzipper.Open.buffer(Buffer.from(await res.arrayBuffer()));
    const paths = directory.files.map((file: { path: string }) => file.path).sort();
    expect(paths).toEqual([
      'data_model/hidden_entity_types.json',
      'dependencies.json',
      'metadata.json',
      'platform_settings/messages/banner.json',
      'platform_settings/messages/consent.json',
      'platform_settings/messages/login.json',
      'platform_settings/messages/noAccess.json',
      'platform_settings/platform.json',
    ]);
    const metadataFile = directory.files.find((file: { path: string }) => file.path === 'metadata.json');
    const metadata = JSON.parse((await metadataFile.buffer()).toString('utf8'));
    expect(Object.keys(metadata)).toEqual(['openCTI_version', 'generated_at', 'bundle_name']);
    expect(metadata.bundle_name).toBe('Integration bundle');
  });

  it('refuses the bundle to a knowledge user without BYPASS', async () => {
    const res = await storageGet(fileId, editorAuthorization);
    expect(res.status).not.toBe(200);
    expect(((await res.json()) as { error: string }).error).toBe('File not found or restricted');
  });

  it('refuses the bundle to a knowledge user without BYPASS through a case variant of the path', async () => {
    const variant = fileId.replace(/^config_preset\//, 'Config_Preset/');
    // The variant reaches the bundle: an admin gets it
    const adminRes = await storageGet(variant, generateBasicAuth());
    expect(adminRes.status).toBe(200);
    await adminRes.arrayBuffer();
    const res = await storageGet(variant, editorAuthorization);
    expect(res.status).not.toBe(200);
    expect(((await res.json()) as { error: string }).error).toBe('File not found or restricted');
  });

  it('refuses the export mutation to a user without BYPASS', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: EXPORT_MUTATION, variables: EXPORT_VARIABLES });
  });
});
