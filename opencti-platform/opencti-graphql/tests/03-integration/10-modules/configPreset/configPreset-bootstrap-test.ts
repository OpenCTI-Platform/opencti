import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { setPlatformBootstrapStatus } from '../../../../src/domain/settings';

const SETTINGS_QUERY = gql`
  query ConfigPresetBootstrapSettings {
    settings {
      id
      platform_bootstrap_status
      platform_bootstrap_wizard_enabled
    }
  }
`;

const SETTINGS_EDIT_MUTATION = gql`
  mutation ConfigPresetBootstrapSettingsEdit($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const ME_EDIT_MUTATION = gql`
  mutation ConfigPresetBootstrapMeEdit($input: [EditInput]!) {
    meEdit(input: $input) {
      id
      bootstrap_wizard_skipped
    }
  }
`;

const readSettings = async () => (await queryAsAdminWithSuccess({ query: SETTINGS_QUERY })).data?.settings;

describe('Config preset bootstrap status', () => {
  // The shared test platform is initialized as a new platform: the status starts pending
  afterAll(async () => {
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
  });

  it('should start pending on a new platform', async () => {
    const settings = await readSettings();
    expect(settings.platform_bootstrap_status).toEqual('pending');
    expect(settings.platform_bootstrap_wizard_enabled).toEqual(true);
  });

  it('should write completed through the domain function', async () => {
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'completed');
    const settings = await readSettings();
    expect(settings.platform_bootstrap_status).toEqual('completed');
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('should reject any other status', async () => {
    await expect(setPlatformBootstrapStatus(testContext, ADMIN_USER, 'skipped')).rejects.toThrow('Invalid platform bootstrap status');
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('should refuse settingsEditField on the status, even for a BYPASS user', async () => {
    const { id } = await readSettings();
    const result = await queryAsAdmin({
      query: SETTINGS_EDIT_MUTATION,
      variables: { id, input: { key: 'platform_bootstrap_status', value: ['completed'] } },
    });
    expect(result.errors?.[0].message).toContain('cannot be edited');
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('should store bootstrap_wizard_skipped on the BYPASS user and refuse it to others', async () => {
    const result = await queryAsAdminWithSuccess({ query: ME_EDIT_MUTATION, variables: { input: { key: 'bootstrap_wizard_skipped', value: [true] } } });
    expect(result.data?.meEdit.bootstrap_wizard_skipped).toEqual(true);
    await queryAsAdminWithSuccess({ query: ME_EDIT_MUTATION, variables: { input: { key: 'bootstrap_wizard_skipped', value: [false] } } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: ME_EDIT_MUTATION, variables: { input: { key: 'bootstrap_wizard_skipped', value: [true] } } });
  });
});
