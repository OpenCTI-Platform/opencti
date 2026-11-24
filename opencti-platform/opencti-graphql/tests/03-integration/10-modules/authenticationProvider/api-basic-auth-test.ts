import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_API_TOKEN, queryInitPlatformAsAdmin, queryInitPlatformAsTokenBearer } from '../../../utils/testQuery';
import { wait } from '../../../../src/database/utils';

const ME_QUERY = gql`
  query { me { id } }
`;

const SETTINGS_QUERY = gql`
  query { settings { id api_basic_auth_enabled } }
`;

const UPDATE_LOCAL_AUTH_QUERY = gql`
  mutation updateLocalAuth($id: ID!, $input: LocalAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateLocalAuth(input: $input) {
        id
        api_basic_auth_enabled
      }
    }
  }
`;

const AUTH_REQUIRED_MESSAGE = 'You must be logged in to do this.';

// Refused means handled as unauthenticated, not any other failure
const isBasicAuthRefused = (result: { data?: { me?: unknown }; errors?: { message: string }[] }) => {
  return !result.data?.me && result.errors?.[0]?.message === AUTH_REQUIRED_MESSAGE;
};

// The platform reads the setting from its cache, refreshed by an event: wait until Basic auth follows it
const waitForBasicAuth = async (accepted: boolean) => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const result = await queryInitPlatformAsAdmin(ME_QUERY);
    if (accepted ? !!result.data?.me : isBasicAuthRefused(result)) {
      return;
    }
    await wait(200);
  }
  throw new Error(`Basic auth was never ${accepted ? 'accepted' : 'refused'}`);
};

// The HTTP requests go through the API token: Basic auth is what this test switches off
describe('API Basic authentication over HTTP', () => {
  let settingsId: string;

  const setApiBasicAuth = async (enabled: boolean) => {
    const result = await queryInitPlatformAsTokenBearer(ADMIN_API_TOKEN, UPDATE_LOCAL_AUTH_QUERY, { id: settingsId, input: { enabled: true, api_basic_auth_enabled: enabled } });
    expect(result.data?.settingsEdit.updateLocalAuth.api_basic_auth_enabled).toEqual(enabled);
    await waitForBasicAuth(enabled);
  };

  beforeAll(async () => {
    const result = await queryInitPlatformAsTokenBearer(ADMIN_API_TOKEN, SETTINGS_QUERY);
    settingsId = result.data?.settings.id;
  });

  afterAll(async () => {
    await setApiBasicAuth(true);
  });

  it('should accept Basic auth while the setting is enabled', async () => {
    const result = await queryInitPlatformAsTokenBearer(ADMIN_API_TOKEN, SETTINGS_QUERY);
    expect(result.data?.settings.api_basic_auth_enabled).toEqual(true);
    const me = await queryInitPlatformAsAdmin(ME_QUERY);
    expect(me.data?.me.id).toBeDefined();
  });

  it('should refuse Basic auth once the setting is disabled, the API token still working', async () => {
    await setApiBasicAuth(false);
    const basicMe = await queryInitPlatformAsAdmin(ME_QUERY);
    expect(isBasicAuthRefused(basicMe)).toBe(true);
    const tokenMe = await queryInitPlatformAsTokenBearer(ADMIN_API_TOKEN, ME_QUERY);
    expect(tokenMe.data?.me.id).toBeDefined();
  });
});
