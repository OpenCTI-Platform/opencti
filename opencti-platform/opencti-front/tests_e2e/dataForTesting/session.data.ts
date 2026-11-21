import { APIRequestContext } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';
import { executeGraphql } from './query-utils';

interface CurrentUser {
  user_email: string;
  capabilities: { name: string }[];
}

const getCurrentUser = async (request: APIRequestContext): Promise<CurrentUser> => {
  const { me } = await executeGraphql<{ me: CurrentUser }>(
    request,
    'Read effective user permissions',
    'query { me { user_email capabilities { name } } }',
  );
  return me;
};

export const authenticateAdminApi = async (request: APIRequestContext) => {
  // APIRequestContext has its own cookie jar: browser login does not repair it on retry.
  await executeGraphql(
    request,
    'Authenticate fixture admin',
    'mutation FixtureAdminLogin($input: UserLoginInput!) { token(input: $input) }',
    { input: { email: 'admin@opencti.io', password: 'admin' } },
  );
  const me = await getCurrentUser(request);
  expect(me.user_email, 'Fixture API must authenticate as admin').toBe('admin@opencti.io');
  expect(me.capabilities.map(({ name }) => name), 'Fixture admin must have BYPASS').toContain('BYPASS');
};

export const waitForUserCapabilities = async (
  request: APIRequestContext,
  email: string,
  capabilities: string[],
  timeout = 30000,
) => {
  await expect.poll(async () => {
    const me = await getCurrentUser(request);
    return {
      email: me.user_email,
      capabilities: me.capabilities.map(({ name }) => name),
    };
  }, {
    message: `Expected ${email}'s effective permissions to include ${capabilities.join(', ')}`,
    timeout,
  }).toMatchObject({ email, capabilities: expect.arrayContaining(capabilities) });
};
