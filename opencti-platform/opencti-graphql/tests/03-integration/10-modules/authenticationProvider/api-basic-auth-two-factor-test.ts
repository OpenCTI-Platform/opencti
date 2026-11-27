import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type Express from 'express';
import { ADMIN_USER, AMBER_GROUP, getGroupIdByName, testContext } from '../../../utils/testQuery';
import conf from '../../../../src/config/conf';
import { patchAttribute } from '../../../../src/database/middleware';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { addUser, addUserTokenByAdmin, authenticateUserByBasicAuth, authenticateUserFromRequest, userDelete } from '../../../../src/modules/user/user-domain';
import { ENTITY_TYPE_USER } from '../../../../src/modules/user/user-types';
import { TokenDuration } from '../../../../src/generated/graphql';

const SWITCH = 'app:authentication:secure_by_default';
// A user allowed to use Basic auth and API tokens, with two-factor authentication enabled
const TWO_FACTOR_USER = { email: 'basic-auth-two-factor@opencti.io', password: 'two-factor-password' };

const buildRequest = (headers: Record<string, string> = {}) => ({
  ip: '127.0.0.1',
  headers: { 'x-forwarded-for': '127.0.0.1', ...headers },
  header: (_: string) => undefined,
}) as unknown as Express.Request;
const buildApiRequest = (headers: Record<string, string>) => buildRequest(headers) as unknown as Parameters<typeof authenticateUserFromRequest>[1];

// The switch is read from the configuration of this process: Basic auth is called directly, not over HTTP
describe('API Basic authentication with two-factor authentication', () => {
  let userId: string;
  let userToken: string;
  const basicAuth = (password = TWO_FACTOR_USER.password) => authenticateUserByBasicAuth(testContext, buildRequest(), { username: TWO_FACTOR_USER.email, password });

  beforeAll(async () => {
    const amberGroupId = await getGroupIdByName(AMBER_GROUP.name);
    const user = await addUser(testContext, ADMIN_USER, {
      user_email: TWO_FACTOR_USER.email, name: TWO_FACTOR_USER.email, password: TWO_FACTOR_USER.password, groups: [amberGroupId],
    });
    userId = user.id;
    const { plaintext_token } = await addUserTokenByAdmin(testContext, ADMIN_USER, userId, { name: 'basic-auth-two-factor', duration: TokenDuration.Days_30 });
    userToken = plaintext_token;
    await patchAttribute(testContext, ADMIN_USER, userId, ENTITY_TYPE_USER, { otp_activated: true });
    resetCacheForEntity(ENTITY_TYPE_USER);
  });

  afterEach(() => {
    conf.clear(SWITCH);
  });

  afterAll(async () => {
    await userDelete(testContext, ADMIN_USER, userId);
  });

  it('should accept Basic auth for an account with two-factor authentication while the switch is off', async () => {
    const user = await basicAuth();
    expect(user.id).toEqual(userId);
  });

  it('should refuse Basic auth for an account with two-factor authentication once the switch is on, the API token still working', async () => {
    conf.set(SWITCH, true);
    await expect(basicAuth()).rejects.toThrow(/use an API token/);
    const tokenUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: `Bearer ${userToken}` }));
    expect(tokenUser?.id).toEqual(userId);
  });

  // Refused before the password: a wrong one gets the same refusal, not a login failure
  it('should refuse Basic auth before checking the password once the switch is on', async () => {
    conf.set(SWITCH, true);
    await expect(basicAuth('wrong-password')).rejects.toThrow(/use an API token/);
  });
});
