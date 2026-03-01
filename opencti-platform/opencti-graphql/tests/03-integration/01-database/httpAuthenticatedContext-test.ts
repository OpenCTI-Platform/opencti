import { describe, expect, it } from 'vitest';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { ADMIN_API_TOKEN, getAuthUser, USER_EDITOR } from '../../utils/testQuery';

describe('Testing createAuthenticatedContext', () => {
  it('should create executeContext with synchronizedUpsert=true for bypass user and synchronized-upsert headers', async () => {
    const token = ADMIN_API_TOKEN;
    const res = {};
    const req = {
      header: (header: string) => {
        return header; // fake response to make conf.getRequestAuditHeaders work
      },
      headers: {
        ['synchronized-upsert']: 'true',
        authorization: 'Bearer ' + token,
      },
      socket: {
        remoteAddress: '128.0.0.1',
      },
    };

    const executeContext = await createAuthenticatedContext(req, res, 'api-test');
    expect(executeContext).toBeDefined();
    expect(executeContext.user).toBeDefined();
    expect(executeContext.user?.origin).toBeDefined();
    expect(executeContext.synchronizedUpsert).toBe(true);
  });
  // don't know how I can test this yet, since I don't have user_editor api token.
  it.skip('should create executeContext with synchronizedUpsert=false for non bypass user and synchronized-upsert headers', async () => {
    const user = await getAuthUser(USER_EDITOR.id);
    const token = user.api_tokens[0];
    const res = {};
    const req = {
      header: (header: string) => {
        return header; // fake response to make conf.getRequestAuditHeaders work
      },
      headers: {
        ['synchronized-upsert']: 'true',
        authorization: 'Bearer ' + token,
      },
      socket: {
        remoteAddress: '128.0.0.1',
      },
    };
    const executeContext = await createAuthenticatedContext(req, res, 'api-test');
    expect(executeContext).toBeDefined();
    expect(executeContext.user).toBeDefined();
    expect(executeContext.user?.origin).toBeDefined();
    expect(executeContext.synchronizedUpsert).toBe(false); // not bypass, no full sync
  });
});
