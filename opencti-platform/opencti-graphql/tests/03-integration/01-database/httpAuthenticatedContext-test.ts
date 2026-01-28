import { describe, expect, it } from 'vitest';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { ADMIN_USER, getAuthUser, USER_EDITOR } from '../../utils/testQuery';

describe('Testing createAuthenticatedContext', () => {
  it('should create executeContext with synchronizedUpsert=true for bypass user and synchronized-upsert headers', async () => {
    const token = ADMIN_USER.api_token;
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
  it('should create executeContext with synchronizedUpsert=false for non bypass user and synchronized-upsert headers', async () => {
    const user = await getAuthUser(USER_EDITOR.id);
    const token = user.api_token;
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
