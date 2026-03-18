import { describe, expect, it } from 'vitest';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { ADMIN_API_TOKEN, getAuthUser, USER_EDITOR } from '../../utils/testQuery';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

describe('Testing createAuthenticatedContext', () => {
  it('should create executeContext with synchronizedUpsert=false for bypass user without synchronized-upsert headers', async () => {
    const token = ADMIN_API_TOKEN;
    const res = {};
    const req = {
      header: (header: string) => {
        return header; // fake response to make conf.getRequestAuditHeaders work
      },
      headers: {
        authorization: 'Bearer ' + token,
      },
      socket: {
        remoteAddress: '128.0.0.1',
      },
    };

    const executeContext = await createAuthenticatedContext(req, res, 'api-test');
    expect(executeContext).toBeDefined();
    expect(executeContext.user).toBeDefined();
    expect(executeContext.user?.id).toBe(OPENCTI_ADMIN_UUID);
    expect(executeContext.user?.origin).toBeDefined();
    expect(executeContext.synchronizedUpsert).toBe(false);
  });
  it('should create executeContext with synchronizedUpsert=false for bypass user and synchronized-upsert headers', async () => {
    const token = ADMIN_API_TOKEN;
    const res = {};
    const req = {
      header: (header: string) => {
        return header; // fake response to make conf.getRequestAuditHeaders work
      },
      headers: {
        ['synchronized-upsert']: 'false',
        authorization: 'Bearer ' + token,
      },
      socket: {
        remoteAddress: '128.0.0.1',
      },
    };

    const executeContext = await createAuthenticatedContext(req, res, 'api-test');
    expect(executeContext).toBeDefined();
    expect(executeContext.user).toBeDefined();
    expect(executeContext.user?.id).toBe(OPENCTI_ADMIN_UUID);
    expect(executeContext.user?.origin).toBeDefined();
    expect(executeContext.synchronizedUpsert).toBe(false);
  });
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
    expect(executeContext.user?.id).toBe(OPENCTI_ADMIN_UUID);
    expect(executeContext.user?.origin).toBeDefined();
    expect(executeContext.synchronizedUpsert).toBe(true);
  });
  it('should create executeContext with synchronizedUpsert=true for bypass user and synchronized-upsert headers & applicant-id', async () => {
    const editorUser = await getAuthUser(USER_EDITOR.id);
    const token = ADMIN_API_TOKEN;
    const res = {};
    const req = {
      header: (header: string) => {
        return header; // fake response to make conf.getRequestAuditHeaders work
      },
      headers: {
        ['synchronized-upsert']: 'true',
        authorization: 'Bearer ' + token,
        ['opencti-applicant-id']: editorUser.id,
      },
      socket: {
        remoteAddress: '128.0.0.1',
      },
    };

    const executeContext = await createAuthenticatedContext(req, res, 'api-test');
    expect(executeContext).toBeDefined();
    expect(executeContext.user).toBeDefined();
    console.log('executeContext', JSON.stringify(executeContext));
    expect(executeContext.user?.id).toBe(editorUser.id);
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
