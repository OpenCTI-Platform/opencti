import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAuthenticatedContext } from '../../../src/http/httpAuthenticatedContext';
import { ADMIN_API_TOKEN, getAuthUser, testContext, USER_EDITOR } from '../../utils/testQuery';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { TokenDuration } from '../../../src/generated/graphql';
import { addUserToken, revokeUserToken } from '../../../src/modules/user/user-domain';
import type { AuthUser } from '../../../src/types/user';

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
    expect(executeContext.user?.id).toBe(editorUser.id);
    expect(executeContext.user?.origin).toBeDefined();
    expect(executeContext.synchronizedUpsert).toBe(true);
  });
  describe('Testing editor context', () => {
    let editorUserToken: { token_id: string; plaintext_token?: string; masked_token?: string; expires_at?: string | null };
    let editorUser: AuthUser;
    beforeAll(async () => {
      editorUser = await getAuthUser(USER_EDITOR.id);
      const input = {
        name: 'Editor Test Token',
        duration: TokenDuration.Days_30,
      };
      // create a token for userEditor
      editorUserToken = await addUserToken(testContext, editorUser, input);
    });
    afterAll(async () => {
      editorUser = await getAuthUser(USER_EDITOR.id); // fetch the user again to get its tokens
      // revoke created token
      await revokeUserToken(testContext, editorUser, editorUserToken.token_id);
    });
    it('should not create executeContext for non bypass user and synchronized-upsert=true header', async () => {
      const token = editorUserToken.plaintext_token;
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
      // context is created without user
      expect(executeContext).toBeDefined();
      expect(executeContext.user).toBeUndefined();
    });
    it('should create executeContext with synchronizedUpsert=false for non bypass user with synchronized-upsert=false headers', async () => {
      const token = editorUserToken.plaintext_token;
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
      expect(executeContext.user?.id).toBe(editorUser.id);
      expect(executeContext.user?.origin).toBeDefined();
      expect(executeContext.synchronizedUpsert).toBe(false); // not bypass, no full sync
    });
    it('should create executeContext with synchronizedUpsert=false for non bypass user without synchronized-upsert headers', async () => {
      const token = editorUserToken.plaintext_token;
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
      expect(executeContext.user?.id).toBe(editorUser.id);
      expect(executeContext.user?.origin).toBeDefined();
      expect(executeContext.synchronizedUpsert).toBe(false); // not bypass, no full sync
    });
  });
});
