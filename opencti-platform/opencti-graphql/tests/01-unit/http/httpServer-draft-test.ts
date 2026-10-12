import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from 'vitest';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@as-integrations/express5';
import type { Request, Response } from 'express';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const {
  mockGetEntitiesMapFromCache,
  mockIsUserCanAccessStoreElement,
  mockUserEditField,
  mockEnterDraft,
  mockResolveQueuedFeedQuarantineDraftId,
} = vi.hoisted(() => ({
  mockGetEntitiesMapFromCache: vi.fn(),
  mockIsUserCanAccessStoreElement: vi.fn(),
  mockUserEditField: vi.fn(),
  mockEnterDraft: vi.fn(),
  mockResolveQueuedFeedQuarantineDraftId: vi.fn(),
}));

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-closure', () => ({
  enterDraft: mockEnterDraft,
}));

vi.mock('../../../src/modules/sourceIntelligence/sourceIntelligence-quarantine', () => ({
  resolveQueuedFeedQuarantineDraftId: mockResolveQueuedFeedQuarantineDraftId,
}));

vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: mockGetEntitiesMapFromCache,
}));

vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    isUserCanAccessStoreElement: mockIsUserCanAccessStoreElement,
  };
});

vi.mock('../../../src/modules/user/user-domain', () => ({
  userEditField: mockUserEditField,
}));

import { checkDraftInContext, enterRequestDraft, releaseRequestDraft, settleRequestDraft } from '../../../src/http/httpServer-draft';

describe('checkDraftInContext service account hint', () => {
  const draftId = 'draft-under-test';
  const draftWorkspace = { id: draftId };

  beforeEach(() => {
    vi.clearAllMocks();
    mockGetEntitiesMapFromCache.mockResolvedValue(new Map([[draftId, draftWorkspace]]));
    mockIsUserCanAccessStoreElement.mockResolvedValue(false);
    mockUserEditField.mockResolvedValue(undefined);
  });

  const buildContext = (user: Partial<AuthUser>): AuthContext => ({
    user: { id: 'user-id', draft_context: '', ...user } as AuthUser,
    draft_context: draftId,
  } as unknown as AuthContext);

  it('should suggest switching to a service account when the connector user is not one', async () => {
    const executeContext = buildContext({ user_service_account: false });

    await expect(checkDraftInContext(executeContext)).rejects.toThrowError(
      `Draft ${draftId} cannot be found, consider switching the user associated to your connector to a service account (instead of a user)`,
    );
  });

  it('should suggest switching to a service account when user_service_account is undefined', async () => {
    const executeContext = buildContext({});

    await expect(checkDraftInContext(executeContext)).rejects.toThrowError(
      `Draft ${draftId} cannot be found, consider switching the user associated to your connector to a service account (instead of a user)`,
    );
  });

  it('should not append the hint when the connector user is already a service account', async () => {
    const executeContext = buildContext({ user_service_account: true });

    await expect(checkDraftInContext(executeContext)).rejects.toThrowError(`Draft ${draftId} cannot be found`);

    try {
      await checkDraftInContext(executeContext);
      throw new Error('checkDraftInContext should have thrown');
    } catch (e) {
      expect((e as Error).message).toBe(`Draft ${draftId} cannot be found`);
      expect((e as Error).message).not.toContain('service account');
    }
  });
});

describe('checkDraftInContext forwarded work', () => {
  const draftId = 'draft-under-test';

  beforeEach(() => {
    vi.clearAllMocks();
    mockGetEntitiesMapFromCache.mockResolvedValue(new Map([[draftId, { id: draftId, draft_status: 'open' }]]));
    mockIsUserCanAccessStoreElement.mockResolvedValue(true);
  });

  it('should refuse work queued for a draft closed with no draft taking over, even while the cache still shows it open', async () => {
    const executeContext = {
      user: { id: 'worker-id', draft_context: '' } as AuthUser,
      draft_context: draftId,
      draft_forward_closed: true,
    } as unknown as AuthContext;

    await expect(checkDraftInContext(executeContext)).rejects.toMatchObject({ extensions: { code: 'DRAFT_LOCKED' } });
    expect(mockUserEditField).not.toHaveBeenCalled();
  });

  it('should accept work forwarded to an open draft', async () => {
    const executeContext = {
      user: { id: 'worker-id', draft_context: '' } as AuthUser,
      draft_context: draftId,
      draft_forward_closed: false,
    } as unknown as AuthContext;

    await expect(checkDraftInContext(executeContext)).resolves.toBeUndefined();
  });
});

describe('enterRequestDraft and releaseRequestDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should leave a request outside any draft untouched', async () => {
    const executeContext = { draft_context: '' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, {});

    expect(mockEnterDraft).not.toHaveBeenCalled();
    expect(executeContext.draft_writer_id).toBeUndefined();
    await expect(releaseRequestDraft(executeContext)).resolves.toBeUndefined();
  });

  it('should move the request to the draft taking over and keep its lease until the execution settled', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-2', closed: false, writerId: 'writer-1', release });
    const executeContext = { draft_context: 'draft-1' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, {});

    expect(mockEnterDraft).toHaveBeenCalledWith('draft-1');
    expect(executeContext).toMatchObject({ draft_context: 'draft-2', draft_forward_closed: false, draft_writer_id: 'writer-1' });
    expect(release).not.toHaveBeenCalled();
    await releaseRequestDraft(executeContext);
    await releaseRequestDraft(executeContext);
    expect(release).toHaveBeenCalledTimes(1);
  });

  it('should log a lease that could not be released without failing the response', async () => {
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-1', closed: false, writerId: 'writer-1', release: vi.fn().mockRejectedValue(new Error('Redis unavailable')) });
    const executeContext = { draft_context: 'draft-1' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, {});

    await expect(releaseRequestDraft(executeContext)).resolves.toBeUndefined();
  });

  it('should route a feed bundle queued before the quarantine of its source into the quarantine draft', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    mockResolveQueuedFeedQuarantineDraftId.mockResolvedValueOnce('quarantine-draft');
    mockEnterDraft.mockResolvedValue({ draftId: 'quarantine-draft', closed: false, writerId: 'writer-1', release });
    const executeContext = { workId: 'work_feed-connector_2026-10-06T15:41:39.000Z', draft_context: '' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, {});

    expect(mockResolveQueuedFeedQuarantineDraftId).toHaveBeenCalledWith(executeContext);
    expect(mockEnterDraft).toHaveBeenCalledWith('quarantine-draft');
    expect(executeContext).toMatchObject({ draft_context: 'quarantine-draft', draft_forward_closed: false, draft_writer_id: 'writer-1' });
  });

  it('should flag a request whose draft chain ended, holding no lease', async () => {
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-1', closed: true, writerId: null, release: vi.fn() });
    const executeContext = { draft_context: 'draft-1' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, {});

    expect(executeContext).toMatchObject({ draft_context: 'draft-1', draft_forward_closed: true, draft_writer_id: null });
    expect(executeContext.draft_writer_release).toBeUndefined();
  });
});

describe('settleRequestDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const leasedHandler = (release: () => Promise<void>, execute: () => Promise<void>) => {
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-1', closed: false, writerId: 'writer-1', release });
    return settleRequestDraft(async (_req: object, res: object) => {
      await enterRequestDraft({ draft_context: 'draft-1' } as unknown as AuthContext, res);
      await execute();
    });
  };

  it('should release the lease of a request only once its handler settled', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    let settle = () => {};
    const execution = new Promise<void>((resolve) => {
      settle = resolve;
    });
    const handling = leasedHandler(release, () => execution)({}, {});
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
    expect(release).not.toHaveBeenCalled();
    settle();
    await handling;
    expect(release).toHaveBeenCalledTimes(1);
  });

  it('should release the lease when the handler fails, and fail the same way', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    const handler = leasedHandler(release, () => Promise.reject(new Error('Context refused')));
    await expect(handler({}, {})).rejects.toThrow('Context refused');
    expect(release).toHaveBeenCalledTimes(1);
  });

  it('should release nothing for a request that took no lease', async () => {
    const handler = settleRequestDraft(async () => {});
    await expect(handler({}, {})).resolves.toBeUndefined();
    expect(mockEnterDraft).not.toHaveBeenCalled();
  });

  it('should pass the next function of Express to the handler', async () => {
    const next = vi.fn();
    const handler = settleRequestDraft(async (_req: object, _res: object, nextFunction: () => void) => {
      nextFunction();
    });
    await handler({}, {}, next);
    expect(next).toHaveBeenCalledTimes(1);
  });
});

describe('settleRequestDraft around the Express 5 integration of Apollo Server', () => {
  let finishExecution = () => {};
  let executionStarted = false;
  const server = new ApolloServer({
    typeDefs: 'type Query { slow: String }',
    resolvers: {
      Query: {
        slow: () => new Promise<string>((resolve) => {
          executionStarted = true;
          finishExecution = () => resolve('done');
        }),
      },
    },
  });

  beforeAll(async () => {
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });
  beforeEach(() => {
    vi.clearAllMocks();
    executionStarted = false;
  });

  const graphqlRequest = (query: string) => ({
    method: 'POST',
    url: '/graphql',
    headers: { 'content-type': 'application/json' },
    body: { query },
  }) as unknown as Request;
  const graphqlResponse = () => {
    const res = { statusCode: 200, setHeader: vi.fn(), status: vi.fn(), send: vi.fn(), write: vi.fn(), end: vi.fn() };
    res.status.mockReturnValue(res);
    return res;
  };
  const leasedMiddleware = (release: () => Promise<void>, refuse = false) => {
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-1', closed: false, writerId: 'writer-1', release });
    return settleRequestDraft(expressMiddleware(server, {
      context: async ({ res }) => {
        await enterRequestDraft({ draft_context: 'draft-1' } as unknown as AuthContext, res);
        if (refuse) {
          throw new Error('Work is no longer alive');
        }
        return {};
      },
    }));
  };

  it('should release the lease only once the execution of the request settled', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    const res = graphqlResponse();
    const next = vi.fn();
    const handling = leasedMiddleware(release)(graphqlRequest('{ slow }'), res as unknown as Response, next);
    await vi.waitFor(() => expect(executionStarted).toBe(true));
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
    expect(release).not.toHaveBeenCalled();
    finishExecution();
    await handling;
    expect(release).toHaveBeenCalledTimes(1);
    expect(res.send).toHaveBeenCalledWith(expect.stringContaining('"slow":"done"'));
    expect(next).not.toHaveBeenCalled();
  });

  it('should release the lease taken by a context that refused the request afterwards', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    const res = graphqlResponse();
    await leasedMiddleware(release, true)(graphqlRequest('{ slow }'), res as unknown as Response, vi.fn());
    expect(executionStarted).toBe(false);
    expect(release).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(500);
  });
});
