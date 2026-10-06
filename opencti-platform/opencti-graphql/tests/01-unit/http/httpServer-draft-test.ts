import { EventEmitter } from 'node:events';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const { mockGetEntitiesMapFromCache, mockIsUserCanAccessStoreElement, mockUserEditField, mockEnterDraft } = vi.hoisted(() => ({
  mockGetEntitiesMapFromCache: vi.fn(),
  mockIsUserCanAccessStoreElement: vi.fn(),
  mockUserEditField: vi.fn(),
  mockEnterDraft: vi.fn(),
}));

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-closure', () => ({
  enterDraft: mockEnterDraft,
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

import { checkDraftInContext, enterRequestDraft } from '../../../src/http/httpServer-draft';

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

describe('enterRequestDraft', () => {
  const response = (ended = false) => Object.assign(new EventEmitter(), { closed: ended, destroyed: false });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should leave a request outside any draft untouched', async () => {
    const executeContext = { draft_context: '' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, response());

    expect(mockEnterDraft).not.toHaveBeenCalled();
    expect(executeContext.draft_writer_id).toBeUndefined();
  });

  it('should move the request to the draft taking over and release its lease when the response ends', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-2', closed: false, writerId: 'writer-1', release });
    const executeContext = { draft_context: 'draft-1' } as unknown as AuthContext;
    const res = response();

    await enterRequestDraft(executeContext, res);

    expect(mockEnterDraft).toHaveBeenCalledWith('draft-1');
    expect(executeContext).toMatchObject({ draft_context: 'draft-2', draft_forward_closed: false, draft_writer_id: 'writer-1' });
    expect(release).not.toHaveBeenCalled();
    res.emit('close');
    expect(release).toHaveBeenCalledTimes(1);
  });

  it('should release at once the lease of a request whose response already ended', async () => {
    const release = vi.fn().mockResolvedValue(undefined);
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-1', closed: false, writerId: 'writer-1', release });

    await enterRequestDraft({ draft_context: 'draft-1' } as unknown as AuthContext, response(true));

    expect(release).toHaveBeenCalledTimes(1);
  });

  it('should flag a request whose draft chain ended, holding no lease', async () => {
    mockEnterDraft.mockResolvedValue({ draftId: 'draft-1', closed: true, writerId: null, release: vi.fn() });
    const executeContext = { draft_context: 'draft-1' } as unknown as AuthContext;

    await enterRequestDraft(executeContext, response());

    expect(executeContext).toMatchObject({ draft_context: 'draft-1', draft_forward_closed: true, draft_writer_id: null });
  });
});
