import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const { mockGetEntitiesMapFromCache, mockIsUserCanAccessStoreElement, mockUserEditField } = vi.hoisted(() => ({
  mockGetEntitiesMapFromCache: vi.fn(),
  mockIsUserCanAccessStoreElement: vi.fn(),
  mockUserEditField: vi.fn(),
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

vi.mock('../../../src/domain/user', () => ({
  userEditField: mockUserEditField,
}));

import { checkDraftInContext } from '../../../src/http/httpServer-draft';

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
