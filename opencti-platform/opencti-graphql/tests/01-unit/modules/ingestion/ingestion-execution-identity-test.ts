import { beforeEach, describe, expect, it, vi } from 'vitest';

const { resolveUserByIdMock, resolveUserByIdFromCacheMock, createOnTheFlyUserMock, userDeleteMock } = vi.hoisted(() => ({
  resolveUserByIdMock: vi.fn(),
  resolveUserByIdFromCacheMock: vi.fn(),
  createOnTheFlyUserMock: vi.fn(),
  userDeleteMock: vi.fn(),
}));

vi.mock('../../../../src/modules/user/user-domain', () => ({
  resolveUserById: resolveUserByIdMock,
  resolveUserByIdFromCache: resolveUserByIdFromCacheMock,
  createOnTheFlyUser: createOnTheFlyUserMock,
  userDelete: userDeleteMock,
}));

import type { AuthContext, AuthUser } from '../../../../src/types/user';
import {
  assertIngestionExecutionIdentityAllowed,
  createIngestionAutomaticUser,
  isIngestionUserWithinCreatorRights,
  validateIngestionExecutionIdentity,
  validateIngestionExecutionIdentityFromEditInputs,
} from '../../../../src/modules/ingestion/ingestion-execution-identity';

interface UserFixture {
  id?: string;
  capabilities?: string[];
  markings?: string[];
  confidence?: number | null;
  overrides?: { entity_type: string; max_confidence: number }[];
}

const buildUser = ({ id = 'user-id', capabilities = [], markings = [], confidence = null, overrides = [] }: UserFixture = {}): AuthUser => ({
  id,
  internal_id: id,
  capabilities: capabilities.map((name) => ({ name })),
  allowed_marking: markings.map((internal_id) => ({ internal_id })),
  effective_confidence_level: confidence === null && overrides.length === 0 ? null : { max_confidence: confidence, overrides },
} as unknown as AuthUser);

const context = {} as AuthContext;

describe('Ingestion execution identity confinement', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('rights inclusion rule', () => {
    it('should accept an identity holding the same capabilities as the creator', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      const target = buildUser({ capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(true);
    });

    it('should accept an identity holding a subset of the creator capabilities', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      const target = buildUser({ capabilities: ['KNOWLEDGE'] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(true);
    });

    it('should reject an identity holding a capability the creator does not have', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      const target = buildUser({ capabilities: ['KNOWLEDGE', 'SETTINGS_SETACCESSES'] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should reject an identity holding BYPASS when the creator does not', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      const target = buildUser({ capabilities: ['BYPASS'] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should accept any identity when the creator holds BYPASS', () => {
      const creator = buildUser({ capabilities: ['BYPASS'] });
      const target = buildUser({ capabilities: ['BYPASS'], markings: ['marking-restricted'], confidence: 100 });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(true);
    });

    it('should reject an identity allowed on a marking the creator cannot see', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], markings: ['marking-green'] });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], markings: ['marking-green', 'marking-red'] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should reject an identity with a confidence level above the creator one', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 50 });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 80 });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should accept an identity with a confidence level below the creator one', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 80 });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 50 });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(true);
    });

    it('should reject an identity whose per entity type confidence override exceeds the creator ceiling', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 50 });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 10, overrides: [{ entity_type: 'Report', max_confidence: 100 }] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should accept an identity whose confidence override stays below the creator override', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 50, overrides: [{ entity_type: 'Report', max_confidence: 90 }] });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 10, overrides: [{ entity_type: 'Report', max_confidence: 80 }] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(true);
    });
  });

  describe('creation validation', () => {
    it('should reject when the chosen identity exceeds the creator rights', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'target', capabilities: ['SETTINGS_SETACCESSES'] }));
      await expect(validateIngestionExecutionIdentity(context, creator, 'target')).rejects.toThrowError();
    });

    it('should accept when the chosen identity rights are included in the creator ones', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'target', capabilities: ['KNOWLEDGE'] }));
      await expect(validateIngestionExecutionIdentity(context, creator, 'target')).resolves.toBeUndefined();
    });

    it('should reject an identity that does not exist', async () => {
      const creator = buildUser({ capabilities: ['BYPASS'] });
      resolveUserByIdMock.mockResolvedValue(undefined);
      await expect(validateIngestionExecutionIdentity(context, creator, 'unknown')).rejects.toThrowError();
    });

    it('should not disclose the target rights in the rejection error', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'target', capabilities: ['SETTINGS_SETACCESSES'] }));
      await expect(validateIngestionExecutionIdentity(context, creator, 'target'))
        .rejects.toThrowError('You are not allowed to use this user for this ingestion');
    });

    it('should refuse an identity-less ingestion when the creator does not hold every right', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      await expect(validateIngestionExecutionIdentity(context, creator, undefined)).rejects.toThrowError();
      expect(resolveUserByIdMock).not.toHaveBeenCalled();
    });

    it('should accept an identity-less ingestion when the creator holds every right', async () => {
      const creator = buildUser({ capabilities: ['BYPASS'] });
      await expect(validateIngestionExecutionIdentity(context, creator, '')).resolves.toBeUndefined();
      expect(resolveUserByIdMock).not.toHaveBeenCalled();
    });
  });

  describe('edition validation', () => {
    it('should apply the same validation when the identity is changed', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'target', capabilities: ['SETTINGS_SETACCESSES'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, creator, [{ key: 'user_id', value: ['target'] }]))
        .rejects.toThrowError();
    });

    it('should not resolve any identity when the edition does not change it', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, creator, [{ key: 'name', value: ['a name'] }]))
        .resolves.toBeUndefined();
      expect(resolveUserByIdMock).not.toHaveBeenCalled();
    });
  });

  describe('automatically created identity', () => {
    it('should keep the generated user when it stays within the creator rights', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      createOnTheFlyUserMock.mockResolvedValue({ id: 'generated' });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'generated', capabilities: ['KNOWLEDGE'] }));
      const created = await createIngestionAutomaticUser(context, creator, { userName: 'feed', serviceAccount: true, confidenceLevel: null });
      expect(created.id).toEqual('generated');
      expect(userDeleteMock).not.toHaveBeenCalled();
    });

    it('should reject and roll back the generated user when it exceeds the creator rights', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      createOnTheFlyUserMock.mockResolvedValue({ id: 'generated' });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'generated', capabilities: ['BYPASS'] }));
      await expect(createIngestionAutomaticUser(context, creator, { userName: 'feed', serviceAccount: true, confidenceLevel: null }))
        .rejects.toThrowError();
      expect(userDeleteMock).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'generated');
    });
  });

  describe('execution time guard', () => {
    it('should allow the execution when the stored identity is still covered by a creator', async () => {
      resolveUserByIdFromCacheMock.mockImplementation(async (_: AuthContext, id: string) => {
        if (id === 'target') return buildUser({ id: 'target', capabilities: ['KNOWLEDGE'] });
        return buildUser({ id: 'creator', capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      });
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: 'target', creator_id: 'creator' }))
        .resolves.toBeUndefined();
    });

    it('should refuse the execution when the creator rights no longer cover the stored identity', async () => {
      resolveUserByIdFromCacheMock.mockImplementation(async (_: AuthContext, id: string) => {
        if (id === 'target') return buildUser({ id: 'target', capabilities: ['SETTINGS_SETACCESSES'] });
        return buildUser({ id: 'creator', capabilities: ['KNOWLEDGE'] });
      });
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: 'target', creator_id: ['creator'] }))
        .rejects.toThrowError();
    });

    it('should refuse the execution when the stored identity no longer exists', async () => {
      resolveUserByIdFromCacheMock.mockResolvedValue(undefined);
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: 'target', creator_id: 'creator' }))
        .rejects.toThrowError();
    });

    it('should refuse the execution of an identity-less feed when the creator does not hold every right', async () => {
      resolveUserByIdFromCacheMock.mockResolvedValue(buildUser({ id: 'creator', capabilities: ['KNOWLEDGE'] }));
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: undefined, creator_id: 'creator' }))
        .rejects.toThrowError();
    });

    it('should allow the execution of an identity-less feed when the creator holds every right', async () => {
      resolveUserByIdFromCacheMock.mockResolvedValue(buildUser({ id: 'creator', capabilities: ['BYPASS'] }));
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: undefined, creator_id: 'creator' }))
        .resolves.toBeUndefined();
    });
  });
});
