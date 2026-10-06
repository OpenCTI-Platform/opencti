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
  validateStoredIngestionExecutionIdentity,
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

    it('should accept an identity carrying no confidence level at all', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 50 });
      const target = buildUser({ capabilities: ['KNOWLEDGE'] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(true);
    });

    it('should reject an identity with a confidence level when the creator has none', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], confidence: 10 });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should reject an identity whose only confidence override exceeds a creator without confidence level', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      const target = buildUser({ capabilities: ['KNOWLEDGE'], overrides: [{ entity_type: 'Report', max_confidence: 70 }] });
      expect(isIngestionUserWithinCreatorRights(creator, target)).toBe(false);
    });

    it('should accept an identity holding no capability nor marking', () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'], markings: ['marking-green'] });
      const target = { id: 'target', internal_id: 'target' } as unknown as AuthUser;
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
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, creator, { user_id: 'stored' }, [{ key: 'user_id', value: ['target'] }]))
        .rejects.toThrowError();
    });

    it('should not resolve any identity when the edition only touches fields without effect on the execution', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, creator, { user_id: 'stored' }, [{ key: 'name', value: ['a name'] }]))
        .resolves.toBeUndefined();
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, creator, { user_id: 'stored' }, [
        { key: 'ingestion_running', value: ['false'] },
        { key: 'description', value: ['a description'] },
      ])).resolves.toBeUndefined();
      expect(resolveUserByIdMock).not.toHaveBeenCalled();
    });

    it('should validate the stored identity when only the uri is changed', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'stored', capabilities: ['SETTINGS_SETACCESSES'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [{ key: 'uri', value: ['http://fakefeed.invalid'] }]))
        .rejects.toThrowError();
      expect(resolveUserByIdMock).toHaveBeenCalledWith(context, 'stored');
    });

    it('should validate the stored identity when the authorized members are changed', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'stored', capabilities: ['SETTINGS_SETACCESSES'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [{ key: 'authorized_members', value: ['editor-id'] }]))
        .rejects.toThrowError();
    });

    it('should validate the stored identity when a field without effect is mixed with a sensitive one', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'stored', capabilities: ['SETTINGS_SETACCESSES'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [
        { key: 'ingestion_running', value: ['true'] },
        { key: 'uri', value: ['http://fakefeed.invalid'] },
      ])).rejects.toThrowError();
    });

    it('should accept an uri edition when the stored identity stays within the editor rights', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'stored', capabilities: ['KNOWLEDGE'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [{ key: 'uri', value: ['http://fakefeed.invalid'] }]))
        .resolves.toBeUndefined();
    });

    it('should validate the new identity instead of the stored one when the identity is changed', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'target', capabilities: ['KNOWLEDGE'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [
        { key: 'user_id', value: ['target'] },
        { key: 'uri', value: ['http://fakefeed.invalid'] },
      ])).resolves.toBeUndefined();
      expect(resolveUserByIdMock).toHaveBeenCalledWith(context, 'target');
      expect(resolveUserByIdMock).not.toHaveBeenCalledWith(context, 'stored');
    });

    it('should treat a stored ingestion without identity as a system identity', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE'] });
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: null }, [{ key: 'uri', value: ['http://fakefeed.invalid'] }]))
        .rejects.toThrowError();
      expect(resolveUserByIdMock).not.toHaveBeenCalled();
    });

    it('should let an editor holding every right repair a feed whose stored identity was deleted', async () => {
      const editor = buildUser({ capabilities: ['BYPASS'] });
      resolveUserByIdMock.mockResolvedValue(undefined);
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'deleted' }, [{ key: 'uri', value: ['http://fakefeed.invalid'] }]))
        .resolves.toBeUndefined();
      await expect(validateStoredIngestionExecutionIdentity(context, editor, { user_id: 'deleted' })).resolves.toBeUndefined();
    });

    it('should still reject a deleted stored identity for an editor not holding every right', async () => {
      const editor = buildUser({ capabilities: ['KNOWLEDGE'] });
      resolveUserByIdMock.mockResolvedValue(undefined);
      await expect(validateStoredIngestionExecutionIdentity(context, editor, { user_id: 'deleted' })).rejects.toThrowError();
    });

    it('should still reject a newly chosen identity that does not exist, even for an editor holding every right', async () => {
      const editor = buildUser({ capabilities: ['BYPASS'] });
      resolveUserByIdMock.mockResolvedValue(undefined);
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [{ key: 'user_id', value: ['unknown'] }]))
        .rejects.toThrowError();
    });

    it('should accept any edition from an editor holding every right', async () => {
      const editor = buildUser({ capabilities: ['BYPASS'] });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'stored', capabilities: ['BYPASS'] }));
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, editor, { user_id: 'stored' }, [{ key: 'uri', value: ['http://fakefeed.invalid'] }]))
        .resolves.toBeUndefined();
    });

    it('should treat an edition clearing the identity as a system identity', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      await expect(validateIngestionExecutionIdentityFromEditInputs(context, creator, { user_id: 'stored' }, [{ key: 'user_id', value: [] }]))
        .rejects.toThrowError();
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

    it('should still reject when the generated user cannot be rolled back', async () => {
      const creator = buildUser({ capabilities: ['KNOWLEDGE'] });
      createOnTheFlyUserMock.mockResolvedValue({ id: 'generated' });
      resolveUserByIdMock.mockResolvedValue(buildUser({ id: 'generated', capabilities: ['BYPASS'] }));
      userDeleteMock.mockRejectedValue(new Error('deletion unavailable'));
      await expect(createIngestionAutomaticUser(context, creator, { userName: 'feed', serviceAccount: true, confidenceLevel: null }))
        .rejects.toThrowError('You are not allowed to use this user for this ingestion');
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

    it('should allow the execution when one of the creators covers the stored identity', async () => {
      resolveUserByIdFromCacheMock.mockImplementation(async (_: AuthContext, id: string) => {
        if (id === 'target') return buildUser({ id: 'target', capabilities: ['KNOWLEDGE'] });
        if (id === 'narrow-creator') return buildUser({ id: 'narrow-creator', capabilities: [] });
        return buildUser({ id: 'wide-creator', capabilities: ['KNOWLEDGE', 'INGESTION_SETINGESTIONS'] });
      });
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: 'target', creator_id: ['narrow-creator', 'wide-creator'] }))
        .resolves.toBeUndefined();
    });

    it('should let the execution continue when no creator can be resolved anymore', async () => {
      resolveUserByIdFromCacheMock.mockImplementation(async (_: AuthContext, id: string) => {
        if (id === 'target') return buildUser({ id: 'target', capabilities: ['KNOWLEDGE'] });
        return undefined;
      });
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', name: 'a feed', user_id: 'target', creator_id: 'gone' }))
        .resolves.toBeUndefined();
    });

    it('should let the execution continue when the feed carries no creator', async () => {
      resolveUserByIdFromCacheMock.mockResolvedValue(buildUser({ id: 'target', capabilities: ['KNOWLEDGE'] }));
      await expect(assertIngestionExecutionIdentityAllowed(context, { id: 'feed', user_id: 'target', creator_id: undefined }))
        .resolves.toBeUndefined();
    });
  });
});
