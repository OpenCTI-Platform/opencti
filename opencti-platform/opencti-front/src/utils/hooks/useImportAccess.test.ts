import { describe, it, expect } from 'vitest';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import useImportAccess from './useImportAccess';
import { KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPDATE } from './useGranted';

const cap = (name: string) => ({ name });

const buildUserContext = (capabilities: string[], capabilitiesInDraft: string[] = []) => createMockUserContext({
  me: {
    id: 'test-user-id',
    capabilities: capabilities.map(cap),
    capabilitiesInDraft: capabilitiesInDraft.map(cap),
    draftContext: null,
  },
});

describe('Hook: useImportAccess', () => {
  describe('hasOnlyAccessToImportDraftTab', () => {
    it('should be false when user has no capabilities', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
    });

    it('should be false when user has KNOWLEDGE_KNASKIMPORT in base (full import access)', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNASKIMPORT]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
    });

    it('should be true when user has KNOWLEDGE_KNUPDATE in base (but not KNOWLEDGE_KNASKIMPORT)', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNUPDATE]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(true);
    });

    it('should be true when user has KNOWLEDGE_KNUPDATE in draft only', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([], [KNOWLEDGE_KNUPDATE]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(true);
    });

    it('should be false when user has only KNOWLEDGE_KNGETEXPORT (read-only capability)', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNGETEXPORT]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
    });

    it('should be false when user has only KNOWLEDGE_KNGETEXPORT in draft', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([], [KNOWLEDGE_KNGETEXPORT]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
    });

    it('should be false when user has only the base KNOWLEDGE capability (read-only access)', () => {
      // Regression: old code matched any capability containing 'KNOWLEDGE', granting incorrect access
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
    });

    it('should be false when user has only the base KNOWLEDGE capability in draft', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([], [KNOWLEDGE]) },
      );
      expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
    });
  });

  describe('isForcedImportToDraft', () => {
    it('should be false when user has no capabilities', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(false);
    });

    it('should be false when user has KNOWLEDGE_KNASKIMPORT in base', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNASKIMPORT]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(false);
    });

    it('should be true when user has KNOWLEDGE_KNASKIMPORT in draft only', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([], [KNOWLEDGE_KNASKIMPORT]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(true);
    });

    it('should be true when user has KNOWLEDGE_KNUPDATE in draft only', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([], [KNOWLEDGE_KNUPDATE]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(true);
    });

    it('should be false when user has KNOWLEDGE_KNUPDATE in base (not forced to draft)', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNUPDATE]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(false);
    });

    it('should be true when user has KNOWLEDGE_KNASKIMPORT in base but KNOWLEDGE_KNUPDATE only in draft', () => {
      // Even with full import access, having KNUPDATE only in draft means edits must go through draft
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNASKIMPORT], [KNOWLEDGE_KNUPDATE]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(true);
    });

    it('should be false when user has both KNOWLEDGE_KNASKIMPORT and KNOWLEDGE_KNUPDATE in base', () => {
      const { hook } = testRenderHook(
        () => useImportAccess(),
        { userContext: buildUserContext([KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE]) },
      );
      expect(hook.result.current.isForcedImportToDraft).toBe(false);
    });
  });
});
