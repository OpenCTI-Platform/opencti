import { describe, it, expect } from 'vitest';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import useImportAccess from './useImportAccess';
import { KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPDATE } from './useGranted';

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

describe('Hook: useImportAccess - form intake capability', () => {
  it('should not force a draft when the form intake capability is granted in main', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNFORMINTAKE]) },
    );
    expect(hook.result.current.isForcedImportToDraft).toBe(false);
  });

  it('should force a draft when the form intake capability is only granted in draft', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([], [KNOWLEDGE_KNFORMINTAKE]) },
    );
    expect(hook.result.current.isForcedImportToDraft).toBe(true);
  });

  it('should not force a draft when the form intake capability is in draft but Create / Update knowledge is in main', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNUPDATE], [KNOWLEDGE_KNFORMINTAKE]) },
    );
    expect(hook.result.current.isForcedImportToDraft).toBe(false);
  });

  it('should not open the other import modes to a form-only user', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNFORMINTAKE]) },
    );
    expect(hook.result.current.hasOnlyAccessToImportDraftTab).toBe(false);
  });

  it('should only offer the forms to a user who can submit forms but not import files', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNFORMINTAKE]) },
    );
    expect(hook.result.current.hasOnlyAccessToFormImport).toBe(true);
  });

  it('should also offer only the forms when the form capability is granted in draft only', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([], [KNOWLEDGE_KNFORMINTAKE]) },
    );
    expect(hook.result.current.hasOnlyAccessToFormImport).toBe(true);
  });

  it('should not restrict a user who can import files to the forms', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNASKIMPORT]) },
    );
    expect(hook.result.current.hasOnlyAccessToFormImport).toBe(false);
  });

  it('should not offer forms without the form capability', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNUPDATE]) },
    );
    expect(hook.result.current.hasOnlyAccessToFormImport).toBe(false);
  });
});

describe('Hook: useImportAccess - canOpenDraft', () => {
  it.each([
    ['a form-only user in main', [KNOWLEDGE_KNFORMINTAKE], [], false],
    ['a form-only user in draft', [], [KNOWLEDGE_KNFORMINTAKE], false],
    ['a user who can only import', [KNOWLEDGE_KNASKIMPORT], [], false],
    ['a user with Create / Update knowledge in main', [KNOWLEDGE_KNUPDATE], [], true],
    ['a user with Create / Update knowledge in draft only', [], [KNOWLEDGE_KNUPDATE], true],
  ])('%s', (_name, capabilities, capabilitiesInDraft, expected) => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext(capabilities, capabilitiesInDraft) },
    );
    expect(hook.result.current.canOpenDraft).toBe(expected);
  });
});

describe('Hook: useImportAccess - isForcedFormSubmissionToDraft', () => {
  it.each([
    // the form capability in main lets the submission stay in main, whatever is granted in draft
    { capabilities: [KNOWLEDGE_KNFORMINTAKE], capabilitiesInDraft: [KNOWLEDGE_KNUPDATE], expected: false },
    { capabilities: [KNOWLEDGE_KNFORMINTAKE], capabilitiesInDraft: [KNOWLEDGE_KNASKIMPORT], expected: false },
    { capabilities: [KNOWLEDGE_KNFORMINTAKE], capabilitiesInDraft: [], expected: false },
    // without it, the forcing of the import applies
    { capabilities: [], capabilitiesInDraft: [KNOWLEDGE_KNFORMINTAKE], expected: true },
    { capabilities: [], capabilitiesInDraft: [KNOWLEDGE_KNUPDATE], expected: true },
    { capabilities: [KNOWLEDGE_KNUPDATE], capabilitiesInDraft: [], expected: false },
  ])('should be $expected with $capabilities in main and $capabilitiesInDraft in draft', ({ capabilities, capabilitiesInDraft, expected }) => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext(capabilities, capabilitiesInDraft) },
    );
    expect(hook.result.current.isForcedFormSubmissionToDraft).toBe(expected);
  });

  it('should keep forcing the file import of a user with Create / Update knowledge in draft only', () => {
    const { hook } = testRenderHook(
      () => useImportAccess(),
      { userContext: buildUserContext([KNOWLEDGE_KNFORMINTAKE], [KNOWLEDGE_KNUPDATE]) },
    );
    expect(hook.result.current.isForcedImportToDraft).toBe(true);
    expect(hook.result.current.hasKnowledgeUpdateInMain).toBe(false);
  });
});
