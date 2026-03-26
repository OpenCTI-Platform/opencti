import { describe, it, expect } from 'vitest';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import useSettingsFallbackUrl from './useSettingsFallbackUrl';
import {
  SETTINGS_FILEINDEXING,
  SETTINGS_SECURITYACTIVITY,
  SETTINGS_SETACCESSES,
  SETTINGS_SETAUTH,
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETDISSEMINATION,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMANAGEXTMHUB,
  SETTINGS_SETMARKINGS,
  SETTINGS_SETPARAMETERS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
  SETTINGS_SUPPORT,
  VIRTUAL_ORGANIZATION_ADMIN,
} from './useGranted';

const buildUserContext = (capabilities: string[]) => createMockUserContext({
  me: {
    id: 'test-user-id',
    capabilities: capabilities.map((name) => ({ name })),
    capabilitiesInDraft: [],
    draftContext: null,
  },
});

describe('Hook: useSettingsFallbackUrl', () => {
  // --- Priority: SETTINGS_SETPARAMETERS ---

  it('should return /dashboard/settings when user has SETTINGS_SETPARAMETERS', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETPARAMETERS]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings');
  });

  it('should prioritize SETTINGS_SETPARAMETERS over SETTINGS_SETACCESSES', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETPARAMETERS, SETTINGS_SETACCESSES]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings');
  });

  // --- Priority: SETTINGS_SETACCESSES / VIRTUAL_ORGANIZATION_ADMIN ---

  it('should return /dashboard/settings/accesses when user has SETTINGS_SETACCESSES', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETACCESSES]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses');
  });

  it('should return /dashboard/settings/accesses when user has VIRTUAL_ORGANIZATION_ADMIN', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([VIRTUAL_ORGANIZATION_ADMIN]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses');
  });

  it('should prioritize SETTINGS_SETACCESSES over SETTINGS_SETMARKINGS', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETACCESSES, SETTINGS_SETMARKINGS]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses');
  });

  // --- Priority: SETTINGS_SETMARKINGS ---

  it('should return /dashboard/settings/accesses/marking when user has only SETTINGS_SETMARKINGS', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETMARKINGS]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses/marking');
  });

  it('should prioritize SETTINGS_SETMARKINGS over SETTINGS_SETDISSEMINATION', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETMARKINGS, SETTINGS_SETDISSEMINATION]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses/marking');
  });

  // --- Priority: SETTINGS_SETDISSEMINATION ---

  it('should return /dashboard/settings/accesses/dissemination_list when user has only SETTINGS_SETDISSEMINATION', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETDISSEMINATION]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses/dissemination_list');
  });

  it('should prioritize SETTINGS_SETDISSEMINATION over SETTINGS_SETAUTH', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETDISSEMINATION, SETTINGS_SETAUTH]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses/dissemination_list');
  });

  // --- Priority: SETTINGS_SETAUTH ---

  it('should return /dashboard/settings/accesses/authentications when user has only SETTINGS_SETAUTH', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETAUTH]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/accesses/authentications');
  });

  // --- Priority: SETTINGS_SETCUSTOMIZATION ---

  it('should return /dashboard/settings/customization when user has SETTINGS_SETCUSTOMIZATION', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETCUSTOMIZATION]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/customization');
  });

  it('should prioritize SETTINGS_SETCUSTOMIZATION over SETTINGS_SETLABELS', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETCUSTOMIZATION, SETTINGS_SETLABELS]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/customization');
  });

  // --- Priority: Taxonomies (SETTINGS_SETLABELS / SETVOCABULARIES / SETKILLCHAINPHASES / SETCASETEMPLATES / SETSTATUSTEMPLATES) ---

  it('should return /dashboard/settings/vocabularies when user has SETTINGS_SETLABELS', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETLABELS]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/vocabularies');
  });

  it('should return /dashboard/settings/vocabularies when user has SETTINGS_SETVOCABULARIES', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETVOCABULARIES]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/vocabularies');
  });

  it('should return /dashboard/settings/vocabularies when user has SETTINGS_SETKILLCHAINPHASES', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETKILLCHAINPHASES]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/vocabularies');
  });

  it('should return /dashboard/settings/vocabularies when user has SETTINGS_SETCASETEMPLATES', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETCASETEMPLATES]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/vocabularies');
  });

  it('should return /dashboard/settings/vocabularies when user has SETTINGS_SETSTATUSTEMPLATES', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETSTATUSTEMPLATES]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/vocabularies');
  });

  // --- Priority: SETTINGS_SECURITYACTIVITY ---

  it('should return /dashboard/settings/activity when user has SETTINGS_SECURITYACTIVITY', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SECURITYACTIVITY]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/activity');
  });

  it('should prioritize SETTINGS_SECURITYACTIVITY over SETTINGS_FILEINDEXING', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SECURITYACTIVITY, SETTINGS_FILEINDEXING]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/activity');
  });

  // --- Priority: SETTINGS_FILEINDEXING ---

  it('should return /dashboard/settings/file_indexing when user has SETTINGS_FILEINDEXING', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_FILEINDEXING]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/file_indexing');
  });

  // --- Priority: Experience (SETTINGS_SUPPORT / SETTINGS_SETMANAGEXTMHUB) ---

  it('should return /dashboard/settings/experience when user has SETTINGS_SUPPORT', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SUPPORT]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/experience');
  });

  it('should return /dashboard/settings/experience when user has SETTINGS_SETMANAGEXTMHUB', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([SETTINGS_SETMANAGEXTMHUB]) },
    );
    expect(hook.result.current).toBe('/dashboard/settings/experience');
  });

  // --- Fallback ---

  it('should return /dashboard when user has no relevant capability', () => {
    const { hook } = testRenderHook(
      () => useSettingsFallbackUrl(),
      { userContext: buildUserContext([]) },
    );
    expect(hook.result.current).toBe('/dashboard');
  });
});

