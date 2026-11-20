import { beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import useSettingsFallbackUrl from './useSettingsFallbackUrl';

let capabilities: string[] = [];
let draftContext: { id: string } | null = null;
vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useAuth')>()),
  default: () => ({ me: { capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [], draftContext } }),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => true, isTrashEnable: () => true }) }));
vi.mock('../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => [] }));

const fallback = () => testRenderHook(() => useSettingsFallbackUrl()).hook.result.current;

describe('Hook: useSettingsFallbackUrl', () => {
  beforeEach(() => {
    capabilities = [];
    draftContext = null;
  });

  it('is the first Settings page the user can open', () => {
    capabilities = ['SETTINGS_SETPARAMETERS', 'SETTINGS_SETLABELS'];
    expect(fallback()).toBe('/dashboard/settings');
    capabilities = ['SETTINGS_SETLABELS'];
    expect(fallback()).toBe('/dashboard/settings/vocabularies/labels');
  });

  // The first open leaf of the left bar, not a section root.
  it.each([
    ['VIRTUAL_ORGANIZATION_ADMIN', '/dashboard/settings/accesses/users'],
    ['SETTINGS_SETAUTH', '/dashboard/settings/accesses/authentications'],
    ['SETTINGS_SETMARKINGS', '/dashboard/settings/accesses/marking'],
    ['SETTINGS_SETCUSTOMIZATION', '/dashboard/settings/customization/entity_types'],
    ['SETTINGS_SECURITYACTIVITY', '/dashboard/settings/activity/audit'],
    ['SETTINGS_FILEINDEXING', '/dashboard/settings/file_indexing'],
    ['SETTINGS_SUPPORT', '/dashboard/settings/experience'],
  ])('with only %s, is %s', (capability, url) => {
    capabilities = [capability];
    expect(fallback()).toBe(url);
  });

  it('is the home page for a user with no Settings capability', () => {
    capabilities = ['KNOWLEDGE'];
    expect(fallback()).toBe('/dashboard');
  });

  it('is the home page in a draft, where Settings is closed even to an administrator', () => {
    capabilities = ['BYPASS'];
    expect(fallback()).toBe('/dashboard/settings');
    draftContext = { id: 'draft-id' };
    expect(fallback()).toBe('/dashboard');
  });
});
