import { beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../../utils/tests/test-render';
import useFirstVisiblePath from './useFirstVisiblePath';
import { sectionEntries } from '../../nav/navSections';

let capabilities: string[] = [];
let hiddenEntities: string[] = [];
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useAuth')>()),
  default: () => ({ me: { capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [], draftContext: null } }),
}));
vi.mock('../../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => true, isTrashEnable: () => true }) }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => hiddenEntities }));

// Real entries: a section lands on its first page in left bar order, the same as the section link of the left bar.
const arsenal = () => testRenderHook(() => useFirstVisiblePath(sectionEntries('arsenal'))).hook.result.current;

describe('Hook: useFirstVisiblePath', () => {
  beforeEach(() => {
    capabilities = ['KNOWLEDGE'];
    hiddenEntities = [];
  });

  it('is the first page of the section', () => {
    expect(arsenal()).toBe('/dashboard/arsenal/malwares');
  });

  it('skips a page whose entity type is hidden', () => {
    hiddenEntities = ['Malware'];
    expect(arsenal()).toBe('/dashboard/arsenal/channels');
  });

  it('is the fallback when no page is open, never a broken url', () => {
    hiddenEntities = ['Malware', 'Channel', 'Tool', 'Vulnerability'];
    expect(arsenal()).toBe('/dashboard');
    hiddenEntities = [];
    capabilities = [];
    expect(arsenal()).toBe('/dashboard');
  });
});
