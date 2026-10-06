import { lazy } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import { CURATION_TABS, type CurationTab } from '../data/curation/curationTabs';
import useNavMenu, { type NavGroup } from './useNavMenu';

vi.mock('../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useGranted')>()),
  default: () => true,
}));
vi.mock('../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useEntitySettings')>()),
  useHiddenEntities: () => [],
  useIsHiddenEntities: () => false,
}));
vi.mock('../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: () => false, isTrashEnable: () => false }),
}));
vi.mock('../../../utils/hooks/useImportAccess', () => ({
  default: () => ({ hasOnlyAccessToImportDraftTab: false }),
}));

const lazyNothing = lazy(async () => ({ default: () => null }));
const tab = (path: string, label: string): CurationTab => ({ order: 0, path, label, component: lazyNothing });

const menu = (): NavGroup[] => testRenderHook(() => useNavMenu()).hook.result.current;
const dataLinks = (groups: NavGroup[]) => groups
  .find((g) => g.id === 'data')?.items.find((i) => i.id === 'data')?.subItems?.map((s) => s.link);

// The registry is a module-level array the product registers its tabs into: each test starts from
// an empty one and gets the registered tabs back afterwards.
let registeredTabs: CurationTab[] = [];
beforeEach(() => {
  registeredTabs = CURATION_TABS.splice(0);
});
afterEach(() => {
  CURATION_TABS.splice(0, CURATION_TABS.length, ...registeredTabs);
});

describe('useNavMenu - Curation hub', () => {
  it('adds no Curation row to Data while no tab is registered', () => {
    expect(dataLinks(menu())).not.toContain('/dashboard/data/curation');
  });

  it('lists Curation right after Relationships once a tab is registered', () => {
    CURATION_TABS.push(tab('inbox', 'Inbox'));
    const links = dataLinks(menu()) ?? [];
    expect(links.slice(0, 3)).toEqual(['/dashboard/data/entities', '/dashboard/data/relationships', '/dashboard/data/curation']);
  });

  it('sums the pending counts of the tabs on the Curation row, and shows none without counting tabs', () => {
    const curationRow = () => menu().find((g) => g.id === 'data')?.items.find((i) => i.id === 'data')
      ?.subItems?.find((s) => s.link === '/dashboard/data/curation');
    CURATION_TABS.push(tab('merges', 'Merges'));
    expect(curationRow()?.badge).toBeUndefined();
    CURATION_TABS.push({ ...tab('inbox', 'Inbox'), useBadgeCount: () => 2 });
    expect(curationRow()?.badge).toBeTruthy();
  });
});
