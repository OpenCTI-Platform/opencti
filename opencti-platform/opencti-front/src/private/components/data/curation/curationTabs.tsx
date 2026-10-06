import React, { type ComponentType, type LazyExoticComponent } from 'react';
import AutoFixHighOutlined from '@mui/icons-material/AutoFixHighOutlined';
import type { HubBadgeCount } from '../../common/hub/HubCountBadge';
import type { HubEntry } from '../../common/hub/HubEntryContext';
import { sortedHubEntries } from '../../common/hub/hubRegistry';
import type { ModuleHelper } from '../../../../utils/platformModulesHelper';

export const PATH_CURATION = '/dashboard/data/curation';

export const CURATION_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/curation-hub/';

/** The hub itself, as its landing page names it while no tab is registered. */
export const CURATION_HUB: HubEntry = {
  label: 'Curation',
  description: 'Keep your knowledge base clean and trustworthy, from one place.',
  icon: <AutoFixHighOutlined />,
};

export interface CurationTab {
  /** Position in the hub, unique across the tabs: lower comes first. */
  order: number;
  /** Route segment under `/dashboard/data/curation`, also the tab value. */
  path: string;
  /** English source string, translated by the hub. */
  label: string;
  /** English source string: the question the tab answers, shown by its first-use state. */
  description?: string;
  /** When set, the tab is listed and routed only for a user granted one of these capabilities. */
  needs?: string[];
  /** When set, the tab (and its badge query) only exists while the platform module it belongs to is enabled. */
  isAvailable?: (modules: ModuleHelper) => boolean;
  /** Pending work in the tab (proposals to review), shown on the tab and summed on the menu item; never a total. */
  useBadgeCount?: HubBadgeCount;
  /** Mounted at `/dashboard/data/curation/<path>/*`; renders the tab's content only, the hub owns the page. */
  component: LazyExoticComponent<ComponentType>;
}

/**
 * The tabs of the Curation hub, the data-quality home of Data: one file per tab in `./tabs/`, whose
 * default export is its `CurationTab`, so each tab is added without touching the others or any shared
 * navigation file (see `.github/instructions/frontend/patterns/navigation.md`). No tab is registered
 * here: each one comes with the feature that provides it, and until then the hub lands on its
 * first-use page.
 */
const tabModules = import.meta.glob<CurationTab>('./tabs/*.tsx', { eager: true, import: 'default' });

export const CURATION_TABS: CurationTab[] = sortedHubEntries(tabModules);

export const grantedCurationTabs = (
  tabs: CurationTab[],
  isGranted: (needs: string[]) => boolean = () => true,
  modules?: ModuleHelper,
): CurationTab[] => tabs
  .filter((tab) => !tab.isAvailable || !modules || tab.isAvailable(modules))
  .filter((tab) => !tab.needs || isGranted(tab.needs));
