import type { ComponentType, LazyExoticComponent } from 'react';
import type { HubBadgeCount } from '../../common/hub/HubCountBadge';
import type { ModuleHelper } from '../../../../utils/platformModulesHelper';

export const PATH_CURATION = '/dashboard/data/curation';

export interface CurationTab {
  /** Position in the hub, lowest first: Conflicts 20, Stale knowledge 30. */
  order: number;
  /** Route segment under `/dashboard/data/curation`, also the tab value. */
  path: string;
  /** English source string, translated by the hub. */
  label: string;
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
 * The tabs of the Curation hub, the data-quality home of Data (information architecture directive,
 * OpenCTI-Platform/opencti#18685): one file per tab in `./tabs/`, whose default export is its
 * `CurationTab`, so each tab is added without touching the others. The hub and its menu entry only
 * exist while a tab is registered.
 */
const tabModules = import.meta.glob<CurationTab>('./tabs/*.tsx', { eager: true, import: 'default' });

export const CURATION_TABS: CurationTab[] = Object.values(tabModules).sort((a, b) => a.order - b.order);

export const grantedCurationTabs = (
  tabs: CurationTab[],
  isGranted: (needs: string[]) => boolean = () => true,
  modules?: ModuleHelper,
): CurationTab[] => tabs
  .filter((tab) => !tab.isAvailable || !modules || tab.isAvailable(modules))
  .filter((tab) => !tab.needs || isGranted(tab.needs));
