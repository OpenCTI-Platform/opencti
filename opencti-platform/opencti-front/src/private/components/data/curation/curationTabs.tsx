import type { ComponentType, LazyExoticComponent } from 'react';

export const PATH_CURATION = '/dashboard/data/curation';

export interface CurationTab {
  /** Route segment under `/dashboard/data/curation`, also the tab value. */
  path: string;
  /** English source string, translated by the hub. */
  label: string;
  /** When set, the tab is listed and routed only for a user granted one of these capabilities. */
  needs?: string[];
  /** Mounted at `/dashboard/data/curation/<path>/*`. */
  component: LazyExoticComponent<ComponentType>;
}

/**
 * The tabs of the Curation hub, the data-quality home of Data, in display order: Inbox, Conflicts,
 * Stale knowledge, Merges, Knowledge health (information architecture directive,
 * OpenCTI-Platform/opencti#18685). The hub and its menu entry only exist while a tab is registered here.
 * Each tab is registered under its own heading, so the tabs can be added independently of one another.
 */
export const CURATION_TABS: CurationTab[] = [
  // Inbox

  // Conflicts

  // Stale knowledge

  // Merges

  // Knowledge health
];

export const grantedCurationTabs = (
  tabs: CurationTab[],
  isGranted: (needs: string[]) => boolean = () => true,
): CurationTab[] => tabs.filter((tab) => !tab.needs || isGranted(tab.needs));
