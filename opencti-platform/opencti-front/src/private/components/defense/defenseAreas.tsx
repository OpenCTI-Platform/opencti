import React, { type ComponentType, type LazyExoticComponent, type ReactNode } from 'react';
import { ShieldCheckOutline } from 'mdi-material-ui';
import type { HubBadgeCount } from '../common/hub/HubCountBadge';
import type { HubEntry } from '../common/hub/HubEntryContext';
import { sortedHubEntries } from '../common/hub/hubRegistry';

export const PATH_DEFENSE = '/dashboard/defense';

export const DEFENSE_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/defense-hub/';

/** The hub itself, as its landing page names it while no area is registered. */
export const DEFENSE_HUB: HubEntry = {
  label: 'Defense',
  description: 'Turn your threat knowledge into detection and proof.',
  icon: <ShieldCheckOutline />,
};

export interface DefenseAreaSection {
  /** Route segment under the area. */
  path: string;
  /** English source string, translated by the hub. */
  label: string;
}

export interface DefenseArea {
  /** Position in the menu, unique across the areas: lower comes first. */
  order: number;
  /** Route segment under `/dashboard/defense`, also the nav item key. */
  path: string;
  /** English source string, translated by the menu. */
  label: string;
  /** English source string: the question the area answers, shown by its first-use state. */
  description?: string;
  icon: ReactNode;
  /** When set, the area is hidden with this entity type (Settings > Customization > Entity types). */
  entityType?: string;
  /** When set, the area is listed and routed only for a user granted one of these capabilities. */
  needs?: string[];
  /** The area's pages, in order: the hub shows them as tabs and names the open one in the breadcrumb. */
  sections?: DefenseAreaSection[];
  /**
   * True for a path below the area (`<id>/overview`, without the area segment) that the area renders as
   * a page of its own, an entity page with its header and tabs: the hub adds no container or breadcrumb.
   */
  rendersOwnPage?: (subPath: string) => boolean;
  /** Pending work in the area, shown on its menu item; never a total. */
  useBadgeCount?: HubBadgeCount;
  /** Mounted at `/dashboard/defense/<path>/*`; renders its content only, the hub owns the page. */
  component: LazyExoticComponent<ComponentType>;
}

/**
 * The areas of the Defense hub: one file per area in `./areas/`, whose default export is its
 * `DefenseArea`, so each area is added without touching the others or any shared navigation file
 * (see `.github/instructions/frontend/patterns/navigation.md`). No area is registered here: each one
 * comes with the feature that provides it, and until then the hub lands on its first-use page.
 */
const areaModules = import.meta.glob<DefenseArea>('./areas/*.tsx', { eager: true, import: 'default' });

export const DEFENSE_AREAS: DefenseArea[] = sortedHubEntries(areaModules);

export const visibleDefenseAreas = (
  areas: DefenseArea[],
  hiddenEntities: string[],
  isGranted: (needs: string[]) => boolean = () => true,
): DefenseArea[] => areas
  .filter((area) => !area.entityType || !hiddenEntities.includes(area.entityType))
  .filter((area) => !area.needs || isGranted(area.needs));

/** The section of `area` that `subPath` (the path below the area) opens, if any. */
export const defenseAreaSection = (area: DefenseArea, subPath: string): DefenseAreaSection | undefined => (
  area.sections?.find((section) => subPath === section.path || subPath.startsWith(`${section.path}/`))
);
