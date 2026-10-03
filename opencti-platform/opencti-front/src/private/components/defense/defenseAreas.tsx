import type { ComponentType, LazyExoticComponent, ReactNode } from 'react';

export const PATH_DEFENSE = '/dashboard/defense';

export interface DefenseArea {
  /** Route segment under `/dashboard/defense`, also the nav item key. */
  path: string;
  /** English source string, translated by the menu. */
  label: string;
  icon: ReactNode;
  /** When set, the area is hidden with this entity type (Settings > Customization > Entity types). */
  entityType?: string;
  /** When set, the area is listed and routed only for a user granted one of these capabilities. */
  needs?: string[];
  /** Mounted at `/dashboard/defense/<path>/*`. */
  component: LazyExoticComponent<ComponentType>;
}

/**
 * The areas of the Defense hub, in menu order: Hunts, Defense matrix, Dissemination assurance
 * (information architecture directive, OpenCTI-Platform/opencti#18685). The hub and its menu entry
 * only exist while at least one visible area is registered here. Each area is registered under its
 * own heading, so the areas can be added independently of one another.
 */
export const DEFENSE_AREAS: DefenseArea[] = [
  // Hunts

  // Defense matrix

  // Dissemination assurance
];

export const visibleDefenseAreas = (
  areas: DefenseArea[],
  hiddenEntities: string[],
  isGranted: (needs: string[]) => boolean = () => true,
): DefenseArea[] => areas
  .filter((area) => !area.entityType || !hiddenEntities.includes(area.entityType))
  .filter((area) => !area.needs || isGranted(area.needs));
