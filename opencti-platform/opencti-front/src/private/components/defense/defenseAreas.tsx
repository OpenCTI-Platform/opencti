import type { ComponentType, LazyExoticComponent, ReactNode } from 'react';

export const PATH_DEFENSE = '/dashboard/defense';

export interface DefenseArea {
  /** Position in the menu. */
  order: number;
  /** Route segment under `/dashboard/defense`, also the nav item key. */
  path: string;
  /** English source string, translated by the menu. */
  label: string;
  icon: ReactNode;
  /** When set, the area is hidden with this entity type (Settings > Customization > Entity types). */
  entityType?: string;
  /** When set, the area is listed and routed only for a user granted one of these capabilities. */
  needs?: string[];
  /**
   * True for a path below the area (`<id>/overview`, without the area segment) that the area renders as
   * a page of its own, an entity page with its header and tabs: the hub adds no container or breadcrumb.
   */
  rendersOwnPage?: (subPath: string) => boolean;
  /** Mounted at `/dashboard/defense/<path>/*`; renders its content only, the hub owns the page. */
  component: LazyExoticComponent<ComponentType>;
}

/**
 * The areas of the Defense hub: one file per area in `./areas/`, whose default export is its
 * `DefenseArea`, so each area is added without touching the others. The hub and its menu entry only
 * exist while a visible area is registered.
 */
const areaModules = import.meta.glob<DefenseArea>('./areas/*.tsx', { eager: true, import: 'default' });

export const DEFENSE_AREAS: DefenseArea[] = Object.values(areaModules).sort((a, b) => a.order - b.order);

export const visibleDefenseAreas = (
  areas: DefenseArea[],
  hiddenEntities: string[],
  isGranted: (needs: string[]) => boolean = () => true,
): DefenseArea[] => areas
  .filter((area) => !area.entityType || !hiddenEntities.includes(area.entityType))
  .filter((area) => !area.needs || isGranted(area.needs));
