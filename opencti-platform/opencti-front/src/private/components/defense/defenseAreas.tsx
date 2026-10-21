import type { ComponentType, LazyExoticComponent, ReactNode } from 'react';

export const PATH_DEFENSE = '/dashboard/defense';

export interface DefenseAreaSection {
  /** Route segment under the area. */
  path: string;
  /** English source string, translated by the hub. */
  label: string;
}

export interface DefenseArea {
  /** Position in the menu, lowest first. */
  order: number;
  /** Route segment under `/dashboard/defense`, also the nav item key. */
  path: string;
  /** English source string, translated by the menu. */
  label: string;
  /** English source string: the question the area answers, shown by its first-use state. */
  description?: string;
  icon: ReactNode;
  /** When set, the area is listed and routed only for a user granted one of these capabilities. */
  needs?: string[];
  /** The area's pages, in order: the hub shows them as tabs and names the open one in the breadcrumb. */
  sections?: DefenseAreaSection[];
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
  isGranted: (needs: string[]) => boolean = () => true,
): DefenseArea[] => areas.filter((area) => !area.needs || isGranted(area.needs));

/** The section of `area` that `subPath` (the path below the area) opens, if any. */
export const defenseAreaSection = (area: DefenseArea, subPath: string): DefenseAreaSection | undefined => (
  area.sections?.find((section) => subPath === section.path || subPath.startsWith(`${section.path}/`))
);
