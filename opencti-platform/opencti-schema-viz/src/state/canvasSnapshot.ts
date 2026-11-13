import type { ToggleableCategory } from '../data/schemaTypes';
import type { LayoutDirection } from '../features/schema-graph/layout/LayoutEngine';
import { DEFAULT_ENABLED_CATEGORIES } from '../shared/theme/typeAppearance';

/** Everything a saved view restores. Selection, path and camera are navigation, not part of a view. */
export interface CanvasSnapshot {
  pinnedTypeIds: string[];
  expandedTypeIds: string[];
  revealedRelations: string[];
  enabledCategories: Record<ToggleableCategory, boolean>;
  showInheritance: boolean;
  showRelations: boolean;
  includeRefs: boolean;
  direction: LayoutDirection;
}

export const EMPTY_SNAPSHOT: CanvasSnapshot = {
  pinnedTypeIds: [],
  expandedTypeIds: [],
  revealedRelations: [],
  enabledCategories: DEFAULT_ENABLED_CATEGORIES,
  showInheritance: false,
  showRelations: true,
  includeRefs: false,
  direction: 'TB',
};

const sorted = (values: readonly string[]) => [...values].sort().join('\n');

export const sameSnapshot = (a: CanvasSnapshot, b: CanvasSnapshot) => sorted(a.pinnedTypeIds) === sorted(b.pinnedTypeIds)
  && sorted(a.expandedTypeIds) === sorted(b.expandedTypeIds)
  && sorted(a.revealedRelations) === sorted(b.revealedRelations)
  && Object.keys(a.enabledCategories).every((key) => a.enabledCategories[key as ToggleableCategory] === b.enabledCategories[key as ToggleableCategory])
  && a.showInheritance === b.showInheritance
  && a.showRelations === b.showRelations
  && a.includeRefs === b.includeRefs
  && a.direction === b.direction;
