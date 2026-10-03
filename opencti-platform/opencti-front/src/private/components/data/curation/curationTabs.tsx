import { type ComponentType, lazy, type LazyExoticComponent } from 'react';

export const PATH_CURATION = '/dashboard/data/curation';

export interface CurationTab {
  /** Route segment under `/dashboard/data/curation`, also the tab value. */
  path: string;
  /** English source string, translated by the hub. */
  label: string;
  /** Mounted at `/dashboard/data/curation/<path>/*`, behind its own `Security` check. */
  component: LazyExoticComponent<ComponentType>;
}

/**
 * The tabs of the Curation hub, the data-quality home of Data, in display order: Inbox, Conflicts,
 * Stale knowledge, Merges, Knowledge health (information architecture directive,
 * OpenCTI-Platform/opencti#18685). The hub and its menu entry only exist while a tab is registered here.
 */
export const CURATION_TABS: CurationTab[] = [
  { path: 'conflicts', label: 'Conflicts', component: lazy(() => import('../provenance/SourceConflicts')) },
  { path: 'stale-knowledge', label: 'Stale knowledge', component: lazy(() => import('../provenance/StaleKnowledge')) },
];
