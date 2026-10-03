import { lazy, type ComponentType, type LazyExoticComponent } from 'react';

export interface EntityChangesViewProps {
  entityId: string;
}

export interface EntityChangesView {
  /** Value of the view switch, also the `view` search parameter of the tab. */
  key: string;
  /** English source string, translated by the tab. */
  label: string;
  component: LazyExoticComponent<ComponentType<EntityChangesViewProps>>;
}

/**
 * The views of an entity's Changes tab, in display order: compare dates and view as of, then the merges the entity
 * took part in (information architecture directive, OpenCTI-Platform/opencti#18685). There is no separate "Diff" or
 * "Merge history" tab: a feature showing how an entity changed registers its view here.
 */
export const ENTITY_CHANGES_VIEWS: EntityChangesView[] = [
  { key: 'merges', label: 'Merges', component: lazy(() => import('@components/data/curation/EntityMergeRecords')) },
];
